//! Sync companion to netring's async `session_stream`. Wraps a
//! [`FlowDriver`] and adds per-flow [`SessionParser`] dispatch,
//! yielding [`SessionEvent`]s.
//!
//! Use this when you want typed L7 messages from a synchronous loop
//! (offline pcap replay, embedded use, non-tokio CLI tools). The
//! async equivalent lives in
//! `netring::FlowStream::session_stream(parser)`.
//!
//! # Example
//!
//! ```no_run
//! use flowscope::extract::FiveTuple;
//! use flowscope::pcap::PcapFlowSource;
//! use flowscope::{FlowSessionDriver, SessionEvent, SessionParser, Timestamp};
//!
//! #[derive(Default, Clone)]
//! struct EchoParser;
//! impl SessionParser for EchoParser {
//!     type Message = Vec<u8>;
//!     fn feed_initiator(&mut self, bytes: &[u8], _ts: Timestamp) -> Vec<Vec<u8>> {
//!         vec![bytes.to_vec()]
//!     }
//!     fn feed_responder(&mut self, bytes: &[u8], _ts: Timestamp) -> Vec<Vec<u8>> {
//!         vec![bytes.to_vec()]
//!     }
//! }
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut driver = FlowSessionDriver::new(FiveTuple::bidirectional(), EchoParser);
//! for view in PcapFlowSource::open("trace.pcap")?.views() {
//!     let view = view?;
//!     for ev in driver.track(&view) {
//!         match ev {
//!             SessionEvent::Application { message, .. } => println!("{} bytes", message.len()),
//!             _ => {}
//!         }
//!     }
//! }
//! # Ok(()) }
//! ```

use std::collections::HashMap;
use std::hash::Hash;

use ahash::RandomState;

use crate::Timestamp;
use crate::driver::FlowDriver;
use crate::event::{AnomalyKind, EndReason, FlowEvent, FlowSide};
use crate::extractor::FlowExtractor;
use crate::reassembler::BufferedReassemblerFactory;
use crate::session::{SessionEvent, SessionParser};
use crate::tracker::{FlowTracker, FlowTrackerConfig};
use crate::view::PacketView;

/// Cap on the size of `poison_reason()` strings carried through
/// [`AnomalyKind::SessionParseError`]. Bounds anomaly event size
/// so a malicious / verbose parser can't blow the consumer's
/// memory.
const POISON_REASON_MAX_BYTES: usize = 256;

fn truncate_reason(s: &str) -> String {
    let mut owned = String::from(s);
    if owned.len() > POISON_REASON_MAX_BYTES {
        // Find char boundary at or below the cap.
        let cap = (0..=POISON_REASON_MAX_BYTES)
            .rev()
            .find(|i| owned.is_char_boundary(*i))
            .unwrap_or(0);
        owned.truncate(cap);
    }
    owned
}

/// Sync session-event driver. Wraps a [`FlowDriver`] with
/// [`BufferedReassemblerFactory`] and adds per-flow
/// [`SessionParser`] dispatch.
///
/// `E` — the flow extractor.
/// `P` — the session parser; the helper requires `Default + Clone`
/// so each new flow gets a fresh per-flow instance via clone.
/// `S` — optional per-flow user state stored on the tracker.
pub struct FlowSessionDriver<E, P>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + 'static,
    P: SessionParser + Clone + Send + 'static,
{
    driver: FlowDriver<E, BufferedReassemblerFactory>,
    parser_factory: P,
    parsers: HashMap<E::Key, P, RandomState>,
}

impl<E, P> FlowSessionDriver<E, P>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + 'static,
    P: SessionParser + Clone + Send + 'static,
{
    /// Construct with default tracker config. `parser` is cloned
    /// once per flow to give each session a fresh instance.
    pub fn new(extractor: E, parser: P) -> Self {
        Self::with_config(extractor, parser, FlowTrackerConfig::default())
    }

    /// Construct with explicit tracker config. Honours
    /// `config.max_reassembler_buffer` and `config.overflow_policy`
    /// when building per-flow reassemblers.
    pub fn with_config(extractor: E, parser: P, config: FlowTrackerConfig) -> Self {
        let factory = match config.max_reassembler_buffer {
            Some(cap) => BufferedReassemblerFactory::default()
                .with_max_buffer(cap)
                .with_overflow_policy(config.overflow_policy),
            None => BufferedReassemblerFactory::default(),
        };
        Self {
            driver: FlowDriver::with_config(extractor, factory, config),
            parser_factory: parser,
            parsers: HashMap::with_hasher(RandomState::new()),
        }
    }

    /// Opt in to forwarding [`SessionEvent::Anomaly`]s through the
    /// stream. Default: `false`. Mirrors
    /// [`FlowDriver::with_emit_anomalies`].
    ///
    /// Anomalies are coalesced per (flow, side, kind) per tick by
    /// the underlying [`FlowDriver`].
    pub fn with_emit_anomalies(mut self, enable: bool) -> Self {
        self.driver = self.driver.with_emit_anomalies(enable);
        self
    }

    /// Set a per-key idle-timeout override on the underlying
    /// tracker. Mirrors [`FlowDriver::with_idle_timeout_fn`].
    pub fn with_idle_timeout_fn<G>(mut self, f: G) -> Self
    where
        G: Fn(&E::Key, Option<crate::L4Proto>) -> Option<std::time::Duration> + Send + 'static,
    {
        self.driver = self.driver.with_idle_timeout_fn(f);
        self
    }

    /// Filter incoming `PacketView`s through a content-hash
    /// [`crate::Dedup`]. Mirrors [`FlowDriver::with_dedup`].
    pub fn with_dedup(mut self, dedup: crate::dedup::Dedup) -> Self {
        self.driver = self.driver.with_dedup(dedup);
        self
    }

    /// Borrow the dedup state.
    pub fn dedup(&self) -> Option<&crate::dedup::Dedup> {
        self.driver.dedup()
    }

    /// Opt in to strictly non-decreasing timestamps. Mirrors
    /// [`FlowDriver::with_monotonic_timestamps`].
    pub fn with_monotonic_timestamps(mut self, enable: bool) -> Self {
        self.driver = self.driver.with_monotonic_timestamps(enable);
        self
    }

    /// Drive one packet. Returns zero or more [`SessionEvent`]s.
    pub fn track<'v>(
        &mut self,
        view: impl Into<PacketView<'v>>,
    ) -> Vec<SessionEvent<E::Key, P::Message>> {
        let mut flow_events = self.driver.track_pending(view);
        let out = self.translate_events(&flow_events);
        self.driver.finalize(flow_events.as_mut_slice());
        out
    }

    /// Run the idle-timeout sweep. Returns any resulting `Closed`
    /// events plus anomalies emitted during the sweep. Also drives
    /// each still-live parser's [`SessionParser::on_tick`] hook with
    /// `now`, emitting any time-driven messages as `Application`
    /// events attributed to the initiator side.
    pub fn sweep(&mut self, now: Timestamp) -> Vec<SessionEvent<E::Key, P::Message>> {
        let mut flow_events = self.driver.sweep_pending(now);
        // Fire `on_tick` on every live parser *before* translating
        // the swept events — a flow this sweep is about to close
        // still gets its final tick, and the tick's messages land
        // ahead of that flow's `Closed`.
        let mut out: Vec<SessionEvent<E::Key, P::Message>> = Vec::new();
        for (key, parser) in self.parsers.iter_mut() {
            for m in parser.on_tick(now) {
                crate::obs::trace_session_message(FlowSide::Initiator, &m);
                out.push(SessionEvent::Application {
                    key: key.clone(),
                    side: FlowSide::Initiator,
                    message: m,
                    ts: now,
                });
            }
        }
        out.extend(self.translate_events(&flow_events));
        self.driver.finalize(flow_events.as_mut_slice());
        out
    }

    /// Sweep every remaining flow, emitting `Closed` events (and any
    /// `Application` events the parser flushes on close). Call once
    /// at end of input — equivalent to `sweep(Timestamp::MAX)`.
    pub fn finish(&mut self) -> Vec<SessionEvent<E::Key, P::Message>> {
        self.sweep(Timestamp::MAX)
    }

    /// Borrow the inner tracker (for stats, introspection).
    pub fn tracker(&self) -> &FlowTracker<E, ()> {
        self.driver.tracker()
    }

    /// Borrow the inner tracker mutably.
    pub fn tracker_mut(&mut self) -> &mut FlowTracker<E, ()> {
        self.driver.tracker_mut()
    }

    /// Iterate `(key, FlowStats)` for every live flow with
    /// reassembler diagnostics patched in. Delegates to the inner
    /// [`FlowDriver::snapshot_flow_stats`].
    pub fn snapshot_flow_stats(&self) -> impl Iterator<Item = (E::Key, crate::FlowStats)> + '_ {
        self.driver.snapshot_flow_stats()
    }

    /// Map a tick's `FlowEvent`s to `SessionEvent`s, draining
    /// reassembler buffers and feeding the per-flow parser as we go.
    ///
    /// Called between `track_pending` / `sweep_pending` and
    /// `finalize` — reassemblers for ended flows are still
    /// accessible here, so FIN-with-payload bytes are captured.
    fn translate_events(
        &mut self,
        flow_events: &[FlowEvent<E::Key>],
    ) -> Vec<SessionEvent<E::Key, P::Message>> {
        let mut out: Vec<SessionEvent<E::Key, P::Message>> = Vec::new();
        for ev in flow_events {
            match ev {
                FlowEvent::Started { key, ts, .. } => {
                    self.parsers
                        .entry(key.clone())
                        .or_insert_with(|| self.parser_factory.clone());
                    out.push(SessionEvent::Started {
                        key: key.clone(),
                        ts: *ts,
                    });
                }
                FlowEvent::Packet { key, ts, .. } => {
                    self.drain_into_parser(key, *ts, &mut out);
                }
                FlowEvent::Ended {
                    key, reason, stats, ..
                } => {
                    // Final drain (captures FIN-with-payload bytes
                    // before the reassembler is dropped in finalize),
                    // then call the parser's fin/rst hook.
                    let ts = stats.last_seen;
                    self.drain_into_parser(key, ts, &mut out);
                    if let Some(mut parser) = self.parsers.remove(key) {
                        match reason {
                            EndReason::Fin | EndReason::IdleTimeout => {
                                for m in parser.fin_initiator() {
                                    out.push(SessionEvent::Application {
                                        key: key.clone(),
                                        side: FlowSide::Initiator,
                                        message: m,
                                        ts,
                                    });
                                }
                                for m in parser.fin_responder() {
                                    out.push(SessionEvent::Application {
                                        key: key.clone(),
                                        side: FlowSide::Responder,
                                        message: m,
                                        ts,
                                    });
                                }
                            }
                            EndReason::Rst
                            | EndReason::Evicted
                            | EndReason::BufferOverflow
                            | EndReason::ParseError => {
                                parser.rst_initiator();
                                parser.rst_responder();
                            }
                        }
                    }
                    out.push(SessionEvent::Closed {
                        key: key.clone(),
                        reason: *reason,
                        stats: stats.clone(),
                    });
                }
                FlowEvent::Anomaly { key, kind, ts } => {
                    out.push(SessionEvent::Anomaly {
                        key: key.clone(),
                        kind: kind.clone(),
                        ts: *ts,
                    });
                }
                FlowEvent::Tick { key, stats, ts } => {
                    out.push(SessionEvent::FlowTick {
                        key: key.clone(),
                        stats: stats.clone(),
                        ts: *ts,
                    });
                }
                FlowEvent::Established { .. } | FlowEvent::StateChange { .. } => {
                    // TCP-machine internal transitions; not surfaced
                    // to SessionEvent.
                }
            }
        }
        out
    }

    fn drain_into_parser(
        &mut self,
        key: &E::Key,
        ts: Timestamp,
        out: &mut Vec<SessionEvent<E::Key, P::Message>>,
    ) {
        // Two passes over the sides so we can synthesise poison events
        // BEFORE returning (callers expect: anomaly first, then Closed).
        for side in [FlowSide::Initiator, FlowSide::Responder] {
            let drained = self.driver.drain_buffer(key, side);
            if drained.is_empty() {
                continue;
            }
            // Get the parser fresh inside the loop — it may have been
            // removed by a previous poison-synthesis call on this key.
            let parser = match self.parsers.get_mut(key) {
                Some(p) => p,
                None => return,
            };
            let messages = match side {
                FlowSide::Initiator => parser.feed_initiator(&drained, ts),
                FlowSide::Responder => parser.feed_responder(&drained, ts),
            };
            for m in messages {
                crate::obs::trace_session_message(side, &m);
                out.push(SessionEvent::Application {
                    key: key.clone(),
                    side,
                    message: m,
                    ts,
                });
            }
            // Plan 55: check is_poisoned() after every feed_*. If
            // the parser has poisoned, emit the anomaly + synthesise
            // a parse-error Closed event, then tear down the parser
            // slot. The flow stays in the tracker (FlowDriver
            // doesn't see SessionParser poison); subsequent packets
            // will produce no further Application events because the
            // parser slot is gone.
            if parser.is_poisoned() {
                let reason = parser.poison_reason().map(truncate_reason);
                self.synthesise_parser_poison(key, side, reason, ts, out);
                return;
            }
        }
    }

    fn synthesise_parser_poison(
        &mut self,
        key: &E::Key,
        side: FlowSide,
        reason: Option<String>,
        ts: Timestamp,
        out: &mut Vec<SessionEvent<E::Key, P::Message>>,
    ) {
        if self.driver.emits_anomalies() {
            out.push(SessionEvent::Anomaly {
                key: Some(key.clone()),
                kind: AnomalyKind::SessionParseError {
                    side,
                    reason: reason.clone(),
                },
                ts,
            });
        }
        // Snapshot stats BEFORE forgetting the flow so the Closed
        // event carries the final counters.
        let stats = self
            .driver
            .tracker()
            .snapshot_stats(key)
            .unwrap_or_default();
        crate::obs::record_flow_ended(EndReason::ParseError, &stats);
        crate::obs::trace_flow_ended(EndReason::ParseError, &stats);
        out.push(SessionEvent::Closed {
            key: key.clone(),
            reason: EndReason::ParseError,
            stats,
        });
        self.parsers.remove(key);
        self.driver.tracker_mut().forget(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AnomalyKind;
    use crate::extract::{FiveTuple, parse::test_frames::ipv4_tcp};

    fn view(frame: &[u8], sec: u32) -> PacketView<'_> {
        PacketView::new(frame, Timestamp::new(sec, 0))
    }

    /// Plan 32 guard: the parser bound is `Clone`, not
    /// `Default + Clone`. A config-built parser with no `Default`
    /// impl must still be accepted by the constructor.
    #[test]
    fn accepts_non_default_parser() {
        #[derive(Clone)]
        struct ConfigParser {
            _limit: usize,
        }
        impl SessionParser for ConfigParser {
            type Message = ();
            fn feed_initiator(&mut self, _b: &[u8], _ts: Timestamp) -> Vec<()> {
                Vec::new()
            }
            fn feed_responder(&mut self, _b: &[u8], _ts: Timestamp) -> Vec<()> {
                Vec::new()
            }
        }
        let _d = FlowSessionDriver::new(FiveTuple::bidirectional(), ConfigParser { _limit: 4096 });
    }

    /// Tiny line-oriented parser: emits one Vec<u8> per newline-terminated frame.
    #[derive(Default, Clone)]
    struct LineParser {
        init: Vec<u8>,
        resp: Vec<u8>,
    }

    impl SessionParser for LineParser {
        type Message = (FlowSide, Vec<u8>);

        fn feed_initiator(&mut self, bytes: &[u8], _ts: Timestamp) -> Vec<Self::Message> {
            drain(&mut self.init, bytes, FlowSide::Initiator)
        }
        fn feed_responder(&mut self, bytes: &[u8], _ts: Timestamp) -> Vec<Self::Message> {
            drain(&mut self.resp, bytes, FlowSide::Responder)
        }
    }

    fn drain(buf: &mut Vec<u8>, bytes: &[u8], side: FlowSide) -> Vec<(FlowSide, Vec<u8>)> {
        buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        while let Some(nl) = buf.iter().position(|&b| b == b'\n') {
            let line = buf[..nl].to_vec();
            out.push((side, line));
            buf.drain(..=nl);
        }
        out
    }

    fn build_3whs() -> [Vec<u8>; 3] {
        let mac = [0u8; 6];
        let ip_a = [10, 0, 0, 1];
        let ip_b = [10, 0, 0, 2];
        [
            ipv4_tcp(mac, mac, ip_a, ip_b, 1234, 80, 1000, 0, 0x02, b""),
            ipv4_tcp(mac, mac, ip_b, ip_a, 80, 1234, 5000, 1001, 0x12, b""),
            ipv4_tcp(mac, mac, ip_a, ip_b, 1234, 80, 1001, 5001, 0x10, b""),
        ]
    }

    /// Plan 33: `finish()` closes every still-open session.
    #[test]
    fn finish_closes_open_sessions() {
        let mut d = FlowSessionDriver::new(FiveTuple::bidirectional(), LineParser::default());
        let frames = build_3whs();
        for f in &frames {
            d.track(view(f, 0));
        }
        let closed = d
            .finish()
            .into_iter()
            .filter(|e| matches!(e, SessionEvent::Closed { .. }))
            .count();
        assert_eq!(closed, 1, "finish() must close the open session");
        assert!(d.finish().is_empty(), "second finish() yields nothing");
    }

    /// Plan 36: `on_tick` fires on `sweep` / `finish` for live
    /// flows — including a flow the sweep is about to close.
    #[test]
    fn on_tick_fires_on_sweep_and_finish() {
        #[derive(Default, Clone)]
        struct TickParser;
        impl SessionParser for TickParser {
            type Message = u8;
            fn feed_initiator(&mut self, _b: &[u8], _ts: Timestamp) -> Vec<u8> {
                Vec::new()
            }
            fn feed_responder(&mut self, _b: &[u8], _ts: Timestamp) -> Vec<u8> {
                Vec::new()
            }
            fn on_tick(&mut self, _now: Timestamp) -> Vec<u8> {
                vec![42]
            }
        }
        let mut d = FlowSessionDriver::new(FiveTuple::bidirectional(), TickParser);
        for f in &build_3whs() {
            d.track(view(f, 0));
        }
        let count = |evs: Vec<SessionEvent<_, u8>>| {
            evs.iter()
                .filter(|e| matches!(e, SessionEvent::Application { message: 42, .. }))
                .count()
        };
        // A non-closing sweep fires on_tick for the live flow.
        assert_eq!(count(d.sweep(Timestamp::new(1, 0))), 1);
        // finish() closes the flow but still drives a final on_tick.
        assert_eq!(count(d.finish()), 1);
        // No flows remain → no further ticks.
        assert_eq!(count(d.sweep(Timestamp::new(99, 0))), 0);
    }

    #[test]
    fn started_event_emitted_on_first_packet() {
        let mut d = FlowSessionDriver::new(FiveTuple::bidirectional(), LineParser::default());
        let frames = build_3whs();
        let mut events = Vec::new();
        for f in &frames {
            events.extend(d.track(view(f, 0)));
        }
        let starts = events
            .iter()
            .filter(|e| matches!(e, SessionEvent::Started { .. }))
            .count();
        assert_eq!(starts, 1);
    }

    #[test]
    fn application_events_for_parsed_messages() {
        let mut d = FlowSessionDriver::new(FiveTuple::bidirectional(), LineParser::default());
        let mut events = Vec::new();
        for f in build_3whs() {
            events.extend(d.track(view(&f, 0)));
        }
        // Initiator data — two complete lines.
        let mac = [0u8; 6];
        let data = ipv4_tcp(
            mac,
            mac,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            1001,
            5001,
            0x18,
            b"hello\nworld\n",
        );
        events.extend(d.track(view(&data, 0)));
        let lines: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                SessionEvent::Application {
                    side,
                    message: (s, m),
                    ..
                } => {
                    assert_eq!(s, side);
                    Some(m.clone())
                }
                _ => None,
            })
            .collect();
        assert_eq!(lines, vec![b"hello".to_vec(), b"world".to_vec()]);
    }

    #[test]
    fn closed_event_carries_stats_on_rst() {
        let mut d = FlowSessionDriver::new(FiveTuple::bidirectional(), LineParser::default());
        let mut events = Vec::new();
        for f in build_3whs() {
            events.extend(d.track(view(&f, 0)));
        }
        let mac = [0u8; 6];
        let rst = ipv4_tcp(
            mac,
            mac,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            1001,
            5001,
            0x04,
            b"",
        );
        events.extend(d.track(view(&rst, 0)));
        let closed = events
            .into_iter()
            .find(|e| matches!(e, SessionEvent::Closed { .. }))
            .expect("expected Closed");
        match closed {
            SessionEvent::Closed { reason, stats, .. } => {
                assert_eq!(reason, EndReason::Rst);
                // Three packets in 3WHS + one RST.
                assert_eq!(stats.packets_initiator + stats.packets_responder, 4);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn fin_with_payload_drains_before_close() {
        // FIN packet carries payload — bytes must reach the parser
        // before the Closed event fires (the FlowDriver finalize
        // path drops the reassembler; FlowSessionDriver drains it
        // first via the track_pending -> drain -> finalize split).
        let mut d = FlowSessionDriver::new(FiveTuple::bidirectional(), LineParser::default());
        let mut events = Vec::new();
        for f in build_3whs() {
            events.extend(d.track(view(&f, 0)));
        }
        let mac = [0u8; 6];
        let fin_with_data = ipv4_tcp(
            mac,
            mac,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            1001,
            5001,
            0x19, // FIN + ACK + PSH
            b"goodbye\n",
        );
        events.extend(d.track(view(&fin_with_data, 0)));
        let goodbye = events.iter().find_map(|e| match e {
            SessionEvent::Application {
                message: (_, m), ..
            } if m.as_slice() == b"goodbye" => Some(()),
            _ => None,
        });
        assert!(
            goodbye.is_some(),
            "FIN-with-payload bytes lost; events: {:?}",
            events
                .iter()
                .filter(|e| matches!(e, SessionEvent::Application { .. }))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn anomaly_event_forwarded_when_emit_anomalies_on() {
        let cfg = FlowTrackerConfig {
            max_reassembler_buffer: Some(64),
            ..FlowTrackerConfig::default()
        };
        let mut d =
            FlowSessionDriver::with_config(FiveTuple::bidirectional(), LineParser::default(), cfg)
                .with_emit_anomalies(true);

        let mut events = Vec::new();
        for f in build_3whs() {
            events.extend(d.track(view(&f, 0)));
        }
        let mac = [0u8; 6];
        let big = vec![b'A'; 200];
        let data = ipv4_tcp(
            mac,
            mac,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            1001,
            5001,
            0x18,
            &big,
        );
        events.extend(d.track(view(&data, 0)));

        let buffer_overflow = events.iter().find(|e| {
            matches!(
                e,
                SessionEvent::Anomaly {
                    kind: AnomalyKind::BufferOverflow { .. },
                    ..
                }
            )
        });
        assert!(
            buffer_overflow.is_some(),
            "expected a BufferOverflow anomaly forwarded"
        );
    }

    #[test]
    fn no_anomaly_events_by_default() {
        let cfg = FlowTrackerConfig {
            max_reassembler_buffer: Some(64),
            ..FlowTrackerConfig::default()
        };
        let mut d =
            FlowSessionDriver::with_config(FiveTuple::bidirectional(), LineParser::default(), cfg);
        let mut events = Vec::new();
        for f in build_3whs() {
            events.extend(d.track(view(&f, 0)));
        }
        let mac = [0u8; 6];
        let big = vec![b'A'; 200];
        let data = ipv4_tcp(
            mac,
            mac,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            1001,
            5001,
            0x18,
            &big,
        );
        events.extend(d.track(view(&data, 0)));
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, SessionEvent::Anomaly { .. })),
            "expected no anomaly events when emit_anomalies is off"
        );
    }

    /// Parser that poisons after seeing more than N bytes on the
    /// initiator side.
    #[derive(Default, Clone)]
    struct PoisonAfterBytes {
        init_bytes: usize,
        poisoned: bool,
    }

    impl SessionParser for PoisonAfterBytes {
        type Message = Vec<u8>;
        fn feed_initiator(&mut self, bytes: &[u8], _ts: Timestamp) -> Vec<Vec<u8>> {
            self.init_bytes += bytes.len();
            if self.init_bytes > 5 {
                self.poisoned = true;
            }
            vec![bytes.to_vec()]
        }
        fn feed_responder(&mut self, bytes: &[u8], _ts: Timestamp) -> Vec<Vec<u8>> {
            vec![bytes.to_vec()]
        }
        fn is_poisoned(&self) -> bool {
            self.poisoned
        }
        fn poison_reason(&self) -> Option<&str> {
            if self.poisoned {
                Some("test: poisoned after >5 initiator bytes")
            } else {
                None
            }
        }
    }

    #[test]
    fn parser_poison_synthesises_parse_error_closed() {
        let mut d = FlowSessionDriver::new(FiveTuple::bidirectional(), PoisonAfterBytes::default());
        let mut events = Vec::new();
        for f in build_3whs() {
            events.extend(d.track(view(&f, 0)));
        }
        let mac = [0u8; 6];
        // Send 10 bytes initiator data — parser poisons.
        let data = ipv4_tcp(
            mac,
            mac,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            1001,
            5001,
            0x18,
            b"0123456789",
        );
        events.extend(d.track(view(&data, 0)));
        let closed = events
            .iter()
            .find_map(|e| match e {
                SessionEvent::Closed { reason, .. } => Some(*reason),
                _ => None,
            })
            .expect("Closed event");
        assert_eq!(closed, EndReason::ParseError);
    }

    #[test]
    fn parser_poison_with_anomalies_emits_parse_error_anomaly() {
        let mut d = FlowSessionDriver::new(FiveTuple::bidirectional(), PoisonAfterBytes::default())
            .with_emit_anomalies(true);
        let mut events = Vec::new();
        for f in build_3whs() {
            events.extend(d.track(view(&f, 0)));
        }
        let mac = [0u8; 6];
        let data = ipv4_tcp(
            mac,
            mac,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            1001,
            5001,
            0x18,
            b"0123456789",
        );
        events.extend(d.track(view(&data, 0)));
        let (anomaly_idx, _) = events
            .iter()
            .enumerate()
            .find(|(_, e)| {
                matches!(
                    e,
                    SessionEvent::Anomaly {
                        kind: AnomalyKind::SessionParseError { .. },
                        ..
                    }
                )
            })
            .expect("ParseError anomaly");
        let closed_idx = events
            .iter()
            .position(|e| {
                matches!(
                    e,
                    SessionEvent::Closed {
                        reason: EndReason::ParseError,
                        ..
                    }
                )
            })
            .expect("ParseError Closed");
        assert!(
            anomaly_idx < closed_idx,
            "anomaly must precede Closed (cause then effect)"
        );
        // Reason string is forwarded + truncated.
        match &events[anomaly_idx] {
            SessionEvent::Anomaly {
                kind: AnomalyKind::SessionParseError { reason, side },
                ..
            } => {
                assert_eq!(*side, FlowSide::Initiator);
                assert!(reason.as_ref().is_some());
                assert!(reason.as_ref().unwrap().contains("poisoned"));
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn non_poisoning_parser_unaffected_by_poison_path() {
        // LineParser never poisons; existing tests should still
        // produce no ParseError events.
        let mut d = FlowSessionDriver::new(FiveTuple::bidirectional(), LineParser::default());
        let mut events = Vec::new();
        for f in build_3whs() {
            events.extend(d.track(view(&f, 0)));
        }
        let mac = [0u8; 6];
        let data = ipv4_tcp(
            mac,
            mac,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            1001,
            5001,
            0x18,
            b"hello\nworld\n",
        );
        events.extend(d.track(view(&data, 0)));
        assert!(
            !events.iter().any(|e| matches!(
                e,
                SessionEvent::Closed {
                    reason: EndReason::ParseError,
                    ..
                }
            )),
            "non-poisoning parser produced a ParseError Closed event"
        );
    }

    #[test]
    fn eviction_pressure_anomaly_has_no_key() {
        let cfg = FlowTrackerConfig {
            max_flows: 2,
            ..FlowTrackerConfig::default()
        };
        let mut d =
            FlowSessionDriver::with_config(FiveTuple::bidirectional(), LineParser::default(), cfg)
                .with_emit_anomalies(true);
        let mut events = Vec::new();
        for src_port in [1234u16, 1235, 1236] {
            let frame = ipv4_tcp(
                [0; 6],
                [0; 6],
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                src_port,
                80,
                0,
                0,
                0x02,
                b"",
            );
            events.extend(d.track(view(&frame, 0)));
        }
        let pressure = events.iter().find(|e| {
            matches!(
                e,
                SessionEvent::Anomaly {
                    kind: AnomalyKind::FlowTableEvictionPressure { .. },
                    ..
                }
            )
        });
        let pressure = pressure.expect("expected an eviction-pressure anomaly");
        match pressure {
            SessionEvent::Anomaly {
                key,
                kind:
                    AnomalyKind::FlowTableEvictionPressure {
                        evicted_in_tick, ..
                    },
                ..
            } => {
                assert!(key.is_none());
                assert_eq!(*evicted_in_tick, 1);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn session_driver_forwards_tick_as_flow_tick() {
        let cfg = FlowTrackerConfig {
            flow_tick_interval: Some(std::time::Duration::from_secs(10)),
            ..FlowTrackerConfig::default()
        };
        let mut d =
            FlowSessionDriver::with_config(FiveTuple::bidirectional(), LineParser::default(), cfg);
        let syn = ipv4_tcp(
            [0; 6],
            [0; 6],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            1000,
            0,
            0x02,
            b"",
        );
        let events = d.track(view(&syn, 0));
        assert!(
            events
                .iter()
                .any(|e| matches!(e, SessionEvent::FlowTick { .. })),
            "first packet should emit initial FlowTick, got: {:?}",
            events
        );
    }
}

//! Sync companion to netring's async `datagram_stream`. Wraps a
//! [`FlowDriver`] (with a no-op reassembler factory) and adds
//! per-flow [`DatagramParser`] dispatch.
//!
//! Use this when you want typed L7 messages from a synchronous
//! UDP-driving loop (DNS-over-UDP, syslog, NTP, SNMP, custom
//! binary datagram protocols).
//!
//! # Example
//!
//! ```no_run
//! use flowscope::extract::FiveTuple;
//! use flowscope::pcap::PcapFlowSource;
//! use flowscope::{DatagramParser, FlowDatagramDriver, FlowSide, SessionEvent, Timestamp};
//!
//! #[derive(Default, Clone)]
//! struct EchoUdp;
//! impl DatagramParser for EchoUdp {
//!     type Message = Vec<u8>;
//!     fn parse(&mut self, payload: &[u8], _side: FlowSide, _ts: Timestamp) -> Vec<Vec<u8>> {
//!         vec![payload.to_vec()]
//!     }
//! }
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut driver = FlowDatagramDriver::new(FiveTuple::bidirectional(), EchoUdp);
//! for view in PcapFlowSource::open("trace.pcap")?.views() {
//!     let view = view?;
//!     for ev in driver.track(&view) {
//!         if let SessionEvent::Application { message, .. } = ev {
//!             println!("{} bytes", message.len());
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
use crate::reassembler::{Reassembler, ReassemblerFactory};
use crate::session::{DatagramParser, SessionEvent};
use crate::tracker::{FlowTracker, FlowTrackerConfig};
use crate::view::PacketView;

/// Cap on the size of `poison_reason()` strings carried through
/// [`AnomalyKind::SessionParseError`]. Matches the
/// [`crate::session_driver`] cap.
const POISON_REASON_MAX_BYTES: usize = 256;

fn truncate_reason(s: &str) -> String {
    let mut owned = String::from(s);
    if owned.len() > POISON_REASON_MAX_BYTES {
        let cap = (0..=POISON_REASON_MAX_BYTES)
            .rev()
            .find(|i| owned.is_char_boundary(*i))
            .unwrap_or(0);
        owned.truncate(cap);
    }
    owned
}

/// A no-op reassembler. UDP traffic doesn't reassemble, but the
/// inner `FlowDriver` requires a `ReassemblerFactory`. This stub
/// is created on TCP-payload callbacks (which UDP traffic never
/// triggers); the slot stays empty in practice.
#[derive(Debug, Default)]
struct NoopReassembler;

impl Reassembler for NoopReassembler {
    fn segment(&mut self, _seq: u32, _payload: &[u8], _ts: crate::Timestamp) {}
}

#[derive(Debug, Default)]
struct NoopReassemblerFactory;

impl<K: Send + 'static> ReassemblerFactory<K> for NoopReassemblerFactory {
    type Reassembler = NoopReassembler;
    fn new_reassembler(&mut self, _key: &K, _side: FlowSide) -> NoopReassembler {
        NoopReassembler
    }
}

/// Sync UDP-datagram driver. Owns a flow tracker + per-flow
/// [`DatagramParser`] instances, yielding [`SessionEvent`]s.
///
/// Builder methods mirror [`crate::FlowSessionDriver`] so users
/// running mixed TCP/UDP traffic can pair the two drivers with
/// identical configuration.
pub struct FlowDatagramDriver<E, P>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + 'static,
    P: DatagramParser + Clone + Send + 'static,
{
    driver: FlowDriver<E, NoopReassemblerFactory>,
    parser_factory: P,
    parsers: HashMap<E::Key, P, RandomState>,
}

impl<E, P> FlowDatagramDriver<E, P>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + 'static,
    P: DatagramParser + Clone + Send + 'static,
{
    /// Construct with default tracker config. `parser` is cloned
    /// once per flow to give each flow a fresh instance.
    pub fn new(extractor: E, parser: P) -> Self {
        Self::with_config(extractor, parser, FlowTrackerConfig::default())
    }

    /// Construct with explicit tracker config.
    pub fn with_config(extractor: E, parser: P, config: FlowTrackerConfig) -> Self {
        Self {
            driver: FlowDriver::with_config(extractor, NoopReassemblerFactory, config),
            parser_factory: parser,
            parsers: HashMap::with_hasher(RandomState::new()),
        }
    }

    /// Opt in to forwarding [`SessionEvent::Anomaly`]s.
    pub fn with_emit_anomalies(mut self, enable: bool) -> Self {
        self.driver = self.driver.with_emit_anomalies(enable);
        self
    }

    /// Set a per-key idle-timeout override.
    pub fn with_idle_timeout_fn<G>(mut self, f: G) -> Self
    where
        G: Fn(&E::Key, Option<crate::L4Proto>) -> Option<std::time::Duration> + Send + 'static,
    {
        self.driver = self.driver.with_idle_timeout_fn(f);
        self
    }

    /// Filter via content-hash [`crate::Dedup`].
    pub fn with_dedup(mut self, dedup: crate::dedup::Dedup) -> Self {
        self.driver = self.driver.with_dedup(dedup);
        self
    }

    /// Opt in to monotonic timestamps.
    pub fn with_monotonic_timestamps(mut self, enable: bool) -> Self {
        self.driver = self.driver.with_monotonic_timestamps(enable);
        self
    }

    /// Drive one packet. Returns zero or more [`SessionEvent`]s.
    pub fn track<'v>(
        &mut self,
        view: impl Into<PacketView<'v>>,
    ) -> Vec<SessionEvent<E::Key, P::Message>> {
        let view: PacketView<'v> = view.into();
        // Capture the UDP payload BEFORE FlowDriver consumes the
        // view; otherwise we'd need to re-parse the (potentially
        // dedup-rewritten / monotonised) frame.
        let udp_payload: Option<Vec<u8>> = extract_udp_payload(view).map(|s| s.to_vec());
        let mut flow_events = self.driver.track_pending(view);
        let out = self.translate_events(&flow_events, udp_payload.as_deref());
        self.driver.finalize(flow_events.as_mut_slice());
        out
    }

    /// Run the idle-timeout sweep. Also drives each still-live
    /// parser's [`DatagramParser::on_tick`] hook with `now`, emitting
    /// any time-driven messages as initiator-side `Application`
    /// events.
    pub fn sweep(&mut self, now: Timestamp) -> Vec<SessionEvent<E::Key, P::Message>> {
        let mut flow_events = self.driver.sweep_pending(now);
        // Fire `on_tick` on every live parser *before* translating
        // the swept events, so a flow this sweep closes still gets
        // its final tick ahead of its `Closed` event.
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
        out.extend(self.translate_events(&flow_events, None));
        self.driver.finalize(flow_events.as_mut_slice());
        out
    }

    /// Sweep every remaining flow, emitting `Closed` events. Call
    /// once at end of input — equivalent to `sweep(Timestamp::MAX)`.
    pub fn finish(&mut self) -> Vec<SessionEvent<E::Key, P::Message>> {
        self.sweep(Timestamp::MAX)
    }

    /// Borrow the inner tracker.
    pub fn tracker(&self) -> &FlowTracker<E, ()> {
        self.driver.tracker()
    }

    /// Borrow the inner tracker mutably.
    pub fn tracker_mut(&mut self) -> &mut FlowTracker<E, ()> {
        self.driver.tracker_mut()
    }

    /// Iterate `(key, FlowStats)` for every live flow.
    pub fn snapshot_flow_stats(&self) -> impl Iterator<Item = (E::Key, crate::FlowStats)> + '_ {
        self.driver.snapshot_flow_stats()
    }

    /// Borrow the dedup state.
    pub fn dedup(&self) -> Option<&crate::dedup::Dedup> {
        self.driver.dedup()
    }

    fn translate_events(
        &mut self,
        flow_events: &[FlowEvent<E::Key>],
        udp_payload: Option<&[u8]>,
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
                FlowEvent::Packet { key, side, ts, .. } => {
                    let Some(payload) = udp_payload else {
                        // Non-UDP packet or no payload — skip silently.
                        continue;
                    };
                    let Some(parser) = self.parsers.get_mut(key) else {
                        continue;
                    };
                    let messages = parser.parse(payload, *side, *ts);
                    for m in messages {
                        crate::obs::trace_session_message(*side, &m);
                        out.push(SessionEvent::Application {
                            key: key.clone(),
                            side: *side,
                            message: m,
                            ts: *ts,
                        });
                    }
                    // Plan 55 — parser poison check.
                    if parser.is_poisoned() {
                        let reason = parser.poison_reason().map(truncate_reason);
                        self.synthesise_parser_poison(key, *side, reason, *ts, &mut out);
                    }
                }
                FlowEvent::Ended {
                    key, reason, stats, ..
                } => {
                    self.parsers.remove(key);
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
                    // TCP-only events; ignored.
                }
            }
        }
        out
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
                kind: AnomalyKind::SessionParseError { side, reason },
                ts,
            });
        }
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

/// Extract the UDP payload from an Ethernet-framed view. Returns
/// `None` if the frame isn't UDP or can't be parsed.
fn extract_udp_payload(view: PacketView<'_>) -> Option<&[u8]> {
    let sp = etherparse::SlicedPacket::from_ethernet(view.frame).ok()?;
    match sp.transport? {
        etherparse::TransportSlice::Udp(udp) => Some(udp.payload()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::{FiveTuple, parse::test_frames::*};

    fn view(frame: &[u8], sec: u32) -> PacketView<'_> {
        PacketView::new(frame, Timestamp::new(sec, 0))
    }

    /// Echo parser: emits one Vec<u8> per packet, side-tagged.
    #[derive(Default, Clone)]
    struct EchoUdp;
    impl DatagramParser for EchoUdp {
        type Message = (FlowSide, Vec<u8>);
        fn parse(&mut self, payload: &[u8], side: FlowSide, _ts: Timestamp) -> Vec<Self::Message> {
            vec![(side, payload.to_vec())]
        }
    }

    /// Plan 33: `finish()` closes every still-open UDP flow.
    #[test]
    fn finish_closes_open_flows() {
        let mut d = FlowDatagramDriver::new(FiveTuple::bidirectional(), EchoUdp);
        let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 53, b"q");
        d.track(view(&f, 0));
        let closed = d
            .finish()
            .into_iter()
            .filter(|e| matches!(e, SessionEvent::Closed { .. }))
            .count();
        assert_eq!(closed, 1, "finish() must close the open flow");
        assert!(d.finish().is_empty(), "second finish() yields nothing");
    }

    /// Plan 36: `on_tick` fires on `finish` for a live UDP flow,
    /// before that flow's `Closed`.
    #[test]
    fn on_tick_fires_on_finish() {
        #[derive(Default, Clone)]
        struct TickParser;
        impl DatagramParser for TickParser {
            type Message = u8;
            fn parse(&mut self, _p: &[u8], _s: FlowSide, _ts: Timestamp) -> Vec<u8> {
                Vec::new()
            }
            fn on_tick(&mut self, _now: Timestamp) -> Vec<u8> {
                vec![7]
            }
        }
        let mut d = FlowDatagramDriver::new(FiveTuple::bidirectional(), TickParser);
        let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 53, b"q");
        d.track(view(&f, 0));
        let count = |evs: Vec<SessionEvent<_, u8>>| {
            evs.iter()
                .filter(|e| matches!(e, SessionEvent::Application { message: 7, .. }))
                .count()
        };
        // finish() closes the UDP flow but drives a final on_tick.
        assert_eq!(count(d.finish()), 1);
        // No flows remain → no further ticks.
        assert_eq!(count(d.sweep(Timestamp::new(99, 0))), 0);
    }

    #[test]
    fn started_and_application_for_udp_packet() {
        let mut d = FlowDatagramDriver::new(FiveTuple::bidirectional(), EchoUdp);
        let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 53, b"query");
        let events = d.track(view(&f, 0));
        assert!(
            events
                .iter()
                .any(|e| matches!(e, SessionEvent::Started { .. }))
        );
        let app = events.iter().find_map(|e| match e {
            SessionEvent::Application {
                message: (s, b), ..
            } => Some((*s, b.clone())),
            _ => None,
        });
        assert_eq!(app, Some((FlowSide::Initiator, b"query".to_vec())));
    }

    #[test]
    fn closed_event_on_idle_timeout() {
        let cfg = FlowTrackerConfig {
            idle_timeout_udp: std::time::Duration::from_secs(1),
            ..FlowTrackerConfig::default()
        };
        let mut d = FlowDatagramDriver::with_config(FiveTuple::bidirectional(), EchoUdp, cfg);
        let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 53, b"q");
        d.track(view(&f, 0));
        let ended = d.sweep(Timestamp::new(10, 0));
        assert!(
            ended
                .iter()
                .any(|e| matches!(e, SessionEvent::Closed { .. }))
        );
    }

    #[test]
    fn tcp_packets_do_not_fire_application_events() {
        let mut d = FlowDatagramDriver::new(FiveTuple::bidirectional(), EchoUdp);
        let syn = ipv4_tcp(
            [0; 6],
            [0; 6],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            0,
            0,
            0x02,
            b"",
        );
        let events = d.track(view(&syn, 0));
        assert!(
            events
                .iter()
                .any(|e| matches!(e, SessionEvent::Started { .. }))
        );
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, SessionEvent::Application { .. })),
            "TCP packet produced an Application event in the UDP driver"
        );
    }

    /// Parser that poisons after >5 bytes on either side.
    #[derive(Default, Clone)]
    struct PoisonAfterBytes {
        seen: usize,
        poisoned: bool,
    }
    impl DatagramParser for PoisonAfterBytes {
        type Message = ();
        fn parse(&mut self, payload: &[u8], _side: FlowSide, _ts: Timestamp) -> Vec<()> {
            self.seen += payload.len();
            if self.seen > 5 {
                self.poisoned = true;
            }
            Vec::new()
        }
        fn is_poisoned(&self) -> bool {
            self.poisoned
        }
        fn poison_reason(&self) -> Option<&str> {
            if self.poisoned {
                Some("too many bytes")
            } else {
                None
            }
        }
    }

    #[test]
    fn datagram_parser_poison_synthesises_parse_error_closed() {
        let mut d =
            FlowDatagramDriver::new(FiveTuple::bidirectional(), PoisonAfterBytes::default());
        let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 53, b"0123456789");
        let events = d.track(view(&f, 0));
        let closed = events.iter().find_map(|e| match e {
            SessionEvent::Closed { reason, .. } => Some(*reason),
            _ => None,
        });
        assert_eq!(closed, Some(EndReason::ParseError));
    }
}

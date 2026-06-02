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

/// Boxed per-flow parser factory closure. Each new flow gets its
/// parser by calling this on the flow's key.
type ParserFactory<K, P> = Box<dyn FnMut(&K) -> P + Send>;

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
/// identical configuration. `S` defaults to `()`; use
/// [`Self::with_state`] / [`Self::with_state_init`] for per-flow
/// user state.
pub struct FlowDatagramDriver<E, P, S = ()>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + 'static,
    P: DatagramParser + Send + 'static,
    S: Send + 'static,
{
    driver: FlowDriver<E, NoopReassemblerFactory, S>,
    parser_factory: ParserFactory<E::Key, P>,
    parsers: HashMap<E::Key, P, RandomState>,
}

// Template-parser path — `S = ()`, `P: Clone`.
impl<E, P> FlowDatagramDriver<E, P, ()>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + 'static,
    P: DatagramParser + Clone + Send + 'static,
{
    /// Construct with default tracker config and `S = ()`. `parser`
    /// is cloned once per flow to give each flow a fresh instance.
    pub fn new(extractor: E, parser: P) -> Self {
        Self::with_config(extractor, parser, FlowTrackerConfig::default())
    }

    /// Construct with explicit tracker config and `S = ()`.
    pub fn with_config(extractor: E, parser: P, config: FlowTrackerConfig) -> Self {
        Self {
            driver: FlowDriver::with_config(extractor, NoopReassemblerFactory, config),
            parser_factory: Box::new(move |_key| parser.clone()),
            parsers: HashMap::with_hasher(RandomState::new()),
        }
    }
}

// Factory path — `S = ()`, no `P: Clone`.
impl<E, P> FlowDatagramDriver<E, P, ()>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + 'static,
    P: DatagramParser + Send + 'static,
{
    /// Construct with default tracker config and a per-flow parser
    /// factory closure. Drops the `P: Clone` requirement of [`Self::new`].
    pub fn with_factory<F>(extractor: E, factory: F) -> Self
    where
        F: FnMut(&E::Key) -> P + Send + 'static,
    {
        Self::with_factory_and_config(extractor, factory, FlowTrackerConfig::default())
    }

    /// Construct with explicit tracker config and a per-flow parser
    /// factory closure.
    pub fn with_factory_and_config<F>(extractor: E, factory: F, config: FlowTrackerConfig) -> Self
    where
        F: FnMut(&E::Key) -> P + Send + 'static,
    {
        Self {
            driver: FlowDriver::with_config(extractor, NoopReassemblerFactory, config),
            parser_factory: Box::new(factory),
            parsers: HashMap::with_hasher(RandomState::new()),
        }
    }
}

// Stateful template-parser path — `S: Default`, `P: Clone`.
impl<E, P, S> FlowDatagramDriver<E, P, S>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + 'static,
    P: DatagramParser + Clone + Send + 'static,
    S: Default + Send + 'static,
{
    /// Construct with default tracker config and per-flow state
    /// initialised via `S::default()`.
    pub fn with_state(extractor: E, parser: P) -> Self {
        Self::with_state_and_config(extractor, parser, FlowTrackerConfig::default())
    }

    /// Construct with explicit tracker config and per-flow state
    /// initialised via `S::default()`.
    pub fn with_state_and_config(extractor: E, parser: P, config: FlowTrackerConfig) -> Self {
        Self {
            driver: FlowDriver::with_state_and_config(extractor, NoopReassemblerFactory, config),
            parser_factory: Box::new(move |_key| parser.clone()),
            parsers: HashMap::with_hasher(RandomState::new()),
        }
    }
}

// Generic template-parser path — `P: Clone`, `S: Send + 'static`.
impl<E, P, S> FlowDatagramDriver<E, P, S>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + 'static,
    P: DatagramParser + Clone + Send + 'static,
    S: Send + 'static,
{
    /// Construct with default tracker config and a custom per-flow
    /// state initialiser.
    pub fn with_state_init<G>(extractor: E, parser: P, init: G) -> Self
    where
        G: FnMut(&E::Key) -> S + Send + 'static,
    {
        Self::with_state_init_and_config(extractor, parser, FlowTrackerConfig::default(), init)
    }

    /// Construct with explicit tracker config and a custom per-flow
    /// state initialiser.
    pub fn with_state_init_and_config<G>(
        extractor: E,
        parser: P,
        config: FlowTrackerConfig,
        init: G,
    ) -> Self
    where
        G: FnMut(&E::Key) -> S + Send + 'static,
    {
        Self {
            driver: FlowDriver::with_state_init_and_config(
                extractor,
                NoopReassemblerFactory,
                config,
                init,
            ),
            parser_factory: Box::new(move |_key| parser.clone()),
            parsers: HashMap::with_hasher(RandomState::new()),
        }
    }
}

// Stateful factory path — `S: Send + 'static`, no `P: Clone`.
impl<E, P, S> FlowDatagramDriver<E, P, S>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + 'static,
    P: DatagramParser + Send + 'static,
    S: Send + 'static,
{
    /// Construct with default tracker config, a per-flow parser
    /// factory, and a custom per-flow state initialiser.
    pub fn with_state_factory<FP, FS>(extractor: E, parser_factory: FP, state_init: FS) -> Self
    where
        FP: FnMut(&E::Key) -> P + Send + 'static,
        FS: FnMut(&E::Key) -> S + Send + 'static,
    {
        Self::with_state_factory_and_config(
            extractor,
            parser_factory,
            state_init,
            FlowTrackerConfig::default(),
        )
    }

    /// Construct with explicit tracker config, a per-flow parser
    /// factory, and a custom per-flow state initialiser.
    pub fn with_state_factory_and_config<FP, FS>(
        extractor: E,
        parser_factory: FP,
        state_init: FS,
        config: FlowTrackerConfig,
    ) -> Self
    where
        FP: FnMut(&E::Key) -> P + Send + 'static,
        FS: FnMut(&E::Key) -> S + Send + 'static,
    {
        Self {
            driver: FlowDriver::with_state_init_and_config(
                extractor,
                NoopReassemblerFactory,
                config,
                state_init,
            ),
            parser_factory: Box::new(parser_factory),
            parsers: HashMap::with_hasher(RandomState::new()),
        }
    }
}

// All non-construction methods — apply to every `S` and every
// parser-source variant.
impl<E, P, S> FlowDatagramDriver<E, P, S>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + 'static,
    P: DatagramParser + Send + 'static,
    S: Send + 'static,
{
    /// Opt in to forwarding [`SessionEvent::FlowAnomaly`] /
    /// [`SessionEvent::TrackerAnomaly`] events.
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
        // Plan 80: defer tear-down of any parser that finished
        // during on_tick to after the iteration so we don't mutate
        // self.parsers while borrowing it.
        enum TickClose<R> {
            Poison(FlowSide, Option<R>),
            Done,
        }
        let mut closes: Vec<(E::Key, TickClose<String>)> = Vec::new();
        for (key, parser) in self.parsers.iter_mut() {
            let kind = parser.parser_kind();
            for m in parser.on_tick(now) {
                crate::obs::trace_session_message(FlowSide::Initiator, &m);
                out.push(SessionEvent::Application {
                    key: key.clone(),
                    side: FlowSide::Initiator,
                    message: m,
                    ts: now,
                    parser_kind: kind,
                });
            }
            if parser.is_poisoned() {
                let reason = parser.poison_reason().map(truncate_reason);
                closes.push((key.clone(), TickClose::Poison(FlowSide::Initiator, reason)));
            } else if parser.is_done() {
                closes.push((key.clone(), TickClose::Done));
            }
        }
        let closed_keys: std::collections::HashSet<E::Key> =
            closes.iter().map(|(k, _)| k.clone()).collect();
        for (key, status) in closes {
            match status {
                TickClose::Poison(side, reason) => {
                    self.synthesise_parser_poison(&key, side, reason, now, &mut out);
                }
                TickClose::Done => {
                    self.synthesise_parser_done(&key, now, &mut out);
                }
            }
        }
        if !closed_keys.is_empty() {
            flow_events.retain(|ev| match ev {
                FlowEvent::Ended { key, .. } => !closed_keys.contains(key),
                _ => true,
            });
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
    pub fn tracker(&self) -> &FlowTracker<E, S> {
        self.driver.tracker()
    }

    /// Borrow the inner tracker mutably.
    pub fn tracker_mut(&mut self) -> &mut FlowTracker<E, S> {
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
                        .or_insert_with_key(|k| (self.parser_factory)(k));
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
                    let kind = parser.parser_kind();
                    let messages = parser.parse(payload, *side, *ts);
                    for m in messages {
                        crate::obs::trace_session_message(*side, &m);
                        out.push(SessionEvent::Application {
                            key: key.clone(),
                            side: *side,
                            message: m,
                            ts: *ts,
                            parser_kind: kind,
                        });
                    }
                    // Plan 55 — parser poison check.
                    // Plan 80 — parser-driven graceful close; poison wins.
                    if parser.is_poisoned() {
                        let reason = parser.poison_reason().map(truncate_reason);
                        self.synthesise_parser_poison(key, *side, reason, *ts, &mut out);
                    } else if parser.is_done() {
                        self.synthesise_parser_done(key, *ts, &mut out);
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
                FlowEvent::FlowAnomaly { key, kind, ts } => {
                    out.push(SessionEvent::FlowAnomaly {
                        key: key.clone(),
                        kind: kind.clone(),
                        ts: *ts,
                    });
                }
                FlowEvent::TrackerAnomaly { kind, ts } => {
                    out.push(SessionEvent::TrackerAnomaly {
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
            out.push(SessionEvent::FlowAnomaly {
                key: key.clone(),
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

    /// Plan 80: parser-driven graceful close (mirror of
    /// [`Self::synthesise_parser_poison`] without the anomaly).
    fn synthesise_parser_done(
        &mut self,
        key: &E::Key,
        ts: Timestamp,
        out: &mut Vec<SessionEvent<E::Key, P::Message>>,
    ) {
        let _ = ts;
        let stats = self
            .driver
            .tracker()
            .snapshot_stats(key)
            .unwrap_or_default();
        crate::obs::record_flow_ended(EndReason::ParserDone, &stats);
        crate::obs::trace_flow_ended(EndReason::ParserDone, &stats);
        out.push(SessionEvent::Closed {
            key: key.clone(),
            reason: EndReason::ParserDone,
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

    /// Plan 38: `FlowDatagramDriver::with_state_init` threads `S`.
    #[test]
    fn with_state_init_threads_s() {
        #[derive(Debug)]
        #[allow(dead_code)]
        struct MyState(u64);
        let d: FlowDatagramDriver<_, _, MyState> =
            FlowDatagramDriver::with_state_init(FiveTuple::bidirectional(), EchoUdp, |_key| {
                MyState(7)
            });
        let _: &FlowTracker<FiveTuple, MyState> = d.tracker();
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

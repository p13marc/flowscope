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
//!     fn feed_initiator(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<Vec<u8>>) {
//!         out.push(bytes.to_vec());
//!     }
//!     fn feed_responder(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<Vec<u8>>) {
//!         out.push(bytes.to_vec());
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
use crate::event::{AnomalyKind, EndReason, FlowEvent, FlowSide};
use crate::extractor::FlowExtractor;
use crate::flow_driver::FlowDriver;
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

/// Build a `BufferedReassemblerFactory` honouring the tracker
/// config's `max_reassembler_buffer` / `overflow_policy` fields.
/// Factored out so all four `FlowSessionDriver` constructors share
/// the wiring.
/// Boxed per-flow parser factory closure. Each new flow gets its
/// parser by calling this on the flow's key.
type ParserFactory<K, P> = Box<dyn FnMut(&K) -> P + Send + Sync>;

fn build_reassembler_factory(config: &FlowTrackerConfig) -> BufferedReassemblerFactory {
    let mut f = BufferedReassemblerFactory::default();
    if let Some(cap) = config.max_reassembler_buffer {
        f = f
            .with_max_buffer(cap)
            .with_overflow_policy(config.overflow_policy);
    }
    if let Some(pct) = config.reassembler_high_watermark_pct {
        f = f.with_high_watermark_threshold(pct);
    }
    f
}

/// Sync session-event driver. Wraps a [`FlowDriver`] with
/// [`BufferedReassemblerFactory`] and adds per-flow
/// [`SessionParser`] dispatch.
///
/// Type parameters:
/// - `E` — the flow extractor.
/// - `P` — the session parser; `P: Clone` is required so the driver
///   can mint per-flow instances by cloning a template (use
///   [`Self::new`]). The bound is dropped on the factory-based
///   constructor (see plan 58).
/// - `S` — optional per-flow user state, defaulting to `()`. Use
///   [`Self::new`] / [`Self::with_config`] for `S = ()` (no
///   annotation required); use [`Self::with_state`] /
///   [`Self::with_state_init`] when per-flow state is needed.
pub struct FlowSessionDriver<E, P, S = ()>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + Sync + 'static,
    P: SessionParser + Send + Sync + 'static,
    S: Send + 'static,
{
    driver: FlowDriver<E, BufferedReassemblerFactory, S>,
    /// Per-flow parser constructor. Built either by wrapping a
    /// template parser in a move closure (`new` / `with_state*`) or
    /// from a caller-supplied `FnMut` (`with_factory*`).
    parser_factory: ParserFactory<E::Key, P>,
    parsers: HashMap<E::Key, P, RandomState>,
}

// Template-parser path — `S = ()` and `P: Clone`. Constructors
// pinned so common-case call sites need no type annotation. The
// template is cloned once per new flow.
impl<E, P> FlowSessionDriver<E, P, ()>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + Sync + 'static,
    P: SessionParser + Clone + Send + Sync + 'static,
{
    /// Construct with default tracker config and `S = ()`. `parser`
    /// is cloned once per flow to give each session a fresh instance.
    pub fn new(extractor: E, parser: P) -> Self {
        Self::with_config(extractor, parser, FlowTrackerConfig::default())
    }

    /// Construct with explicit tracker config and `S = ()`. Honours
    /// `config.max_reassembler_buffer` and `config.overflow_policy`
    /// when building per-flow reassemblers.
    pub fn with_config(extractor: E, parser: P, config: FlowTrackerConfig) -> Self {
        let reassembler = build_reassembler_factory(&config);
        Self {
            driver: FlowDriver::with_config(extractor, reassembler, config),
            parser_factory: Box::new(move |_key| parser.clone()),
            parsers: HashMap::with_hasher(RandomState::new()),
        }
    }
}

// Factory path — `S = ()`. `P` doesn't need `Clone`; each flow's
// parser is minted by the caller-supplied closure. Use for parsers
// with expensive setup (compiled regex sets, ML model weights, …)
// where you'd rather share state via `Arc` than clone a template.
impl<E, P> FlowSessionDriver<E, P, ()>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + Sync + 'static,
    P: SessionParser + Send + Sync + 'static,
{
    /// Construct with default tracker config and a per-flow parser
    /// factory closure. Drops the `P: Clone` requirement of [`Self::new`].
    pub fn with_factory<F>(extractor: E, factory: F) -> Self
    where
        F: FnMut(&E::Key) -> P + Send + Sync + 'static,
    {
        Self::with_factory_and_config(extractor, factory, FlowTrackerConfig::default())
    }

    /// Construct with explicit tracker config and a per-flow parser
    /// factory closure.
    pub fn with_factory_and_config<F>(extractor: E, factory: F, config: FlowTrackerConfig) -> Self
    where
        F: FnMut(&E::Key) -> P + Send + Sync + 'static,
    {
        let reassembler = build_reassembler_factory(&config);
        Self {
            driver: FlowDriver::with_config(extractor, reassembler, config),
            parser_factory: Box::new(factory),
            parsers: HashMap::with_hasher(RandomState::new()),
        }
    }
}

// Stateful template-parser path — `S: Default`, `P: Clone`.
impl<E, P, S> FlowSessionDriver<E, P, S>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + Sync + 'static,
    P: SessionParser + Clone + Send + Sync + 'static,
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
        let reassembler = build_reassembler_factory(&config);
        Self {
            driver: FlowDriver::with_state_and_config(extractor, reassembler, config),
            parser_factory: Box::new(move |_key| parser.clone()),
            parsers: HashMap::with_hasher(RandomState::new()),
        }
    }
}

// Generic path — `S: Send + 'static` only. Custom state init +
// every non-construction method. `P: Clone` for the
// template-parser stateful ctors; the factory variants live on
// the impl block below.
impl<E, P, S> FlowSessionDriver<E, P, S>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + Sync + 'static,
    P: SessionParser + Clone + Send + Sync + 'static,
    S: Send + 'static,
{
    /// Construct with default tracker config and a custom per-flow
    /// state initialiser. Use when `S` isn't `Default` or when state
    /// should be derived from the flow key.
    pub fn with_state_init<G>(extractor: E, parser: P, init: G) -> Self
    where
        G: FnMut(&E::Key) -> S + Send + Sync + 'static,
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
        G: FnMut(&E::Key) -> S + Send + Sync + 'static,
    {
        let reassembler = build_reassembler_factory(&config);
        Self {
            driver: FlowDriver::with_state_init_and_config(extractor, reassembler, config, init),
            parser_factory: Box::new(move |_key| parser.clone()),
            parsers: HashMap::with_hasher(RandomState::new()),
        }
    }
}

// Stateful factory path — `S: Send + 'static`, no `P: Clone`.
impl<E, P, S> FlowSessionDriver<E, P, S>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + Sync + 'static,
    P: SessionParser + Send + Sync + 'static,
    S: Send + 'static,
{
    /// Construct with default tracker config, a per-flow parser
    /// factory, and a custom per-flow state initialiser.
    pub fn with_state_factory<FP, FS>(extractor: E, parser_factory: FP, state_init: FS) -> Self
    where
        FP: FnMut(&E::Key) -> P + Send + Sync + 'static,
        FS: FnMut(&E::Key) -> S + Send + Sync + 'static,
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
        FP: FnMut(&E::Key) -> P + Send + Sync + 'static,
        FS: FnMut(&E::Key) -> S + Send + Sync + 'static,
    {
        let reassembler = build_reassembler_factory(&config);
        Self {
            driver: FlowDriver::with_state_init_and_config(
                extractor,
                reassembler,
                config,
                state_init,
            ),
            parser_factory: Box::new(parser_factory),
            parsers: HashMap::with_hasher(RandomState::new()),
        }
    }
}

// All non-construction methods — apply to every `S` and every
// parser-source variant (no `P: Clone` bound).
impl<E, P, S> FlowSessionDriver<E, P, S>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + Sync + 'static,
    P: SessionParser + Send + Sync + 'static,
    S: Send + 'static,
{
    /// Opt in to forwarding [`SessionEvent::FlowAnomaly`] /
    /// [`SessionEvent::TrackerAnomaly`] events through the
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
        G: Fn(&E::Key, Option<crate::L4Proto>) -> Option<std::time::Duration> + Send + Sync + 'static,
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
        let mut out = Vec::new();
        self.track_into(view, &mut out);
        out
    }

    /// Append-only variant of [`Self::track`]. Reuses the caller's
    /// capacity — zero allocation at this surface in steady state.
    /// Plan 119 / 121 deep zero-alloc threading.
    pub fn track_into<'v>(
        &mut self,
        view: impl Into<PacketView<'v>>,
        out: &mut Vec<SessionEvent<E::Key, P::Message>>,
    ) {
        let mut flow_events = self.driver.track_pending(view);
        self.translate_events_into(&flow_events, out);
        self.driver.finalize(flow_events.as_mut_slice());
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
        // Plan 80: collect (key, status) for parsers that finished
        // during on_tick. Defer tear-down to after the iteration so
        // we don't mutate self.parsers while borrowing it.
        enum TickClose<R> {
            Poison(FlowSide, Option<R>),
            Done,
        }
        let mut closes: Vec<(E::Key, TickClose<String>)> = Vec::new();
        let mut tick_scratch: Vec<P::Message> = Vec::new();
        for (key, parser) in self.parsers.iter_mut() {
            let kind = parser.parser_kind();
            tick_scratch.clear();
            parser.on_tick(now, &mut tick_scratch);
            for m in tick_scratch.drain(..) {
                crate::obs::trace_session_message(FlowSide::Initiator, &m);
                out.push(SessionEvent::Application {
                    key: key.clone(),
                    side: FlowSide::Initiator,
                    message: m,
                    ts: now,
                    parser_kind: kind,
                });
            }
            // Poison wins over done.
            if parser.is_poisoned() {
                let reason = parser.poison_reason().map(truncate_reason);
                closes.push((key.clone(), TickClose::Poison(FlowSide::Initiator, reason)));
            } else if parser.is_done() {
                closes.push((key.clone(), TickClose::Done));
            }
        }
        // Process deferred tear-downs.
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
        // Filter out any tracker-driven Ended events for flows we
        // already closed via tick tear-down — prevents double-Closed
        // emission if the tracker also idle-timed the same flow this
        // sweep.
        if !closed_keys.is_empty() {
            flow_events.retain(|ev| match ev {
                FlowEvent::Ended { key, .. } => !closed_keys.contains(key),
                _ => true,
            });
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

    /// Force-end the session with this key. Mirror of
    /// [`crate::FlowTracker::force_close`] / [`FlowDriver::force_close`]
    /// at the session layer. New in 0.8.0.
    ///
    /// Drains any buffered initiator/responder bytes through the
    /// parser (one last `feed_*` per side), calls `fin_initiator()`
    /// / `fin_responder()` to flush parser-side closing messages,
    /// emits the resulting `Application` events, removes the parser
    /// slot, then forwards the underlying driver's `Ended` event
    /// as `SessionEvent::Closed { reason: ForceClosed, .. }`.
    ///
    /// Returns the resulting events; empty if `key` was not active.
    pub fn force_close(
        &mut self,
        key: &E::Key,
        now: Timestamp,
    ) -> Vec<SessionEvent<E::Key, P::Message>> {
        let mut out = Vec::new();
        // Drain reassembled bytes into the parser before tear-down,
        // so any messages buffered in the reassembler don't get
        // dropped.
        self.drain_into_parser(key, now, &mut out);
        // The drain may have synthesised a parser-poison / parser-done
        // close already; if so the parser slot is gone and the
        // driver-level force_close will report no flow.
        let driver_events = self.driver.force_close(key, now);
        out.extend(self.translate_events(&driver_events));
        out
    }

    /// Borrow the inner tracker (for stats, introspection).
    pub fn tracker(&self) -> &FlowTracker<E, S> {
        self.driver.tracker()
    }

    /// Borrow the inner tracker mutably.
    pub fn tracker_mut(&mut self) -> &mut FlowTracker<E, S> {
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
        let mut out = Vec::new();
        self.translate_events_into(flow_events, &mut out);
        out
    }

    fn translate_events_into(
        &mut self,
        flow_events: &[FlowEvent<E::Key>],
        out: &mut Vec<SessionEvent<E::Key, P::Message>>,
    ) {
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
                FlowEvent::Packet { key, ts, .. } => {
                    self.drain_into_parser(key, *ts, out);
                }
                FlowEvent::Ended {
                    key,
                    reason,
                    stats,
                    l4,
                    ..
                } => {
                    // Final drain (captures FIN-with-payload bytes
                    // before the reassembler is dropped in finalize),
                    // then call the parser's fin/rst hook.
                    let ts = stats.last_seen;
                    self.drain_into_parser(key, ts, out);
                    if let Some(mut parser) = self.parsers.remove(key) {
                        let kind = parser.parser_kind();
                        match reason {
                            EndReason::Fin
                            | EndReason::IdleTimeout
                            | EndReason::ParserDone
                            | EndReason::ForceClosed => {
                                let mut fin_scratch: Vec<P::Message> = Vec::new();
                                parser.fin_initiator(&mut fin_scratch);
                                for m in fin_scratch.drain(..) {
                                    out.push(SessionEvent::Application {
                                        key: key.clone(),
                                        side: FlowSide::Initiator,
                                        message: m,
                                        ts,
                                        parser_kind: kind,
                                    });
                                }
                                parser.fin_responder(&mut fin_scratch);
                                for m in fin_scratch.drain(..) {
                                    out.push(SessionEvent::Application {
                                        key: key.clone(),
                                        side: FlowSide::Responder,
                                        message: m,
                                        ts,
                                        parser_kind: kind,
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
                        l4: *l4,
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
                    // TCP-machine internal transitions; not surfaced
                    // to SessionEvent.
                }
            }
        }
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
            let kind = parser.parser_kind();
            let mut messages: Vec<P::Message> = Vec::new();
            match side {
                FlowSide::Initiator => parser.feed_initiator(&drained, ts, &mut messages),
                FlowSide::Responder => parser.feed_responder(&drained, ts, &mut messages),
            }
            for m in messages.drain(..) {
                crate::obs::trace_session_message(side, &m);
                out.push(SessionEvent::Application {
                    key: key.clone(),
                    side,
                    message: m,
                    ts,
                    parser_kind: kind,
                });
            }
            // Plan 55: check is_poisoned() after every feed_*. If
            // the parser has poisoned, emit the anomaly + synthesise
            // a parse-error Closed event, then tear down the parser
            // slot. The flow stays in the tracker (FlowDriver
            // doesn't see SessionParser poison); subsequent packets
            // will produce no further Application events because the
            // parser slot is gone.
            //
            // Plan 80: same wiring for is_done() — synthesise a
            // ParserDone Closed event. Poison precedence: a parser
            // that's both poisoned AND done surfaces as ParseError.
            if parser.is_poisoned() {
                let reason = parser.poison_reason().map(truncate_reason);
                self.synthesise_parser_poison(key, side, reason, ts, out);
                return;
            }
            if parser.is_done() {
                self.synthesise_parser_done(key, ts, out);
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
            out.push(SessionEvent::FlowAnomaly {
                key: key.clone(),
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
        let l4 = self.driver.tracker().snapshot_l4(key);
        crate::obs::record_flow_ended(EndReason::ParseError, &stats);
        crate::obs::trace_flow_ended(EndReason::ParseError, &stats);
        out.push(SessionEvent::Closed {
            key: key.clone(),
            reason: EndReason::ParseError,
            stats,
            l4,
        });
        self.parsers.remove(key);
        self.driver.tracker_mut().forget(key);
    }

    /// Plan 80: parser-driven graceful close. No anomaly is emitted
    /// (the parser is signalling success, not failure). Mirrors
    /// [`Self::synthesise_parser_poison`] in shape: snapshot stats,
    /// record metrics, emit Closed, drop the parser slot, forget the
    /// flow in the tracker.
    fn synthesise_parser_done(
        &mut self,
        key: &E::Key,
        ts: Timestamp,
        out: &mut Vec<SessionEvent<E::Key, P::Message>>,
    ) {
        let _ = ts; // No anomaly event needed; ts only matters if we
        // re-emit an anomaly here in the future.
        let stats = self
            .driver
            .tracker()
            .snapshot_stats(key)
            .unwrap_or_default();
        let l4 = self.driver.tracker().snapshot_l4(key);
        crate::obs::record_flow_ended(EndReason::ParserDone, &stats);
        crate::obs::trace_flow_ended(EndReason::ParserDone, &stats);
        out.push(SessionEvent::Closed {
            key: key.clone(),
            reason: EndReason::ParserDone,
            stats,
            l4,
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
            fn feed_initiator(&mut self, _b: &[u8], _ts: Timestamp, _out: &mut Vec<()>) {}
            fn feed_responder(&mut self, _b: &[u8], _ts: Timestamp, _out: &mut Vec<()>) {}
        }
        let _d = FlowSessionDriver::new(FiveTuple::bidirectional(), ConfigParser { _limit: 4096 });
    }

    /// Plan 38: `FlowSessionDriver::with_state_init` threads `S`
    /// through to the inner tracker.
    #[test]
    fn with_state_init_threads_s() {
        #[derive(Debug)]
        struct MyState(u64);
        let d: FlowSessionDriver<_, _, MyState> = FlowSessionDriver::with_state_init(
            FiveTuple::bidirectional(),
            LineParser::default(),
            |_key| MyState(7),
        );
        let tracker: &FlowTracker<FiveTuple, MyState> = d.tracker();
        let states: Vec<u64> = tracker.iter_active().map(|f| f.user.0).collect();
        let _ = states;
    }

    /// Plan 58: `with_factory` works with a `!Clone` parser.
    #[test]
    fn with_factory_accepts_non_clone_parser() {
        // A parser that owns a *non-Clone* resource (`Box<u32>` —
        // just a stand-in for a real expensive-setup type).
        struct ExpensiveParser {
            _heavy: Box<u32>,
        }
        impl SessionParser for ExpensiveParser {
            type Message = ();
            fn feed_initiator(&mut self, _b: &[u8], _ts: Timestamp, _out: &mut Vec<()>) {}
            fn feed_responder(&mut self, _b: &[u8], _ts: Timestamp, _out: &mut Vec<()>) {}
        }
        // Wouldn't compile with FlowSessionDriver::new (needs Clone).
        let mut d =
            FlowSessionDriver::with_factory(FiveTuple::bidirectional(), |_k: &_| ExpensiveParser {
                _heavy: Box::new(42),
            });
        // Drive a packet to make sure the factory is callable.
        let _ = d.track(view(b"", 0));
    }

    /// Plan 38: `with_state` works for any `S: Default` parser.
    #[test]
    fn with_state_uses_default() {
        #[derive(Debug, Default)]
        struct Counter(u32);
        let d: FlowSessionDriver<_, _, Counter> =
            FlowSessionDriver::with_state(FiveTuple::bidirectional(), LineParser::default());
        let tracker: &FlowTracker<FiveTuple, Counter> = d.tracker();
        let counts: Vec<u32> = tracker.iter_active().map(|f| f.user.0).collect();
        let _ = counts;
    }

    /// Tiny line-oriented parser: emits one Vec<u8> per newline-terminated frame.
    #[derive(Default, Clone)]
    struct LineParser {
        init: Vec<u8>,
        resp: Vec<u8>,
    }

    impl SessionParser for LineParser {
        type Message = (FlowSide, Vec<u8>);

        fn feed_initiator(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<Self::Message>) {
            drain(&mut self.init, bytes, FlowSide::Initiator, out);
        }
        fn feed_responder(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<Self::Message>) {
            drain(&mut self.resp, bytes, FlowSide::Responder, out);
        }
    }

    fn drain(buf: &mut Vec<u8>, bytes: &[u8], side: FlowSide, out: &mut Vec<(FlowSide, Vec<u8>)>) {
        buf.extend_from_slice(bytes);
        while let Some(nl) = buf.iter().position(|&b| b == b'\n') {
            let line = buf[..nl].to_vec();
            out.push((side, line));
            buf.drain(..=nl);
        }
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
            fn feed_initiator(&mut self, _b: &[u8], _ts: Timestamp, _out: &mut Vec<u8>) {}
            fn feed_responder(&mut self, _b: &[u8], _ts: Timestamp, _out: &mut Vec<u8>) {}
            fn on_tick(&mut self, _now: Timestamp, out: &mut Vec<u8>) {
                out.push(42);
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
                SessionEvent::FlowAnomaly {
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
            !events.iter().any(|e| e.anomaly_kind().is_some()),
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
        fn feed_initiator(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<Vec<u8>>) {
            self.init_bytes += bytes.len();
            if self.init_bytes > 5 {
                self.poisoned = true;
            }
            out.push(bytes.to_vec());
        }
        fn feed_responder(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<Vec<u8>>) {
            out.push(bytes.to_vec());
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
                    SessionEvent::FlowAnomaly {
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
            SessionEvent::FlowAnomaly {
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

    // ── Plan 80: SessionParser::is_done() / EndReason::ParserDone ──

    /// Parser that emits one message on first `feed_initiator` and
    /// then reports `is_done() == true`. Single-pair completion
    /// semantics (HTTP/1.0 after body, DNS-over-TCP after Q/R).
    #[derive(Default, Clone)]
    struct DoneAfterOne {
        done: bool,
    }
    impl SessionParser for DoneAfterOne {
        type Message = ();
        fn feed_initiator(&mut self, _bytes: &[u8], _ts: Timestamp, out: &mut Vec<()>) {
            self.done = true;
            out.push(());
        }
        fn feed_responder(&mut self, _bytes: &[u8], _ts: Timestamp, _out: &mut Vec<()>) {}
        fn is_done(&self) -> bool {
            self.done
        }
    }

    #[test]
    fn is_done_triggers_parser_done_close() {
        let mut d = FlowSessionDriver::new(FiveTuple::bidirectional(), DoneAfterOne::default());
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
            b"hello",
        );
        events.extend(d.track(view(&data, 0)));
        let closed = events
            .iter()
            .find_map(|e| match e {
                SessionEvent::Closed { reason, .. } => Some(*reason),
                _ => None,
            })
            .expect("Closed event");
        assert_eq!(closed, EndReason::ParserDone);
    }

    #[test]
    fn is_done_emits_no_anomaly() {
        // ParserDone is a clean close — no FlowAnomaly should be
        // synthesised even when emit_anomalies is on.
        let mut d = FlowSessionDriver::new(FiveTuple::bidirectional(), DoneAfterOne::default())
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
            b"hello",
        );
        events.extend(d.track(view(&data, 0)));
        assert!(
            !events.iter().any(|e| matches!(
                e,
                SessionEvent::FlowAnomaly {
                    kind: AnomalyKind::SessionParseError { .. },
                    ..
                }
            )),
            "ParserDone close should not emit a SessionParseError anomaly"
        );
    }

    /// Parser that returns `true` from BOTH is_poisoned and
    /// is_done. Poison must win (worse condition).
    #[derive(Clone)]
    struct BothPoisonedAndDone;
    impl SessionParser for BothPoisonedAndDone {
        type Message = ();
        fn feed_initiator(&mut self, _bytes: &[u8], _ts: Timestamp, out: &mut Vec<()>) {
            out.push(());
        }
        fn feed_responder(&mut self, _bytes: &[u8], _ts: Timestamp, _out: &mut Vec<()>) {}
        fn is_poisoned(&self) -> bool {
            true
        }
        fn is_done(&self) -> bool {
            true
        }
    }

    #[test]
    fn is_poisoned_wins_over_is_done() {
        let mut d = FlowSessionDriver::new(FiveTuple::bidirectional(), BothPoisonedAndDone);
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
            b"hello",
        );
        events.extend(d.track(view(&data, 0)));
        let closed = events
            .iter()
            .find_map(|e| match e {
                SessionEvent::Closed { reason, .. } => Some(*reason),
                _ => None,
            })
            .expect("Closed event");
        assert_eq!(closed, EndReason::ParseError, "poison must win over done");
    }

    #[test]
    fn parser_done_flow_does_not_double_close_on_natural_fin() {
        // Flow closes via ParserDone; subsequent FIN packet should
        // not produce a second Closed event for the same flow
        // (the tracker entry was already forgotten).
        let mut d = FlowSessionDriver::new(FiveTuple::bidirectional(), DoneAfterOne::default());
        let mut events = Vec::new();
        for f in build_3whs() {
            events.extend(d.track(view(&f, 0)));
        }
        let mac = [0u8; 6];
        // Trigger ParserDone.
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
            b"hello",
        );
        events.extend(d.track(view(&data, 0)));
        // Now feed a FIN — flow already gone from the tracker, so
        // this looks like a fresh flow's first packet (no Closed
        // for the original flow).
        let fin = ipv4_tcp(
            mac,
            mac,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            1006,
            5001,
            0x11,
            &[],
        );
        events.extend(d.track(view(&fin, 1)));
        let closed_count = events
            .iter()
            .filter(|e| matches!(e, SessionEvent::Closed { .. }))
            .count();
        assert_eq!(closed_count, 1, "expected exactly one Closed event");
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
                SessionEvent::TrackerAnomaly {
                    kind: AnomalyKind::FlowTableEvictionPressure { .. },
                    ..
                }
            )
        });
        let pressure = pressure.expect("expected an eviction-pressure anomaly");
        match pressure {
            SessionEvent::TrackerAnomaly {
                kind:
                    AnomalyKind::FlowTableEvictionPressure {
                        evicted_in_tick, ..
                    },
                ..
            } => {
                // TrackerAnomaly carries no key — its absence in the
                // destructure pattern is the assertion.
                assert_eq!(*evicted_in_tick, 1);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn parser_kind_threaded_into_application_events() {
        // Custom parser with a non-default parser_kind. Drive a flow
        // through the session driver; every `Application` event must
        // carry the parser's kind verbatim.
        #[derive(Default, Clone)]
        struct KindedParser;
        impl SessionParser for KindedParser {
            type Message = u8;
            fn feed_initiator(&mut self, _b: &[u8], _ts: Timestamp, out: &mut Vec<u8>) {
                out.push(1);
            }
            fn feed_responder(&mut self, _b: &[u8], _ts: Timestamp, out: &mut Vec<u8>) {
                out.push(2);
            }
            fn parser_kind(&self) -> &'static str {
                "kinded"
            }
        }
        let mut d = FlowSessionDriver::new(FiveTuple::bidirectional(), KindedParser);
        let mac = [0u8; 6];
        let ip_a = [10, 0, 0, 1];
        let ip_b = [10, 0, 0, 2];
        // 3WHS + initiator data.
        let frames = [
            ipv4_tcp(mac, mac, ip_a, ip_b, 1234, 80, 1000, 0, 0x02, b""),
            ipv4_tcp(mac, mac, ip_b, ip_a, 80, 1234, 5000, 1001, 0x12, b""),
            ipv4_tcp(mac, mac, ip_a, ip_b, 1234, 80, 1001, 5001, 0x10, b""),
            ipv4_tcp(mac, mac, ip_a, ip_b, 1234, 80, 1001, 5001, 0x18, b"x"),
        ];
        let mut events = Vec::new();
        for f in &frames {
            events.extend(d.track(view(f, 0)));
        }
        let app: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                SessionEvent::Application { parser_kind, .. } => Some(*parser_kind),
                _ => None,
            })
            .collect();
        assert!(!app.is_empty(), "expected at least one Application event");
        for k in app {
            assert_eq!(k, "kinded");
        }
    }

    #[test]
    fn default_parser_kind_is_empty() {
        #[derive(Default, Clone)]
        struct Noop;
        impl SessionParser for Noop {
            type Message = u8;
            fn feed_initiator(&mut self, _b: &[u8], _ts: Timestamp, _out: &mut Vec<u8>) {}
            fn feed_responder(&mut self, _b: &[u8], _ts: Timestamp, _out: &mut Vec<u8>) {}
        }
        assert_eq!(Noop.parser_kind(), "");
    }

    #[cfg(all(feature = "http", feature = "tls", feature = "dns"))]
    #[test]
    fn shipped_http_tls_dns_parser_kinds() {
        use crate::DatagramParser as _;
        use crate::dns::{DnsTcpParser, DnsUdpParser};
        use crate::http::HttpParser;
        use crate::tls::TlsParser;
        assert_eq!(HttpParser::default().parser_kind(), "http/1");
        assert_eq!(TlsParser::default().parser_kind(), "tls");
        assert_eq!(DnsTcpParser::default().parser_kind(), "dns-tcp");
        assert_eq!(DnsUdpParser::default().parser_kind(), "dns-udp");
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

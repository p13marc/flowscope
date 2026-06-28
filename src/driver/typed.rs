//! Plan 121 architectural shape — `Driver<E>` with typed slot
//! drain handles.
//!
//! Replaces the 0.10-era closed-`M` `Driver<E, M>` shape:
//!
//! - **No `M` parameter.** The driver emits flow-lifecycle
//!   [`Event<K>`] only. Per-parser typed messages flow through
//!   [`super::SlotHandle<M, K>`] returned from the builder at
//!   registration time.
//! - **No lift closures.** Each parser stays typed at its own
//!   `P::Message`; consumers drain a typed handle. The
//!   netring-style `monitor.protocol::<Http>(handler)` pattern
//!   reduces to one slot-handle drain per protocol.
//! - **Pull-based, single-threaded.** Drain happens at the
//!   consumer's pace inside the event loop. For cross-task
//!   delivery, users build a channel on top of the drain.
//!
//! ```ignore
//! use flowscope::driver::{Driver, Event};
//! use flowscope::driver::SlotMessage;
//! use flowscope::extract::FiveTuple;
//! use flowscope::http::{HttpMessage, HttpParser};
//! use flowscope::extract::FiveTupleKey;
//!
//! let mut builder = Driver::builder(FiveTuple::bidirectional());
//! let mut http_slot = builder.session_on_ports(HttpParser::default(), [80, 8080]);
//! let mut driver = builder.build();
//!
//! let mut lifecycle: Vec<Event<FiveTupleKey>> = Vec::new();
//! let mut http_msgs: Vec<SlotMessage<HttpMessage, FiveTupleKey>> = Vec::new();
//!
//! // driver.track_into(view, &mut lifecycle);
//! // http_slot.drain(&mut http_msgs);
//! ```

use std::{hash::Hash, time::Duration};

use super::{
    BroadcastSlotHandle,
    slot::SlotHandle,
    typed_slot::{ErasedSlot, TypedConcreteDatagramSlot, TypedConcreteSlot},
    typed_slot_heuristic::{TypedHeuristicDatagramSlot, TypedHeuristicSessionSlot},
};
use crate::{
    PacketView, Timestamp,
    dedup::Dedup,
    detect::signatures::SignatureFn,
    event::{AnomalyKind, EndReason, FlowEvent, FlowSide, FlowState, FlowStats},
    extractor::{FlowExtractor, L4Proto, TcpInfo},
    flow_driver::FlowDriver,
    history::HistoryString,
    parser_kind::ParserKind,
    reassembler::NoopReassemblerFactory,
    session::{DatagramParser, SessionParser},
    tracker::{FlowTracker, FlowTrackerConfig},
};

/// Per-key idle-timeout predicate, boxed.
type IdleTimeoutFn<K> =
    Box<dyn Fn(&K, Option<L4Proto>) -> Option<Duration> + Send + Sync + 'static>;

/// Flow-lifecycle event type for the typed driver.
///
/// Plan 121: no `M` parameter, no `Message` variant — per-parser
/// typed messages flow through [`SlotHandle`] returned by the
/// builder. `ParserClosed` stays as a lifecycle marker for when
/// a parser self-terminates.
///
/// `Serialize`able under the `serde` feature with the same
/// `tag = "type"` / `snake_case` shape as
/// [`FlowEvent`](crate::FlowEvent), and convertible from it via
/// `Event::from(flow_event)` (issue #97). The conversion is
/// lossless — [`FlowEvent::StateChange`] maps to
/// [`Self::FlowStateChange`].
///
/// `Serialize` only (not `Deserialize`): the driver only ever emits
/// events, so only the serialize half is derived. To read events back,
/// deserialize the tracker primitive [`FlowEvent`](crate::FlowEvent)
/// (which is round-trippable) and `Event::from` it.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", rename_all = "snake_case"))]
#[cfg_attr(feature = "serde", serde(bound(serialize = "K: serde::Serialize")))]
#[non_exhaustive]
pub enum Event<K> {
    /// First packet of a new flow.
    FlowStarted {
        key: K,
        ts: Timestamp,
        l4: Option<L4Proto>,
    },

    /// TCP flow reached the `Established` state (3-way handshake
    /// complete). Not emitted for UDP / ICMP flows.
    FlowEstablished {
        key: K,
        ts: Timestamp,
        l4: Option<L4Proto>,
    },

    /// TCP state-machine transition other than reaching
    /// `Established` (e.g. `Established → FinWait`). The lossless
    /// counterpart of [`FlowEvent::StateChange`] (issue #97).
    ///
    /// The typed `Driver<E>` does **not** emit this today —
    /// `FlowEstablished` covers the common case and the driver
    /// historically omits raw state churn — but the variant exists
    /// so `Event::from(FlowEvent::StateChange { .. })` is lossless
    /// and so future driver modes can surface it.
    FlowStateChange {
        key: K,
        from: FlowState,
        to: FlowState,
        ts: Timestamp,
    },

    /// Per-packet event on an existing flow.
    ///
    /// # Per-packet TCP details
    ///
    /// The `tcp` field is **always `None` unless the driver was
    /// built with [`DriverBuilder::emit_packet_details`]`(true)`**
    /// — that's an opt-in, off by default to avoid per-packet
    /// extractor re-parse cost. Reading `tcp` on a default-
    /// configured driver and getting `None` is expected, not a
    /// bug. Use the convenience accessor [`Event::tcp`] when you
    /// want "tcp info if available, on any variant" without
    /// destructuring.
    FlowPacket {
        key: K,
        side: FlowSide,
        len: usize,
        ts: Timestamp,
        tcp: Option<TcpInfo>,
    },

    /// Flow ended (FIN / RST / idle / eviction / parser close).
    FlowEnded {
        key: K,
        reason: EndReason,
        stats: FlowStats,
        history: HistoryString,
        l4: Option<L4Proto>,
        ts: Timestamp,
    },

    /// Periodic [`FlowStats`] snapshot — emitted when
    /// [`crate::FlowTrackerConfig::flow_tick_interval`] is set.
    FlowTick {
        key: K,
        stats: FlowStats,
        ts: Timestamp,
    },

    /// Parser-level close — a registered parser drained its
    /// `fin_*` accumulator or reported `is_done` / `is_poisoned`.
    /// Distinct from [`Self::FlowEnded`]: this fires per
    /// (parser, flow); the flow may still be alive.
    ParserClosed {
        key: K,
        parser_kind: ParserKind,
        reason: EndReason,
        ts: Timestamp,
    },

    /// Live per-flow anomaly forwarded from the central tracker.
    /// Emitted only when `emit_anomalies(true)` was set.
    FlowAnomaly {
        key: K,
        kind: AnomalyKind,
        ts: Timestamp,
    },

    /// Live tracker-global anomaly.
    TrackerAnomaly { kind: AnomalyKind, ts: Timestamp },
}

impl<K> Event<K> {
    /// Borrow the flow key, if the variant has one.
    pub fn key(&self) -> Option<&K> {
        match self {
            Event::FlowStarted { key, .. }
            | Event::FlowEstablished { key, .. }
            | Event::FlowStateChange { key, .. }
            | Event::FlowPacket { key, .. }
            | Event::FlowEnded { key, .. }
            | Event::FlowTick { key, .. }
            | Event::ParserClosed { key, .. }
            | Event::FlowAnomaly { key, .. } => Some(key),
            Event::TrackerAnomaly { .. } => None,
        }
    }

    /// Per-packet TCP details, when available.
    ///
    /// Returns the `tcp` field for [`Self::FlowPacket`] events;
    /// `None` for every other variant. The field itself is only
    /// populated when the driver was built with
    /// [`DriverBuilder::emit_packet_details`]`(true)`; if you
    /// haven't opted in, this accessor (like the field) always
    /// returns `None`.
    ///
    /// Useful for cross-variant pipelines that want "tcp info if
    /// the event carries any, otherwise None" without an explicit
    /// destructuring `match` arm on `FlowPacket`.
    pub fn tcp(&self) -> Option<&TcpInfo> {
        match self {
            Event::FlowPacket { tcp, .. } => tcp.as_ref(),
            _ => None,
        }
    }

    /// Borrow the timestamp on the event.
    pub fn timestamp(&self) -> Timestamp {
        match self {
            Event::FlowStarted { ts, .. }
            | Event::FlowEstablished { ts, .. }
            | Event::FlowStateChange { ts, .. }
            | Event::FlowPacket { ts, .. }
            | Event::FlowEnded { ts, .. }
            | Event::FlowTick { ts, .. }
            | Event::ParserClosed { ts, .. }
            | Event::FlowAnomaly { ts, .. }
            | Event::TrackerAnomaly { ts, .. } => *ts,
        }
    }

    /// Project this typed event back to a tracker
    /// [`FlowEvent`](crate::FlowEvent), if it has one (issue #97).
    ///
    /// Returns `None` for [`Self::ParserClosed`] — a parser-level
    /// marker with no tracker-event counterpart. The
    /// [`Self::FlowPacket`] `tcp` enrichment is dropped (`FlowEvent`
    /// carries no per-packet TCP details) and [`Self::FlowEnded`]'s
    /// explicit `ts` is folded back into `stats.last_seen`.
    ///
    /// This is the bridge that lets the `emit` writers — which speak
    /// `FlowEvent` — consume a typed `Driver<E>` stream. See
    /// [`crate::emit`] for the `write_event`-over-`Event` path.
    pub fn into_flow_event(self) -> Option<FlowEvent<K>> {
        Some(match self {
            Event::FlowStarted { key, ts, l4 } => FlowEvent::Started {
                key,
                side: FlowSide::Initiator,
                ts,
                l4,
            },
            Event::FlowEstablished { key, ts, l4 } => FlowEvent::Established { key, ts, l4 },
            Event::FlowStateChange { key, from, to, ts } => {
                FlowEvent::StateChange { key, from, to, ts }
            }
            Event::FlowPacket {
                key,
                side,
                len,
                ts,
                tcp: _,
            } => FlowEvent::Packet { key, side, len, ts },
            Event::FlowEnded {
                key,
                reason,
                stats,
                history,
                l4,
                ts: _,
            } => FlowEvent::Ended {
                key,
                reason,
                stats,
                history,
                l4,
            },
            Event::FlowTick { key, stats, ts } => FlowEvent::Tick { key, stats, ts },
            Event::FlowAnomaly { key, kind, ts } => FlowEvent::FlowAnomaly { key, kind, ts },
            Event::TrackerAnomaly { kind, ts } => FlowEvent::TrackerAnomaly { kind, ts },
            Event::ParserClosed { .. } => return None,
        })
    }

    /// Borrowing variant of [`Self::into_flow_event`] — clones the
    /// key/stats. Convenient for emit writers that take
    /// `&FlowEvent<K>` without consuming the event.
    pub fn to_flow_event(&self) -> Option<FlowEvent<K>>
    where
        K: Clone,
    {
        self.clone().into_flow_event()
    }
}

impl<K> From<FlowEvent<K>> for Event<K> {
    /// Lossless conversion from the tracker primitive to the typed
    /// driver event (issue #97).
    ///
    /// Every `FlowEvent` variant has an `Event` counterpart:
    /// `StateChange` maps to [`Event::FlowStateChange`], `Ended`'s
    /// timestamp is taken from `stats.last_seen`, and
    /// [`Event::FlowPacket`]'s `tcp` enrichment defaults to `None`
    /// (it is a driver-only, opt-in field — populate it via the
    /// driver's `emit_packet_details`, not this conversion).
    fn from(ev: FlowEvent<K>) -> Self {
        match ev {
            FlowEvent::Started { key, ts, l4, .. } => Event::FlowStarted { key, ts, l4 },
            FlowEvent::Established { key, ts, l4 } => Event::FlowEstablished { key, ts, l4 },
            FlowEvent::StateChange { key, from, to, ts } => {
                Event::FlowStateChange { key, from, to, ts }
            }
            FlowEvent::Packet { key, side, len, ts } => Event::FlowPacket {
                key,
                side,
                len,
                ts,
                tcp: None,
            },
            FlowEvent::Ended {
                key,
                reason,
                stats,
                history,
                l4,
            } => {
                let ts = stats.last_seen;
                Event::FlowEnded {
                    key,
                    reason,
                    stats,
                    history,
                    l4,
                    ts,
                }
            }
            FlowEvent::Tick { key, stats, ts } => Event::FlowTick { key, stats, ts },
            FlowEvent::FlowAnomaly { key, kind, ts } => Event::FlowAnomaly { key, kind, ts },
            FlowEvent::TrackerAnomaly { kind, ts } => Event::TrackerAnomaly { kind, ts },
        }
    }
}

/// Plan 121 typed driver. Emits flow-lifecycle [`Event<K>`] only;
/// per-parser typed messages flow through [`SlotHandle`].
///
/// `Driver<E>` is `Send + Sync` since 0.13 — every field is
/// structurally Send+Sync (`Arc<SegQueue<_>>` slot queues,
/// owned `FlowDriver`, `Vec<Box<dyn ErasedSlot<_> + Send + Sync>>`
/// slot list). Methods take `&mut self`, so the `Sync` impl is
/// decorative — you can borrow the driver across threads, but
/// only one caller mutates at a time. The headline use case is
/// `tokio::spawn(driver_task)` on the default multi-thread
/// runtime.
pub struct Driver<E>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + Sync + 'static,
{
    central: FlowDriver<E, NoopReassemblerFactory, ()>,
    extractor: E,
    emit_packet_details: bool,
    slots: Vec<Box<dyn ErasedSlot<E::Key> + Send + Sync>>,
}

impl<E> Driver<E>
where
    E: FlowExtractor + Clone + Send + 'static,
    E::Key: Hash + Eq + Clone + Send + Sync + 'static,
{
    /// Begin building.
    pub fn builder(extractor: E) -> DriverBuilder<E> {
        DriverBuilder {
            extractor,
            config: FlowTrackerConfig::default(),
            monotonic_timestamps: false,
            emit_anomalies: false,
            emit_packet_details: false,
            dedup: None,
            idle_timeout_fn: None,
            slots: Vec::new(),
        }
    }

    /// Process one packet. Returns the merged flow-lifecycle
    /// event stream. Typed parser messages don't appear here —
    /// drain them via the [`SlotHandle`]s returned at build
    /// time.
    pub fn track<'v>(&mut self, view: impl Into<PacketView<'v>>) -> Vec<Event<E::Key>> {
        let mut out = Vec::new();
        self.track_into(view, &mut out);
        out
    }

    /// Append-only variant of [`Self::track`]. Reuses `out`'s
    /// capacity — zero allocation at the surface in steady
    /// state.
    pub fn track_into<'v>(
        &mut self,
        view: impl Into<PacketView<'v>>,
        out: &mut Vec<Event<E::Key>>,
    ) {
        let view: PacketView<'v> = view.into();
        let ts = view.timestamp;

        let tcp_for_packet: Option<TcpInfo> = if self.emit_packet_details {
            self.extractor.extract(view).and_then(|e| e.tcp)
        } else {
            None
        };

        let mut tcp_slot = tcp_for_packet;
        for flow_ev in self.central.track(view).into_iter() {
            let this_tcp = if matches!(flow_ev, FlowEvent::Packet { .. }) {
                let t = tcp_slot;
                tcp_slot = None;
                t
            } else {
                None
            };
            if let Some(ev) = map_flow_event(flow_ev, this_tcp) {
                out.push(ev);
            }
        }

        for slot in &mut self.slots {
            slot.track_into(view, ts, out);
        }
    }

    /// Periodic sweep. Drives idle-timeout `FlowEnded` events
    /// + each slot's `on_tick`.
    pub fn sweep(&mut self, now: Timestamp) -> Vec<Event<E::Key>> {
        let mut out = Vec::new();
        self.sweep_into(now, &mut out);
        out
    }

    /// Append-only sweep.
    pub fn sweep_into(&mut self, now: Timestamp, out: &mut Vec<Event<E::Key>>) {
        for flow_ev in self.central.sweep(now) {
            if let Some(ev) = map_flow_event(flow_ev, None) {
                out.push(ev);
            }
        }
        for slot in &mut self.slots {
            slot.sweep_into(now, out);
        }
    }

    /// End-of-input flush.
    pub fn finish(&mut self) -> Vec<Event<E::Key>> {
        let mut out = Vec::new();
        self.finish_into(&mut out);
        out
    }

    /// Append-only finish.
    pub fn finish_into(&mut self, out: &mut Vec<Event<E::Key>>) {
        for flow_ev in self.central.finish() {
            if let Some(ev) = map_flow_event(flow_ev, None) {
                out.push(ev);
            }
        }
        for slot in &mut self.slots {
            slot.finish_into(out);
        }
    }

    /// One-call iterator over a pcap file — drives every packet
    /// through this driver and yields the lifecycle event
    /// stream. Per-parser typed messages still flow through
    /// the registered [`SlotHandle`](super::SlotHandle)s; drain
    /// them yourself between iterator pulls if you need them
    /// in-line.
    ///
    /// This is the multi-parser sibling of the per-protocol
    /// `*_from_pcap` helpers (`flowscope::http::requests_from_pcap`,
    /// `flowscope::dns::messages_from_pcap`, etc.) — those work
    /// when one parser owns the whole walk; this works when you
    /// want HTTP + TLS + DNS slots on the same `Driver` and
    /// process the combined event stream in one pass.
    ///
    /// ```no_run
    /// # #[cfg(all(feature = "pcap", feature = "extractors", feature = "tracker"))]
    /// # fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// use flowscope::driver::Driver;
    /// use flowscope::extract::FiveTuple;
    /// # use flowscope::http::HttpParser;
    /// let mut builder = Driver::builder(FiveTuple::bidirectional());
    /// let _http_slot = builder.session_on_ports(HttpParser::default(), [80]);
    /// let driver = builder.build();
    /// for ev in driver.run_pcap("trace.pcap")? {
    ///     let _ev = ev?;
    /// }
    /// # Ok(()) }
    /// ```
    ///
    /// Issue #64 (0.18).
    #[cfg(feature = "pcap")]
    pub fn run_pcap<P: AsRef<std::path::Path>>(self, path: P) -> crate::Result<RunPcap<E>> {
        let source = crate::pcap::PcapFlowSource::open(path)?;
        Ok(RunPcap {
            driver: self,
            views: source.views(),
            buf: Vec::with_capacity(32),
            cursor: 0,
            finished: false,
        })
    }

    /// Force-end the flow with this key. Mirror of
    /// [`crate::FlowTracker::force_close`] /
    /// [`crate::FlowDriver::force_close`] at the typed-driver
    /// layer.
    ///
    /// Drains any reassembler-buffered bytes through each
    /// registered slot's parser (one last `feed_*` + `fin_*`
    /// per side); typed messages flushed by the parser land in
    /// their slot handle, [`Event::ParserClosed`] events land
    /// in `out`, and a final [`Event::FlowEnded`] with reason
    /// [`crate::EndReason::ForceClosed`] is emitted by the
    /// central tracker.
    ///
    /// No-op if `key` is not currently tracked.
    pub fn force_close(&mut self, key: &E::Key, now: Timestamp) -> Vec<Event<E::Key>> {
        let mut out = Vec::new();
        self.force_close_into(key, now, &mut out);
        out
    }

    /// Append-only variant of [`Self::force_close`]. Reuses
    /// `out`'s capacity.
    pub fn force_close_into(&mut self, key: &E::Key, now: Timestamp, out: &mut Vec<Event<E::Key>>) {
        // Slots first — they may drain reassembled bytes and
        // emit `ParserClosed` ahead of the central tracker's
        // `FlowEnded`.
        for slot in &mut self.slots {
            slot.force_close_into(key, now, out);
        }
        for flow_ev in self.central.force_close(key, now) {
            if let Some(ev) = map_flow_event(flow_ev, None) {
                out.push(ev);
            }
        }
    }

    /// Borrow the underlying tracker for introspection.
    pub fn tracker(&self) -> &FlowTracker<E, ()> {
        self.central.tracker()
    }

    /// Mutable borrow of the underlying tracker.
    pub fn tracker_mut(&mut self) -> &mut FlowTracker<E, ()> {
        self.central.tracker_mut()
    }
}

/// Builder for [`Driver`]. Mutates in place; each
/// session/datagram registration returns a typed [`SlotHandle`].
#[must_use = "a DriverBuilder does nothing until you register parsers and call `.build()`"]
pub struct DriverBuilder<E>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + Sync + 'static,
{
    extractor: E,
    config: FlowTrackerConfig,
    monotonic_timestamps: bool,
    emit_anomalies: bool,
    emit_packet_details: bool,
    dedup: Option<Dedup>,
    idle_timeout_fn: Option<IdleTimeoutFn<E::Key>>,
    slots: Vec<Box<dyn ErasedSlot<E::Key> + Send + Sync>>,
}

impl<E> DriverBuilder<E>
where
    E: FlowExtractor + Clone + Send + 'static,
    E::Key: Hash + Eq + Clone + Send + Sync + 'static,
{
    /// Override the central tracker's config.
    pub fn config(&mut self, c: FlowTrackerConfig) -> &mut Self {
        self.config = c;
        self
    }

    /// Strict-monotonic timestamps. Recommended for offline
    /// pcap replay.
    pub fn monotonic_timestamps(&mut self, on: bool) -> &mut Self {
        self.monotonic_timestamps = on;
        self
    }

    /// Per-packet `tcp: Option<TcpInfo>` enrichment.
    pub fn emit_packet_details(&mut self, on: bool) -> &mut Self {
        self.emit_packet_details = on;
        self
    }

    /// Emit `FlowAnomaly` / `TrackerAnomaly` events inline.
    pub fn emit_anomalies(&mut self, on: bool) -> &mut Self {
        self.emit_anomalies = on;
        self
    }

    /// Content-hash duplicate filtering on the central
    /// flow-lifecycle path.
    pub fn dedup(&mut self, dedup: Dedup) -> &mut Self {
        self.dedup = Some(dedup);
        self
    }

    /// Per-key idle-timeout override.
    pub fn idle_timeout_fn<F>(&mut self, f: F) -> &mut Self
    where
        F: Fn(&E::Key, Option<L4Proto>) -> Option<Duration> + Send + Sync + 'static,
    {
        self.idle_timeout_fn = Some(Box::new(f));
        self
    }

    /// Register a session parser bound to a port set. Returns a
    /// typed drain handle for the parser's output.
    pub fn session_on_ports<P, I>(&mut self, parser: P, ports: I) -> SlotHandle<P::Message, E::Key>
    where
        P: SessionParser + Clone + Send + Sync + 'static,
        P::Message: Send + Sync + 'static,
        I: IntoIterator<Item = u16>,
    {
        let port_set: smallvec::SmallVec<[u16; 4]> = ports.into_iter().collect();
        let (slot, handle) = TypedConcreteSlot::new(
            self.extractor.clone(),
            parser,
            self.config.clone(),
            Some(port_set),
            self.monotonic_timestamps,
        );
        self.slots.push(Box::new(slot));
        handle
    }

    /// Register a session parser bound to a port set, with
    /// **broadcast** (fan-out) consumer semantics. Returns a
    /// [`BroadcastSlotHandle`] — each [`Clone`] of the handle
    /// is a separate subscriber that sees **every** message.
    ///
    /// Plan 150 (0.13). Compare with
    /// [`Self::session_on_ports`] (competitive-consumer MPMC).
    /// Use broadcast when multiple downstream consumers each
    /// need their own copy of every message — typically a
    /// logger + a metrics aggregator + a sink. Each subscriber's
    /// queue grows independently; cap with
    /// [`BroadcastSlotHandle::drain_n`].
    ///
    /// Requires `P::Message: Clone` (each push clones once per
    /// live subscriber).
    pub fn session_on_ports_broadcast_each<P, I>(
        &mut self,
        parser: P,
        ports: I,
    ) -> BroadcastSlotHandle<P::Message, E::Key>
    where
        P: SessionParser + Clone + Send + Sync + 'static,
        P::Message: Send + Sync + Clone + 'static,
        E::Key: Send + Sync + Clone + 'static,
        I: IntoIterator<Item = u16>,
    {
        let port_set: smallvec::SmallVec<[u16; 4]> = ports.into_iter().collect();
        let (slot, handle) = super::typed_slot::TypedBroadcastSlot::new(
            self.extractor.clone(),
            parser,
            self.config.clone(),
            Some(port_set),
            self.monotonic_timestamps,
        );
        self.slots.push(Box::new(slot));
        handle
    }

    /// Register a session parser that observes every flow.
    pub fn session_broadcast<P>(&mut self, parser: P) -> SlotHandle<P::Message, E::Key>
    where
        P: SessionParser + Clone + Send + Sync + 'static,
        P::Message: Send + Sync + 'static,
    {
        let (slot, handle) = TypedConcreteSlot::new(
            self.extractor.clone(),
            parser,
            self.config.clone(),
            None,
            self.monotonic_timestamps,
        );
        self.slots.push(Box::new(slot));
        handle
    }

    /// Register a session parser activated by a signature
    /// probe — runs against every flow's initial bytes; pins
    /// to the parser once the signature matches.
    pub fn session_heuristic<P>(
        &mut self,
        parser: P,
        signature: SignatureFn,
    ) -> SlotHandle<P::Message, E::Key>
    where
        P: SessionParser + Clone + Send + Sync + 'static,
        P::Message: Send + Sync + 'static,
    {
        self.session_heuristic_with_budget(
            parser,
            signature,
            super::typed_slot_heuristic::DEFAULT_PROBE_PACKETS,
        )
    }

    /// Register a session parser with a custom probe-packet
    /// budget.
    pub fn session_heuristic_with_budget<P>(
        &mut self,
        parser: P,
        signature: SignatureFn,
        max_probe_packets: u8,
    ) -> SlotHandle<P::Message, E::Key>
    where
        P: SessionParser + Clone + Send + Sync + 'static,
        P::Message: Send + Sync + 'static,
    {
        let (slot, handle) = TypedHeuristicSessionSlot::new(
            self.extractor.clone(),
            parser,
            self.config.clone(),
            signature,
            max_probe_packets,
            self.monotonic_timestamps,
        );
        self.slots.push(Box::new(slot));
        handle
    }

    /// Register a datagram parser bound to a port set.
    pub fn datagram_on_ports<D, I>(&mut self, parser: D, ports: I) -> SlotHandle<D::Message, E::Key>
    where
        D: DatagramParser + Clone + Send + Sync + 'static,
        D::Message: Send + Sync + 'static,
        I: IntoIterator<Item = u16>,
    {
        let port_set: smallvec::SmallVec<[u16; 4]> = ports.into_iter().collect();
        let (slot, handle) = TypedConcreteDatagramSlot::new(
            self.extractor.clone(),
            parser,
            self.config.clone(),
            Some(port_set),
            self.monotonic_timestamps,
        );
        self.slots.push(Box::new(slot));
        handle
    }

    /// Register a datagram parser that observes every flow.
    pub fn datagram_broadcast<D>(&mut self, parser: D) -> SlotHandle<D::Message, E::Key>
    where
        D: DatagramParser + Clone + Send + Sync + 'static,
        D::Message: Send + Sync + 'static,
    {
        let (slot, handle) = TypedConcreteDatagramSlot::new(
            self.extractor.clone(),
            parser,
            self.config.clone(),
            None,
            self.monotonic_timestamps,
        );
        self.slots.push(Box::new(slot));
        handle
    }

    /// Register a datagram parser activated by a signature
    /// probe.
    pub fn datagram_heuristic<D>(
        &mut self,
        parser: D,
        signature: SignatureFn,
    ) -> SlotHandle<D::Message, E::Key>
    where
        D: DatagramParser + Clone + Send + Sync + 'static,
        D::Message: Send + Sync + 'static,
    {
        self.datagram_heuristic_with_budget(
            parser,
            signature,
            super::typed_slot_heuristic::DEFAULT_PROBE_PACKETS,
        )
    }

    /// Register a datagram parser with a custom probe-packet
    /// budget.
    pub fn datagram_heuristic_with_budget<D>(
        &mut self,
        parser: D,
        signature: SignatureFn,
        max_probe_packets: u8,
    ) -> SlotHandle<D::Message, E::Key>
    where
        D: DatagramParser + Clone + Send + Sync + 'static,
        D::Message: Send + Sync + 'static,
    {
        let (slot, handle) = TypedHeuristicDatagramSlot::new(
            self.extractor.clone(),
            parser,
            self.config.clone(),
            signature,
            max_probe_packets,
            self.monotonic_timestamps,
        );
        self.slots.push(Box::new(slot));
        handle
    }

    /// Materialise the driver.
    pub fn build(self) -> Driver<E> {
        let mut central =
            FlowDriver::with_config(self.extractor.clone(), NoopReassemblerFactory, self.config)
                .with_emit_anomalies(self.emit_anomalies)
                .with_monotonic_timestamps(self.monotonic_timestamps);
        if let Some(d) = self.dedup {
            central = central.with_dedup(d);
        }
        if let Some(f) = self.idle_timeout_fn {
            central
                .tracker_mut()
                .set_idle_timeout_fn(move |k, l4| f(k, l4));
        }
        Driver {
            central,
            extractor: self.extractor,
            emit_packet_details: self.emit_packet_details,
            slots: self.slots,
        }
    }
}

/// Map a tracker-emitted [`FlowEvent`] into the typed
/// [`Event<K>`] shape. Drops `Message` / `StateChange` (the
/// former is now slot-handle-routed; the latter has no
/// shipping equivalent — `FlowEstablished` covers it).
fn map_flow_event<K>(ev: FlowEvent<K>, tcp: Option<TcpInfo>) -> Option<Event<K>> {
    // The typed driver historically omits raw TCP state churn —
    // `FlowEstablished` covers the common case — so drop `StateChange`
    // here even though `Event` can now represent it (issue #97). The
    // rest reuse the lossless `From` conversion, then patch in the
    // opt-in per-packet `tcp` details the conversion can't know about.
    if matches!(ev, FlowEvent::StateChange { .. }) {
        return None;
    }
    let mut event = Event::from(ev);
    if let Event::FlowPacket { tcp: slot, .. } = &mut event {
        *slot = tcp;
    }
    Some(event)
}

#[cfg(feature = "pcap")]
#[must_use = "RunPcap is a lazy iterator — it replays no packets until consumed (e.g. in a `for` loop)"]
pub struct RunPcap<E>
where
    E: FlowExtractor + Clone + Send + 'static,
    E::Key: Hash + Eq + Clone + Send + Sync + 'static,
{
    driver: Driver<E>,
    views: crate::pcap::ViewIter<std::io::BufReader<std::fs::File>>,
    buf: Vec<Event<E::Key>>,
    cursor: usize,
    finished: bool,
}

#[cfg(feature = "pcap")]
impl<E> Iterator for RunPcap<E>
where
    E: FlowExtractor + Clone + Send + 'static,
    E::Key: Hash + Eq + Clone + Send + Sync + 'static,
{
    type Item = crate::Result<Event<E::Key>>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            // Drain any buffered events first.
            if self.cursor < self.buf.len() {
                let ev = self.buf[self.cursor].clone();
                self.cursor += 1;
                return Some(Ok(ev));
            }
            self.buf.clear();
            self.cursor = 0;
            // Pull the next packet.
            match self.views.next() {
                Some(Ok(view)) => {
                    self.driver.track_into(&view, &mut self.buf);
                }
                Some(Err(e)) => return Some(Err(e)),
                None => {
                    if self.finished {
                        return None;
                    }
                    self.finished = true;
                    self.driver.finish_into(&mut self.buf);
                }
            }
        }
    }
}

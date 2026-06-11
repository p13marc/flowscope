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

use std::hash::Hash;
use std::sync::Arc;
use std::time::Duration;

use crossbeam_queue::SegQueue;

use crate::PacketView;
use crate::Timestamp;
use crate::dedup::Dedup;
use crate::detect::signatures::SignatureFn;
use crate::event::{AnomalyKind, EndReason, FlowEvent, FlowSide, FlowStats};
use crate::extractor::{FlowExtractor, L4Proto, TcpInfo};
use crate::flow_driver::FlowDriver;
use crate::history::HistoryString;
use crate::reassembler::NoopReassemblerFactory;
use crate::session::{DatagramParser, SessionParser};
use crate::tracker::{FlowTracker, FlowTrackerConfig};

use super::BroadcastSlotHandle;
use super::slot::{SlotHandle, SlotMessage};
use super::typed_slot::{ErasedSlot, TypedConcreteDatagramSlot, TypedConcreteSlot};
use super::typed_slot_heuristic::{TypedHeuristicDatagramSlot, TypedHeuristicSessionSlot};

/// Per-key idle-timeout predicate, boxed.
type IdleTimeoutFn<K> =
    Box<dyn Fn(&K, Option<L4Proto>) -> Option<Duration> + Send + Sync + 'static>;

/// Flow-lifecycle event type for the typed driver.
///
/// Plan 121: no `M` parameter, no `Message` variant — per-parser
/// typed messages flow through [`SlotHandle`] returned by the
/// builder. `ParserClosed` stays as a lifecycle marker for when
/// a parser self-terminates.
#[derive(Debug, Clone)]
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
        parser_kind: &'static str,
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
            | Event::FlowPacket { ts, .. }
            | Event::FlowEnded { ts, .. }
            | Event::FlowTick { ts, .. }
            | Event::ParserClosed { ts, .. }
            | Event::FlowAnomaly { ts, .. }
            | Event::TrackerAnomaly { ts, .. } => *ts,
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

    /// Begin building **without** committing to an extractor
    /// instance up front. Useful when slot registration ordering
    /// precedes extractor selection — consumer-built monitor
    /// chains (e.g. netring's `MonitorBuilder`) want to register
    /// every protocol parser before the user picks the capture
    /// source.
    ///
    /// Caller must finalise via
    /// [`DeferredDriverBuilder::build_with`]; there is no
    /// `build()` method, so the compile-time guarantee that an
    /// extractor is set is preserved by the type system.
    ///
    /// `Driver::deferred().session_on_ports(p, ports).build_with(ext)`
    /// produces a driver behaviourally identical to
    /// `Driver::builder(ext).session_on_ports(p, ports).build()`
    /// for the same `(p, ports, ext)`.
    ///
    /// ```ignore
    /// use flowscope::driver::{Driver, SlotMessage};
    /// use flowscope::extract::{FiveTuple, FiveTupleKey};
    /// use flowscope::http::{HttpMessage, HttpParser};
    ///
    /// let mut builder = Driver::<FiveTuple>::deferred();
    /// let mut http: SlotHandle<HttpMessage, FiveTupleKey> =
    ///     builder.session_on_ports(HttpParser::default(), [80, 8080]);
    /// builder.emit_anomalies(true);
    ///
    /// // …later, after CLI parsing / config resolution:
    /// let driver = builder.build_with(FiveTuple::bidirectional());
    /// ```
    pub fn deferred() -> DeferredDriverBuilder<E> {
        DeferredDriverBuilder {
            config: FlowTrackerConfig::default(),
            monotonic_timestamps: false,
            emit_anomalies: false,
            emit_packet_details: false,
            dedup: None,
            idle_timeout_fn: None,
            pending: Vec::new(),
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

// ───────────────────────────────────────────────────────────────
// Plan 124 — DeferredDriverBuilder<E>
//
// Mirrors `DriverBuilder<E>` minus the extractor instance, with
// `build_with(ext)` as the finalizer. No `build()` method — the
// type system rules out finalising without an extractor.
//
// At each slot-registration call we pre-allocate the
// `Arc<SegQueue>` so the `SlotHandle` can be returned
// immediately, and we capture a closure that — given the
// extractor — materialises the matching concrete slot bound to
// the *same* queue.
// ───────────────────────────────────────────────────────────────

/// Closure type alias for one deferred slot's materialiser.
/// Lazy-built at `build_with` time; takes the extractor + the
/// shared config and produces the boxed type-erased slot.
type DeferredMaterialiser<E> = Box<
    dyn FnOnce(
            &E,
            &FlowTrackerConfig,
            bool,
        ) -> Box<dyn ErasedSlot<<E as FlowExtractor>::Key> + Send + Sync>
        + Send
        + Sync,
>;

/// Builder for [`Driver`] without an extractor instance up
/// front. Construct with [`Driver::deferred`]; finalise with
/// [`Self::build_with`].
pub struct DeferredDriverBuilder<E>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + Sync + 'static,
{
    config: FlowTrackerConfig,
    monotonic_timestamps: bool,
    emit_anomalies: bool,
    emit_packet_details: bool,
    dedup: Option<Dedup>,
    idle_timeout_fn: Option<IdleTimeoutFn<E::Key>>,
    pending: Vec<DeferredMaterialiser<E>>,
}

impl<E> DeferredDriverBuilder<E>
where
    E: FlowExtractor + Clone + Send + 'static,
    E::Key: Hash + Eq + Clone + Send + Sync + 'static,
{
    /// Override the central tracker's config.
    pub fn config(&mut self, c: FlowTrackerConfig) -> &mut Self {
        self.config = c;
        self
    }

    /// Strict-monotonic timestamps. Recommended for offline pcap
    /// replay.
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

    /// Register a session parser bound to a port set.
    pub fn session_on_ports<P, I>(&mut self, parser: P, ports: I) -> SlotHandle<P::Message, E::Key>
    where
        P: SessionParser + Clone + Send + Sync + 'static,
        P::Message: Send + Sync + 'static,
        I: IntoIterator<Item = u16>,
    {
        let port_set: smallvec::SmallVec<[u16; 4]> = ports.into_iter().collect();
        let (handle, mat) = make_session_materialiser(parser, Some(port_set));
        self.pending.push(mat);
        handle
    }

    /// Register a session parser that observes every flow.
    pub fn session_broadcast<P>(&mut self, parser: P) -> SlotHandle<P::Message, E::Key>
    where
        P: SessionParser + Clone + Send + Sync + 'static,
        P::Message: Send + Sync + 'static,
    {
        let (handle, mat) = make_session_materialiser::<E, P>(parser, None);
        self.pending.push(mat);
        handle
    }

    /// Register a session parser activated by a signature probe.
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

    /// Register a session parser with a custom probe budget.
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
        let (handle, mat) =
            make_session_heuristic_materialiser::<E, P>(parser, signature, max_probe_packets);
        self.pending.push(mat);
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
        let (handle, mat) = make_datagram_materialiser::<E, D>(parser, Some(port_set));
        self.pending.push(mat);
        handle
    }

    /// Register a datagram parser that observes every flow.
    pub fn datagram_broadcast<D>(&mut self, parser: D) -> SlotHandle<D::Message, E::Key>
    where
        D: DatagramParser + Clone + Send + Sync + 'static,
        D::Message: Send + Sync + 'static,
    {
        let (handle, mat) = make_datagram_materialiser::<E, D>(parser, None);
        self.pending.push(mat);
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

    /// Register a datagram parser with a custom probe budget.
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
        let (handle, mat) =
            make_datagram_heuristic_materialiser::<E, D>(parser, signature, max_probe_packets);
        self.pending.push(mat);
        handle
    }

    /// Materialise the driver with the supplied extractor
    /// instance.
    pub fn build_with(self, extractor: E) -> Driver<E> {
        let mut central = FlowDriver::with_config(
            extractor.clone(),
            NoopReassemblerFactory,
            self.config.clone(),
        )
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
        let mut slots: Vec<Box<dyn ErasedSlot<E::Key> + Send + Sync>> =
            Vec::with_capacity(self.pending.len());
        for materialiser in self.pending {
            slots.push(materialiser(
                &extractor,
                &self.config,
                self.monotonic_timestamps,
            ));
        }
        Driver {
            central,
            extractor,
            emit_packet_details: self.emit_packet_details,
            slots,
        }
    }
}

// ── Materialiser helpers ─────────────────────────────────────

fn make_session_materialiser<E, P>(
    parser: P,
    ports: Option<smallvec::SmallVec<[u16; 4]>>,
) -> (SlotHandle<P::Message, E::Key>, DeferredMaterialiser<E>)
where
    E: FlowExtractor + Clone + Send + 'static,
    E::Key: Hash + Eq + Clone + Send + Sync + 'static,
    P: SessionParser + Clone + Send + Sync + 'static,
    P::Message: Send + Sync + 'static,
{
    let parser_kind = parser.parser_kind();
    let msg_buf: Arc<SegQueue<SlotMessage<P::Message, E::Key>>> = Arc::new(SegQueue::new());
    let handle = SlotHandle {
        inner: Arc::clone(&msg_buf),
        parser_kind,
    };
    let materialiser: DeferredMaterialiser<E> = Box::new(move |ext, cfg, mono| {
        let slot =
            TypedConcreteSlot::with_queue(ext.clone(), parser, cfg.clone(), ports, mono, msg_buf);
        Box::new(slot) as Box<dyn ErasedSlot<E::Key> + Send + Sync>
    });
    (handle, materialiser)
}

fn make_session_heuristic_materialiser<E, P>(
    parser: P,
    signature: SignatureFn,
    max_probe_packets: u8,
) -> (SlotHandle<P::Message, E::Key>, DeferredMaterialiser<E>)
where
    E: FlowExtractor + Clone + Send + 'static,
    E::Key: Hash + Eq + Clone + Send + Sync + 'static,
    P: SessionParser + Clone + Send + Sync + 'static,
    P::Message: Send + Sync + 'static,
{
    let parser_kind = parser.parser_kind();
    let msg_buf: Arc<SegQueue<SlotMessage<P::Message, E::Key>>> = Arc::new(SegQueue::new());
    let handle = SlotHandle {
        inner: Arc::clone(&msg_buf),
        parser_kind,
    };
    let materialiser: DeferredMaterialiser<E> = Box::new(move |ext, cfg, mono| {
        let slot = TypedHeuristicSessionSlot::with_queue(
            ext.clone(),
            parser,
            cfg.clone(),
            signature,
            max_probe_packets,
            mono,
            msg_buf,
        );
        Box::new(slot) as Box<dyn ErasedSlot<E::Key> + Send + Sync>
    });
    (handle, materialiser)
}

fn make_datagram_materialiser<E, D>(
    parser: D,
    ports: Option<smallvec::SmallVec<[u16; 4]>>,
) -> (SlotHandle<D::Message, E::Key>, DeferredMaterialiser<E>)
where
    E: FlowExtractor + Clone + Send + 'static,
    E::Key: Hash + Eq + Clone + Send + Sync + 'static,
    D: DatagramParser + Clone + Send + Sync + 'static,
    D::Message: Send + Sync + 'static,
{
    let parser_kind = parser.parser_kind();
    let msg_buf: Arc<SegQueue<SlotMessage<D::Message, E::Key>>> = Arc::new(SegQueue::new());
    let handle = SlotHandle {
        inner: Arc::clone(&msg_buf),
        parser_kind,
    };
    let materialiser: DeferredMaterialiser<E> = Box::new(move |ext, cfg, mono| {
        let slot = TypedConcreteDatagramSlot::with_queue(
            ext.clone(),
            parser,
            cfg.clone(),
            ports,
            mono,
            msg_buf,
        );
        Box::new(slot) as Box<dyn ErasedSlot<E::Key> + Send + Sync>
    });
    (handle, materialiser)
}

fn make_datagram_heuristic_materialiser<E, D>(
    parser: D,
    signature: SignatureFn,
    max_probe_packets: u8,
) -> (SlotHandle<D::Message, E::Key>, DeferredMaterialiser<E>)
where
    E: FlowExtractor + Clone + Send + 'static,
    E::Key: Hash + Eq + Clone + Send + Sync + 'static,
    D: DatagramParser + Clone + Send + Sync + 'static,
    D::Message: Send + Sync + 'static,
{
    let parser_kind = parser.parser_kind();
    let msg_buf: Arc<SegQueue<SlotMessage<D::Message, E::Key>>> = Arc::new(SegQueue::new());
    let handle = SlotHandle {
        inner: Arc::clone(&msg_buf),
        parser_kind,
    };
    let materialiser: DeferredMaterialiser<E> = Box::new(move |ext, cfg, mono| {
        let slot = TypedHeuristicDatagramSlot::with_queue(
            ext.clone(),
            parser,
            cfg.clone(),
            signature,
            max_probe_packets,
            mono,
            msg_buf,
        );
        Box::new(slot) as Box<dyn ErasedSlot<E::Key> + Send + Sync>
    });
    (handle, materialiser)
}

/// Map a tracker-emitted [`FlowEvent`] into the typed
/// [`Event<K>`] shape. Drops `Message` / `StateChange` (the
/// former is now slot-handle-routed; the latter has no
/// shipping equivalent — `FlowEstablished` covers it).
fn map_flow_event<K>(ev: FlowEvent<K>, tcp: Option<TcpInfo>) -> Option<Event<K>> {
    match ev {
        FlowEvent::Started { key, ts, l4, .. } => Some(Event::FlowStarted { key, ts, l4 }),
        FlowEvent::Established { key, ts, l4 } => Some(Event::FlowEstablished { key, ts, l4 }),
        FlowEvent::Packet { key, side, len, ts } => Some(Event::FlowPacket {
            key,
            side,
            len,
            ts,
            tcp,
        }),
        FlowEvent::Ended {
            key,
            reason,
            stats,
            history,
            l4,
        } => {
            let ts = stats.last_seen;
            Some(Event::FlowEnded {
                key,
                reason,
                stats,
                history,
                l4,
                ts,
            })
        }
        FlowEvent::Tick { key, stats, ts } => Some(Event::FlowTick { key, stats, ts }),
        FlowEvent::FlowAnomaly { key, kind, ts } => Some(Event::FlowAnomaly { key, kind, ts }),
        FlowEvent::TrackerAnomaly { kind, ts } => Some(Event::TrackerAnomaly { kind, ts }),
        FlowEvent::StateChange { .. } => None,
    }
}

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
//! use flowscope::driver_unified::typed::{Driver, Event};
//! use flowscope::driver_unified::SlotMessage;
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
use std::time::Duration;

use crate::PacketView;
use crate::Timestamp;
use crate::dedup::Dedup;
use crate::detect::signatures::SignatureFn;
use crate::driver::FlowDriver;
use crate::event::{AnomalyKind, EndReason, FlowEvent, FlowSide, FlowStats};
use crate::extractor::{FlowExtractor, L4Proto, TcpInfo};
use crate::history::HistoryString;
use crate::reassembler::NoopReassemblerFactory;
use crate::session::{DatagramParser, SessionParser};
use crate::tracker::{FlowTracker, FlowTrackerConfig};

use super::slot::SlotHandle;
use super::typed_slot::{ErasedSlot, TypedConcreteDatagramSlot, TypedConcreteSlot};
use super::typed_slot_heuristic::{TypedHeuristicDatagramSlot, TypedHeuristicSessionSlot};

/// Per-key idle-timeout predicate, boxed.
type IdleTimeoutFn<K> = Box<dyn Fn(&K, Option<L4Proto>) -> Option<Duration> + Send + 'static>;

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
    /// The `tcp` field is populated only when
    /// [`DriverBuilder::emit_packet_details`] was called with
    /// `true`.
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
pub struct Driver<E>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + 'static,
{
    central: FlowDriver<E, NoopReassemblerFactory, ()>,
    extractor: E,
    emit_packet_details: bool,
    slots: Vec<Box<dyn ErasedSlot<E::Key>>>,
}

impl<E> Driver<E>
where
    E: FlowExtractor + Clone + Send + 'static,
    E::Key: Hash + Eq + Clone + Send + 'static,
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
    E::Key: Hash + Eq + Clone + Send + 'static,
{
    extractor: E,
    config: FlowTrackerConfig,
    monotonic_timestamps: bool,
    emit_anomalies: bool,
    emit_packet_details: bool,
    dedup: Option<Dedup>,
    idle_timeout_fn: Option<IdleTimeoutFn<E::Key>>,
    slots: Vec<Box<dyn ErasedSlot<E::Key>>>,
}

impl<E> DriverBuilder<E>
where
    E: FlowExtractor + Clone + Send + 'static,
    E::Key: Hash + Eq + Clone + Send + 'static,
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
        F: Fn(&E::Key, Option<L4Proto>) -> Option<Duration> + Send + 'static,
    {
        self.idle_timeout_fn = Some(Box::new(f));
        self
    }

    /// Register a session parser bound to a port set. Returns a
    /// typed drain handle for the parser's output.
    pub fn session_on_ports<P, I>(&mut self, parser: P, ports: I) -> SlotHandle<P::Message, E::Key>
    where
        P: SessionParser + Clone + Send + 'static,
        P::Message: 'static,
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

    /// Register a session parser that observes every flow.
    pub fn session_broadcast<P>(&mut self, parser: P) -> SlotHandle<P::Message, E::Key>
    where
        P: SessionParser + Clone + Send + 'static,
        P::Message: 'static,
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
        P: SessionParser + Clone + Send + 'static,
        P::Message: 'static,
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
        P: SessionParser + Clone + Send + 'static,
        P::Message: 'static,
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
        D: DatagramParser + Clone + Send + 'static,
        D::Message: 'static,
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
        D: DatagramParser + Clone + Send + 'static,
        D::Message: 'static,
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
        D: DatagramParser + Clone + Send + 'static,
        D::Message: 'static,
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
        D: DatagramParser + Clone + Send + 'static,
        D::Message: 'static,
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

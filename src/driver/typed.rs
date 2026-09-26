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

use std::{hash::Hash, sync::Arc, time::Duration};

use crossbeam_queue::SegQueue;

use super::{
    BroadcastSlotHandle,
    broadcast::BroadcastInner,
    slot::SlotHandle,
    typed_slot::{DatagramSlot, ErasedSlot, Order, SessionSlot},
};
use crate::{
    PacketView, Timestamp,
    dedup::Dedup,
    detect::signatures::SignatureFn,
    event::{AnomalyKind, EndReason, FlowEvent, FlowSide, FlowState, FlowStats},
    extractor::{FlowExtractor, L4Proto, Orientation, TcpInfo},
    flow_driver::FlowDriver,
    history::HistoryString,
    parser_kind::{ParserKind, SlotId},
    reassembler::StreamChunks,
    segment_reassembler::SegmentBufferReassemblerFactory,
    session::{
        DatagramParser, SessionParser, TemplateFactory,
        core::{Ctx, DEFAULT_PROBE_PACKETS, DatagramCore, Ports, Selector, SessionCore, Stream},
        engine::{Dispatch, Engine},
    },
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
/// [`Self::StateChange`].
///
/// Since 0.20 (#110) the variants share `FlowEvent`'s names (no
/// redundant `Flow` prefix), so the two enums also serialize to the
/// same `type` tags (`"started"`, `"established"`, `"ended"`, …).
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
    ///
    /// `orientation` is the flow's deterministic canonical direction
    /// ([`Orientation`], issue #118) — equal to the initiator's
    /// orientation and to [`FlowStats::initiator_orientation`].
    Started {
        key: K,
        /// Canonical (address-sorted) orientation of the flow's
        /// first packet. Deterministic regardless of arrival order.
        orientation: Orientation,
        ts: Timestamp,
        l4: Option<L4Proto>,
    },

    /// TCP flow reached the `Established` state (3-way handshake
    /// complete). Not emitted for UDP / ICMP flows.
    Established {
        key: K,
        ts: Timestamp,
        l4: Option<L4Proto>,
    },

    /// TCP state-machine transition other than reaching
    /// `Established` (e.g. `Established → FinWait`). The lossless
    /// counterpart of [`FlowEvent::StateChange`] (issue #97).
    ///
    /// The typed `Driver<E>` does **not** emit this today —
    /// `Established` covers the common case and the driver
    /// historically omits raw state churn — but the variant exists
    /// so `Event::from(FlowEvent::StateChange { .. })` is lossless
    /// and so future driver modes can surface it.
    StateChange {
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
    /// The variant is `#[non_exhaustive]` (0.21, issue #121) —
    /// future per-packet enrichments are additive. Construct
    /// synthetic packets via
    /// `flowscope::test_helpers::events::driver::packet*`; match
    /// with a trailing `..`.
    #[non_exhaustive]
    Packet {
        key: K,
        side: FlowSide,
        /// Canonical (address-sorted) orientation of this packet
        /// ([`Orientation`], issue #118). Together with the flow's
        /// [`FlowStats::initiator_orientation`] it recovers `side`
        /// deterministically.
        orientation: Orientation,
        len: usize,
        ts: Timestamp,
        tcp: Option<TcpInfo>,
        /// Physical capture leg this packet arrived on (issue #121).
        /// Opt-in via [`DriverBuilder::emit_packet_source_idx`] —
        /// always `None` otherwise; `None` also for the `0`
        /// "unused" sentinel. See
        /// [`crate::FlowEvent::Packet`]'s field docs for the
        /// audit-tier vs per-direction-binding distinction.
        source_idx: Option<u32>,
    },

    /// Flow ended (FIN / RST / idle / eviction / parser close).
    Ended {
        key: K,
        reason: EndReason,
        stats: FlowStats,
        history: HistoryString,
        l4: Option<L4Proto>,
        ts: Timestamp,
    },

    /// Periodic [`FlowStats`] snapshot — emitted when
    /// [`crate::FlowTrackerConfig::flow_tick_interval`] is set.
    Tick {
        key: K,
        stats: FlowStats,
        ts: Timestamp,
    },

    /// A registered parser was closed for this flow — once per
    /// (parser, flow), never re-opened for the same flow.
    ///
    /// - Early close, flow still alive: `reason` is
    ///   [`EndReason::ParseError`] (poisoned), [`EndReason::ParserDone`],
    ///   [`EndReason::StreamGap`] or [`EndReason::BufferOverflow`],
    ///   and `detail` says why.
    /// - At the flow's end: `reason` is the flow's end reason, and the
    ///   event comes right before that flow's [`Self::Ended`].
    ///
    /// `#[non_exhaustive]` — match with a trailing `..`.
    #[non_exhaustive]
    ParserClosed {
        key: K,
        /// Which registered parser (two slots can share a
        /// `parser_kind`). New in 0.25.0.
        slot: SlotId,
        parser_kind: ParserKind,
        reason: EndReason,
        /// The parser's `poison_reason()` (≤ 256 bytes), the gap
        /// size, or the reassembly stop reason. New in 0.25.0.
        detail: Option<String>,
        ts: Timestamp,
    },

    /// A registered parser stopped reading one side of the flow: a
    /// gap it cannot bridge ([`EndReason::StreamGap`], see
    /// [`crate::GapResponse::StopSide`]) or a reassembly limit on that
    /// side ([`EndReason::BufferOverflow`]). The other side keeps
    /// being parsed; when both are stopped a [`Self::ParserClosed`]
    /// follows. New in 0.25.0.
    ///
    /// `#[non_exhaustive]` — match with a trailing `..`.
    #[non_exhaustive]
    ParserSideStopped {
        key: K,
        /// Which registered parser.
        slot: SlotId,
        parser_kind: ParserKind,
        side: FlowSide,
        reason: EndReason,
        /// The gap size or the reassembly stop reason.
        detail: Option<String>,
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
            Event::Started { key, .. }
            | Event::Established { key, .. }
            | Event::StateChange { key, .. }
            | Event::Packet { key, .. }
            | Event::Ended { key, .. }
            | Event::Tick { key, .. }
            | Event::ParserClosed { key, .. }
            | Event::ParserSideStopped { key, .. }
            | Event::FlowAnomaly { key, .. } => Some(key),
            Event::TrackerAnomaly { .. } => None,
        }
    }

    /// Per-packet TCP details, when available.
    ///
    /// Returns the `tcp` field for [`Self::Packet`] events;
    /// `None` for every other variant. The field itself is only
    /// populated when the driver was built with
    /// [`DriverBuilder::emit_packet_details`]`(true)`; if you
    /// haven't opted in, this accessor (like the field) always
    /// returns `None`.
    ///
    /// Useful for cross-variant pipelines that want "tcp info if
    /// the event carries any, otherwise None" without an explicit
    /// destructuring `match` arm on `Packet`.
    pub fn tcp(&self) -> Option<&TcpInfo> {
        match self {
            Event::Packet { tcp, .. } => tcp.as_ref(),
            _ => None,
        }
    }

    /// Borrow the timestamp on the event.
    pub fn timestamp(&self) -> Timestamp {
        match self {
            Event::Started { ts, .. }
            | Event::Established { ts, .. }
            | Event::StateChange { ts, .. }
            | Event::Packet { ts, .. }
            | Event::Ended { ts, .. }
            | Event::Tick { ts, .. }
            | Event::ParserClosed { ts, .. }
            | Event::ParserSideStopped { ts, .. }
            | Event::FlowAnomaly { ts, .. }
            | Event::TrackerAnomaly { ts, .. } => *ts,
        }
    }

    /// Project this typed event back to a tracker
    /// [`FlowEvent`](crate::FlowEvent), if it has one (issue #97).
    ///
    /// Returns `None` for [`Self::ParserClosed`] /
    /// [`Self::ParserSideStopped`] — parser-level markers with no
    /// tracker-event counterpart. The
    /// [`Self::Packet`] `tcp` enrichment is dropped (`FlowEvent`
    /// carries no per-packet TCP details) and [`Self::Ended`]'s
    /// explicit `ts` is folded back into `stats.last_seen`.
    ///
    /// This is the bridge that lets the `emit` writers — which speak
    /// `FlowEvent` — consume a typed `Driver<E>` stream. See
    /// [`crate::emit`] for the `write_event`-over-`Event` path.
    pub fn into_flow_event(self) -> Option<FlowEvent<K>> {
        Some(match self {
            Event::Started {
                key,
                orientation,
                ts,
                l4,
            } => FlowEvent::Started {
                key,
                side: FlowSide::Initiator,
                orientation,
                ts,
                l4,
            },
            Event::Established { key, ts, l4 } => FlowEvent::Established { key, ts, l4 },
            Event::StateChange { key, from, to, ts } => {
                FlowEvent::StateChange { key, from, to, ts }
            }
            Event::Packet {
                key,
                side,
                orientation,
                len,
                ts,
                tcp: _,
                source_idx,
            } => FlowEvent::Packet {
                key,
                side,
                orientation,
                len,
                ts,
                source_idx,
            },
            Event::Ended {
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
            Event::Tick { key, stats, ts } => FlowEvent::Tick { key, stats, ts },
            Event::FlowAnomaly { key, kind, ts } => FlowEvent::FlowAnomaly { key, kind, ts },
            Event::TrackerAnomaly { kind, ts } => FlowEvent::TrackerAnomaly { kind, ts },
            Event::ParserClosed { .. } | Event::ParserSideStopped { .. } => return None,
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
    /// `StateChange` maps to [`Event::StateChange`], `Ended`'s
    /// timestamp is taken from `stats.last_seen`, and
    /// [`Event::Packet`]'s `tcp` enrichment defaults to `None`
    /// (it is a driver-only, opt-in field — populate it via the
    /// driver's `emit_packet_details`, not this conversion).
    fn from(ev: FlowEvent<K>) -> Self {
        match ev {
            FlowEvent::Started {
                key,
                orientation,
                ts,
                l4,
                ..
            } => Event::Started {
                key,
                orientation,
                ts,
                l4,
            },
            FlowEvent::Established { key, ts, l4 } => Event::Established { key, ts, l4 },
            FlowEvent::StateChange { key, from, to, ts } => {
                Event::StateChange { key, from, to, ts }
            }
            FlowEvent::Packet {
                key,
                side,
                orientation,
                len,
                ts,
                source_idx,
            } => Event::Packet {
                key,
                side,
                orientation,
                len,
                ts,
                tcp: None,
                source_idx,
            },
            FlowEvent::Ended {
                key,
                reason,
                stats,
                history,
                l4,
            } => {
                let ts = stats.last_seen;
                Event::Ended {
                    key,
                    reason,
                    stats,
                    history,
                    l4,
                    ts,
                }
            }
            FlowEvent::Tick { key, stats, ts } => Event::Tick { key, stats, ts },
            FlowEvent::FlowAnomaly { key, kind, ts } => Event::FlowAnomaly { key, kind, ts },
            FlowEvent::TrackerAnomaly { kind, ts } => Event::TrackerAnomaly { kind, ts },
        }
    }
}

/// The slot list, as the engine's [`Dispatch`].
struct Slots<K> {
    list: Vec<Box<dyn ErasedSlot<K> + Send + Sync>>,
    needs_ports: bool,
    emit_packet_details: bool,
    order: Order,
}

impl<K> Dispatch<K> for Slots<K>
where
    K: Hash + Eq + Clone,
{
    type Out = Vec<Event<K>>;

    fn needs_ports(&self) -> bool {
        self.needs_ports
    }
    fn wants_stream(&self, ports: Ports) -> bool {
        self.list.iter().any(|s| s.wants_stream(ports))
    }
    fn wants_datagram(&self, ports: Ports, l4: Option<crate::L4Proto>) -> bool {
        self.list.iter().any(|s| s.wants_datagram(ports, l4))
    }
    fn on_stream(
        &mut self,
        cx: &Ctx<'_, K>,
        ports: Ports,
        chunks: &Stream<'_>,
        out: &mut Self::Out,
    ) {
        for slot in &mut self.list {
            slot.on_stream(cx, ports, chunks, out, &mut self.order);
        }
    }
    fn streams_done(&self, key: &K, ports: Ports) -> [bool; 2] {
        let mut done = [true, true];
        for slot in &self.list {
            let d = slot.streams_done(key, ports);
            done[0] &= d[0];
            done[1] &= d[1];
            if done == [false, false] {
                break;
            }
        }
        done
    }
    fn on_datagram(&mut self, cx: &Ctx<'_, K>, ports: Ports, payload: &[u8], out: &mut Self::Out) {
        for slot in &mut self.list {
            slot.on_datagram(cx, ports, payload, out, &mut self.order);
        }
    }
    fn on_flow_end(
        &mut self,
        key: &K,
        reason: EndReason,
        stats: &FlowStats,
        finals: [&StreamChunks; 2],
        ports: Ports,
        anomalies: bool,
        out: &mut Self::Out,
    ) {
        for slot in &mut self.list {
            slot.on_flow_end(
                key,
                reason,
                stats,
                finals,
                ports,
                anomalies,
                out,
                &mut self.order,
            );
        }
    }
    fn on_tick(
        &mut self,
        now: Timestamp,
        stamp: Timestamp,
        orientation_of: &dyn Fn(&K) -> Orientation,
        anomalies: bool,
        out: &mut Self::Out,
    ) {
        for slot in &mut self.list {
            slot.on_tick(now, stamp, orientation_of, anomalies, out, &mut self.order);
        }
    }
    fn retain(&mut self, alive: &dyn Fn(&K) -> bool) {
        for slot in &mut self.list {
            slot.retain(alive);
        }
    }
    fn lifecycle(&mut self, ev: FlowEvent<K>, tcp: Option<TcpInfo>, out: &mut Self::Out) {
        let tcp = if self.emit_packet_details { tcp } else { None };
        if let Some(ev) = map_flow_event(ev, tcp) {
            out.push(ev);
        }
    }
}

/// The multi-parser driver: one flow table, one reassembler per flow
/// side, and any number of parser slots fed from them. Emits
/// flow-lifecycle [`Event<K>`]s; each parser's typed messages flow
/// through the [`SlotHandle`] returned at registration.
///
/// Every slot sees exactly the flows the lifecycle reports: the
/// builder's [`config`](DriverBuilder::config),
/// [`idle_timeout_fn`](DriverBuilder::idle_timeout_fn),
/// [`dedup`](DriverBuilder::dedup) and
/// [`monotonic_timestamps`](DriverBuilder::monotonic_timestamps)
/// apply to parsing as much as to lifecycle, in whatever order they
/// were set.
///
/// `Driver<E>` is `Send + Sync`: move it into a
/// `tokio::spawn(driver_task)` and drain the handles anywhere.
pub struct Driver<E>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + Sync + 'static,
{
    engine: Engine<E>,
    slots: Slots<E::Key>,
    /// Lifecycle events emitted so far (see
    /// [`SlotMessage::lifecycle_pos`](super::SlotMessage::lifecycle_pos)).
    lifecycle_seq: u64,
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

    /// Process one packet. Returns the flow-lifecycle event stream;
    /// typed parser messages go to the [`SlotHandle`]s.
    pub fn track<'v>(&mut self, view: impl Into<PacketView<'v>>) -> Vec<Event<E::Key>> {
        let mut out = Vec::new();
        self.track_into(view, &mut out);
        out
    }

    /// Append-only variant of [`Self::track`]. Reuses `out`'s
    /// capacity.
    ///
    /// Order within one call: lifecycle events in tracker order; a
    /// flow's [`Event::ParserClosed`] events come before its
    /// [`Event::Ended`].
    pub fn track_into<'v>(
        &mut self,
        view: impl Into<PacketView<'v>>,
        out: &mut Vec<Event<E::Key>>,
    ) {
        let start = self.begin(out);
        self.engine.track(view, &mut self.slots, out);
        self.end(out, start);
    }

    /// Lifecycle events emitted so far, across every call. Merge the
    /// slot queues into the lifecycle stream in engine order by
    /// delivering a [`SlotMessage`](super::SlotMessage) right before
    /// lifecycle event number
    /// [`lifecycle_pos`](super::SlotMessage::lifecycle_pos) (ties by
    /// [`seq`](super::SlotMessage::seq)).
    pub fn lifecycle_seq(&self) -> u64 {
        self.lifecycle_seq
    }

    fn begin(&mut self, out: &[Event<E::Key>]) -> usize {
        self.slots.order.base = self.lifecycle_seq;
        self.slots.order.start = out.len();
        out.len()
    }

    fn end(&mut self, out: &[Event<E::Key>], start: usize) {
        self.lifecycle_seq += (out.len() - start) as u64;
    }

    /// Periodic sweep: parsers' `on_tick`, out-of-order hole
    /// deadlines, idle-timeout `Ended` events.
    pub fn sweep(&mut self, now: Timestamp) -> Vec<Event<E::Key>> {
        let mut out = Vec::new();
        self.sweep_into(now, &mut out);
        out
    }

    /// Append-only sweep.
    pub fn sweep_into(&mut self, now: Timestamp, out: &mut Vec<Event<E::Key>>) {
        let start = self.begin(out);
        self.engine.sweep(now, &mut self.slots, out);
        self.end(out, start);
    }

    /// End-of-input flush.
    pub fn finish(&mut self) -> Vec<Event<E::Key>> {
        let mut out = Vec::new();
        self.finish_into(&mut out);
        out
    }

    /// Append-only finish.
    ///
    /// Every flow ends. Parsers' `on_tick` sees `Timestamp::MAX`;
    /// output is stamped with the latest packet timestamp (never
    /// `Timestamp::MAX`) and the monotonic clock is left alone.
    pub fn finish_into(&mut self, out: &mut Vec<Event<E::Key>>) {
        let start = self.begin(out);
        self.engine.finish(&mut self.slots, out);
        self.end(out, start);
    }

    /// One-call iterator over a pcap file — drives every packet
    /// through this driver and yields the lifecycle event
    /// stream. Per-parser typed messages still flow through
    /// the registered [`SlotHandle`](super::SlotHandle)s; drain
    /// them yourself between iterator pulls if you need them
    /// in-line.
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

    /// Force-end the flow with this key: its last bytes reach every
    /// parser, parsers are flushed (`fin_*`) and closed
    /// ([`Event::ParserClosed`]), then [`Event::Ended`] with
    /// [`crate::EndReason::ForceClosed`]. No-op for an unknown key.
    pub fn force_close(&mut self, key: &E::Key, now: Timestamp) -> Vec<Event<E::Key>> {
        let mut out = Vec::new();
        self.force_close_into(key, now, &mut out);
        out
    }

    /// Append-only variant of [`Self::force_close`].
    pub fn force_close_into(&mut self, key: &E::Key, now: Timestamp, out: &mut Vec<Event<E::Key>>) {
        let start = self.begin(out);
        self.engine.force_close(key, now, &mut self.slots, out);
        self.end(out, start);
    }

    /// Borrow the underlying tracker for introspection.
    pub fn tracker(&self) -> &FlowTracker<E, ()> {
        self.engine.flow.tracker()
    }

    /// Mutable borrow of the underlying tracker.
    pub fn tracker_mut(&mut self) -> &mut FlowTracker<E, ()> {
        self.engine.flow.tracker_mut()
    }

    /// Borrow the underlying flow driver (reassembly state, memcap
    /// accounting).
    pub fn flow_driver(&self) -> &FlowDriver<E, SegmentBufferReassemblerFactory, ()> {
        &self.engine.flow
    }

    /// Live `(key, stats)` for every tracked flow, including the
    /// reassembly diagnostics (gaps, retransmits, watermark, …).
    pub fn snapshot_flow_stats(&self) -> impl Iterator<Item = (E::Key, FlowStats)> + '_ {
        self.engine.flow.snapshot_flow_stats()
    }
}

/// Builder for [`Driver`]. Mutates in place; each
/// session/datagram registration returns a typed [`SlotHandle`].
/// Settings and registrations may come in any order.
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
    /// Flow-table and reassembly config.
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

    /// Per-packet physical capture leg on [`Event::Packet`]
    /// (issue #121). Convenience passthrough for
    /// [`crate::FlowTrackerConfig::emit_packet_source_idx`].
    pub fn emit_packet_source_idx(&mut self, on: bool) -> &mut Self {
        self.config.emit_packet_source_idx = on;
        self
    }

    /// Emit `FlowAnomaly` / `TrackerAnomaly` events inline —
    /// reassembly anomalies (gaps, retransmits, overflows,
    /// watermark, overlap inconsistencies) and parser poison
    /// ([`AnomalyKind::SessionParseError`]) included.
    pub fn emit_anomalies(&mut self, on: bool) -> &mut Self {
        self.emit_anomalies = on;
        self
    }

    /// Content-hash duplicate filtering before tracking. Duplicates
    /// reach neither the lifecycle nor any parser.
    pub fn dedup(&mut self, dedup: Dedup) -> &mut Self {
        self.dedup = Some(dedup);
        self
    }

    /// Per-key idle-timeout override. Parser state lives exactly as
    /// long as the flow, so this also decides when parsers reset.
    pub fn idle_timeout_fn<F>(&mut self, f: F) -> &mut Self
    where
        F: Fn(&E::Key, Option<L4Proto>) -> Option<Duration> + Send + Sync + 'static,
    {
        self.idle_timeout_fn = Some(Box::new(f));
        self
    }

    fn next_slot_id(&self) -> SlotId {
        SlotId(self.slots.len() as u32)
    }

    fn add_session<P>(&mut self, parser: P, selector: Selector) -> SlotHandle<P::Message, E::Key>
    where
        P: SessionParser + Clone + Send + Sync + 'static,
        P::Message: Send + Sync + 'static,
    {
        let parser_kind = parser.parser_kind();
        let id = self.next_slot_id();
        let queue = Arc::new(SegQueue::new());
        self.slots.push(Box::new(SessionSlot {
            core: SessionCore::new(TemplateFactory(parser), selector),
            sink: Arc::clone(&queue),
            id,
        }));
        SlotHandle {
            inner: queue,
            parser_kind,
            slot: id,
        }
    }

    fn add_datagram<D>(&mut self, parser: D, selector: Selector) -> SlotHandle<D::Message, E::Key>
    where
        D: DatagramParser + Clone + Send + Sync + 'static,
        D::Message: Send + Sync + 'static,
    {
        let parser_kind = parser.parser_kind();
        let id = self.next_slot_id();
        let queue = Arc::new(SegQueue::new());
        self.slots.push(Box::new(DatagramSlot {
            core: DatagramCore::new(TemplateFactory(parser), selector),
            sink: Arc::clone(&queue),
            id,
        }));
        SlotHandle {
            inner: queue,
            parser_kind,
            slot: id,
        }
    }

    /// Register a session parser for flows with either port in
    /// `ports`. Returns a typed drain handle for its messages.
    pub fn session_on_ports<P, I>(&mut self, parser: P, ports: I) -> SlotHandle<P::Message, E::Key>
    where
        P: SessionParser + Clone + Send + Sync + 'static,
        P::Message: Send + Sync + 'static,
        I: IntoIterator<Item = u16>,
    {
        self.add_session(parser, Selector::Ports(ports.into_iter().collect()))
    }

    /// Register a session parser bound to a port set, with
    /// **broadcast** (fan-out) consumer semantics. Returns a
    /// [`BroadcastSlotHandle`] — each [`Clone`] of the handle
    /// is a separate subscriber that sees **every** message.
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
        let parser_kind = parser.parser_kind();
        let id = self.next_slot_id();
        let inner = BroadcastInner::new();
        let handle = BroadcastSlotHandle::new(Arc::clone(&inner), parser_kind, id);
        self.slots.push(Box::new(SessionSlot {
            core: SessionCore::new(
                TemplateFactory(parser),
                Selector::Ports(ports.into_iter().collect()),
            ),
            sink: inner,
            id,
        }));
        handle
    }

    /// Register a session parser that observes every TCP flow.
    pub fn session_broadcast<P>(&mut self, parser: P) -> SlotHandle<P::Message, E::Key>
    where
        P: SessionParser + Clone + Send + Sync + 'static,
        P::Message: Send + Sync + 'static,
    {
        self.add_session(parser, Selector::All)
    }

    /// Register a session parser activated by a signature probe
    /// over the first bytes of each flow's reassembled stream. Once
    /// the signature matches, the parser receives the stream from its
    /// first byte (the probed bytes are replayed).
    pub fn session_heuristic<P>(
        &mut self,
        parser: P,
        signature: SignatureFn,
    ) -> SlotHandle<P::Message, E::Key>
    where
        P: SessionParser + Clone + Send + Sync + 'static,
        P::Message: Send + Sync + 'static,
    {
        self.session_heuristic_with_budget(parser, signature, DEFAULT_PROBE_PACKETS)
    }

    /// [`Self::session_heuristic`] with a custom budget of
    /// data-bearing packets before the probe gives up.
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
        self.add_session(
            parser,
            Selector::Signature {
                signature,
                max_probe_packets,
            },
        )
    }

    /// Register a datagram parser bound to a port set.
    pub fn datagram_on_ports<D, I>(&mut self, parser: D, ports: I) -> SlotHandle<D::Message, E::Key>
    where
        D: DatagramParser + Clone + Send + Sync + 'static,
        D::Message: Send + Sync + 'static,
        I: IntoIterator<Item = u16>,
    {
        self.add_datagram(parser, Selector::Ports(ports.into_iter().collect()))
    }

    /// Register a datagram parser that observes every UDP flow.
    pub fn datagram_broadcast<D>(&mut self, parser: D) -> SlotHandle<D::Message, E::Key>
    where
        D: DatagramParser + Clone + Send + Sync + 'static,
        D::Message: Send + Sync + 'static,
    {
        self.add_datagram(parser, Selector::All)
    }

    /// Register a datagram parser activated by a signature probe.
    pub fn datagram_heuristic<D>(
        &mut self,
        parser: D,
        signature: SignatureFn,
    ) -> SlotHandle<D::Message, E::Key>
    where
        D: DatagramParser + Clone + Send + Sync + 'static,
        D::Message: Send + Sync + 'static,
    {
        self.datagram_heuristic_with_budget(parser, signature, DEFAULT_PROBE_PACKETS)
    }

    /// [`Self::datagram_heuristic`] with a custom probe budget.
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
        self.add_datagram(
            parser,
            Selector::Signature {
                signature,
                max_probe_packets,
            },
        )
    }

    /// Materialise the driver.
    pub fn build(self) -> Driver<E> {
        let mut engine = Engine::new(self.extractor, self.config);
        engine.flow.set_emit_anomalies(self.emit_anomalies);
        engine
            .flow
            .set_monotonic_timestamps(self.monotonic_timestamps);
        engine.flow.set_dedup(self.dedup);
        if let Some(f) = self.idle_timeout_fn {
            engine
                .flow
                .tracker_mut()
                .set_idle_timeout_fn(move |k, l4| f(k, l4));
        }
        let needs_ports = self.slots.iter().any(|s| s.needs_ports());
        Driver {
            engine,
            slots: Slots {
                list: self.slots,
                needs_ports,
                emit_packet_details: self.emit_packet_details,
                order: Order::default(),
            },
            lifecycle_seq: 0,
        }
    }
}

/// Map a tracker-emitted [`FlowEvent`] into the typed
/// [`Event<K>`] shape. Drops `Message` / `StateChange` (the
/// former is now slot-handle-routed; the latter has no
/// shipping equivalent — `Established` covers it).
fn map_flow_event<K>(ev: FlowEvent<K>, tcp: Option<TcpInfo>) -> Option<Event<K>> {
    // The typed driver historically omits raw TCP state churn —
    // `Established` covers the common case — so drop `StateChange`
    // here even though `Event` can now represent it (issue #97). The
    // rest reuse the lossless `From` conversion, then patch in the
    // opt-in per-packet `tcp` details the conversion can't know about.
    if matches!(ev, FlowEvent::StateChange { .. }) {
        return None;
    }
    let mut event = Event::from(ev);
    if let Event::Packet { tcp: slot, .. } = &mut event {
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

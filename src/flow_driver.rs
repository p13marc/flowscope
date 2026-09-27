//! [`FlowDriver`] — sync wrapper that bundles a [`FlowTracker`] with
//! a [`ReassemblerFactory`] and dispatches TCP segments to the right
//! reassembler.
//!
//! The async equivalent lives in `netring`'s `FlowStream::with_async_reassembler`.
//!
//! # Reassembly failures never end a flow
//!
//! A flow's lifecycle ([`FlowEvent::Started`] … [`FlowEvent::Ended`])
//! reflects the transport: `Ended.reason` is always one of `Fin`,
//! `Rst`, `IdleTimeout`, `Evicted` or `ForceClosed`. When reassembly
//! of a side stops (per-side cap under
//! [`OverflowPolicy::DropFlow`], or
//! the tracker-wide memcap), the flow **stays tracked** — its later
//! packets are still recognised as the same connection — and the
//! stop is reported through the [`AnomalyKind::BufferOverflow`] /
//! [`AnomalyKind::GlobalMemcapHit`] anomalies, the drained
//! [`StreamChunks::stop`], and [`crate::FlowStats`]. (Before 0.25 the
//! driver synthesised `Ended { reason: BufferOverflow }` and forgot
//! the flow, so its next packet started a new flow mid-stream.)
//!
//! # What the driver feeds its reassemblers
//!
//! Besides each data segment, a reassembler learns the stream origin
//! from the SYN / SYN-ACK ([`Reassembler::set_origin`]; a SYN's own
//! data — TCP Fast Open — starts one past its sequence number), the
//! peer's acknowledgements ([`Reassembler::peer_ack`]) and its own FIN
//! ([`Reassembler::fin_seen`]). RST payloads (diagnostic text) are not
//! stream data and are ignored.
//!
//! # Event gating
//!
//! The driver owns its tracker's `Ended` events: they are always
//! produced internally so per-flow state is released, and the
//! [`FlowTrackerConfig::suppress_events`] mask /
//! [`FlowTracker::pause_events`] only decide what reaches the caller
//! (including the driver's own `FlowAnomaly` / `TrackerAnomaly` /
//! `Tick`). [`FlowTrackerConfig::auto_sweep_interval`] runs the
//! driver's full sweep, not just the tracker's.

use std::collections::HashMap;
use std::time::Duration;

use ahash::RandomState;

use crate::Timestamp;
use crate::event::{
    AnomalyKind, EventMask, FlowEvent, FlowSide, FlowStats, MemcapPolicy, OverflowPolicy,
    ReassemblyStop,
};
use crate::extractor::{FlowExtractor, L4Meta, L4Proto, Orientation, TcpFlags, TcpInfo};
use crate::reassembler::{Reassembler, ReassemblerFactory, SegmentOutcome, StreamChunks};
use crate::tracker::{FlowEvents, FlowTracker, FlowTrackerConfig, PacketContext};
use crate::view::PacketView;

/// What the driver learned about the packet it just tracked. Returned
/// by [`FlowDriver::last_packet`]; the session engines use it to
/// dispatch per-packet work without depending on
/// [`FlowEvent::Packet`] (which load-shedding can suppress).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PacketInfo<K> {
    /// Flow the packet belongs to.
    pub key: K,
    /// Logical side that sent it.
    pub side: FlowSide,
    /// Canonical direction of the packet.
    pub orientation: Orientation,
    /// L4 protocol, when identified.
    pub l4: Option<L4Proto>,
    /// Parsed TCP header, for TCP packets.
    pub tcp: Option<TcpInfo>,
    /// Ports and L4 payload location reported by the extractor
    /// (offsets into the tracked frame). New in 0.25.0.
    pub l4_meta: Option<L4Meta>,
    /// Packet timestamp (after dedup / monotonic clamping).
    pub ts: Timestamp,
    /// `true` when this packet created the flow.
    pub is_new: bool,
    /// Set when the reassembler let this packet's payload through
    /// ([`SegmentOutcome::Passthrough`]): `payload[skip..]` are the
    /// next in-order bytes and were **not** buffered.
    #[cfg_attr(
        not(all(feature = "session", feature = "extractors")),
        allow(dead_code)
    )]
    pub(crate) passthrough: Option<usize>,
}

impl<K> PacketInfo<K> {
    /// The in-order bytes the reassembler let through for this
    /// packet (engine mode), sliced from `frame`.
    #[cfg_attr(
        not(all(feature = "session", feature = "extractors")),
        allow(dead_code)
    )]
    pub(crate) fn passthrough_bytes<'a>(&self, frame: &'a [u8]) -> Option<&'a [u8]> {
        let skip = self.passthrough?;
        let tcp = self.tcp.as_ref()?;
        let start = tcp.payload_offset.checked_add(skip)?;
        let end = tcp.payload_offset.checked_add(tcp.payload_len)?;
        frame.get(start..end)
    }
}

/// Per-reassembler diagnostic counters, captured before a segment is
/// fed (or a sweep runs) and diffed afterwards into anomaly events.
#[derive(Clone, Copy, Default, Debug)]
struct Counters {
    dropped: u64,
    oversize: u64,
    crossings: u64,
    retransmits: u64,
    inconsistencies: u64,
    gaps: u64,
    gap_bytes: u64,
    out_of_window: u64,
    ack_gaps: u64,
    origin_resets: u64,
    high_watermark: u64,
}

impl Counters {
    fn of<R: Reassembler>(r: &R) -> Self {
        Self {
            dropped: r.dropped_segments(),
            oversize: r.bytes_dropped_oversize(),
            crossings: r.high_watermark_crossings(),
            retransmits: r.retransmits(),
            inconsistencies: r.rexmit_inconsistencies(),
            gaps: r.gaps(),
            gap_bytes: r.gap_bytes(),
            out_of_window: r.out_of_window_segments(),
            ack_gaps: r.ack_confirmed_gaps(),
            origin_resets: r.origin_resets(),
            high_watermark: r.high_watermark(),
        }
    }

    /// Anomaly kinds for everything that changed between `self`
    /// (before) and `r` (after), for one side.
    fn diff<R: Reassembler>(&self, r: &R, side: FlowSide, out: &mut Vec<AnomalyKind>) {
        let now = Counters::of(r);
        let oversize = now.oversize.saturating_sub(self.oversize);
        if oversize > 0 {
            let policy = if r.stop_reason() == Some(ReassemblyStop::Overflow) {
                OverflowPolicy::DropFlow
            } else {
                OverflowPolicy::SlidingWindow
            };
            out.push(AnomalyKind::BufferOverflow {
                side,
                bytes: oversize,
                policy,
            });
        }
        let gaps = now.gaps.saturating_sub(self.gaps);
        if gaps > 0 {
            out.push(AnomalyKind::StreamGap {
                side,
                gaps,
                bytes: now.gap_bytes.saturating_sub(self.gap_bytes),
            });
        }
        let dropped = now.dropped.saturating_sub(self.dropped);
        if dropped > 0 {
            out.push(AnomalyKind::OutOfOrderSegment {
                side,
                count: dropped,
            });
        }
        let oow = now.out_of_window.saturating_sub(self.out_of_window);
        if oow > 0 {
            out.push(AnomalyKind::OutOfWindowSegment { side, count: oow });
        }
        if now.crossings > self.crossings
            && let Some((cap, threshold_pct)) = r.high_watermark_threshold()
        {
            out.push(AnomalyKind::ReassemblerHighWatermark {
                side,
                bytes: r.bytes_in_flight(),
                cap,
                threshold_pct,
            });
        }
        let retransmits = now.retransmits.saturating_sub(self.retransmits);
        if retransmits > 0 {
            out.push(AnomalyKind::RetransmittedSegment {
                side,
                count: retransmits,
            });
        }
        let inconsistencies = now.inconsistencies.saturating_sub(self.inconsistencies);
        if inconsistencies > 0 {
            out.push(AnomalyKind::TcpRexmitInconsistency {
                side,
                count: inconsistencies,
            });
        }
    }
}

/// A live reassembler plus the bytes it last contributed to the
/// tracker-wide memcap pool.
struct Live<R> {
    r: R,
    accounted: u64,
}

/// Final diagnostics of a side whose reassembler was dropped.
#[derive(Debug, Clone, Copy)]
struct DoneStats {
    counters: Counters,
}

/// Stream state of one side of a flow.
enum SideSlot<R> {
    /// No data seen yet.
    Empty,
    /// Reassembling.
    Live(Box<Live<R>>),
    /// No longer reassembled — discarded by the consumer or stopped
    /// by the memcap. Later segments are ignored; the reassembler is
    /// gone (no memory held). `stop` is reported to the next drain
    /// once (`reported`); `stats` keeps the final counters (`None`
    /// when all were zero).
    Done {
        stats: Option<Box<DoneStats>>,
        stop: Option<ReassemblyStop>,
        reported: bool,
    },
}

/// Stream state of one flow.
struct StreamFlow<R> {
    sides: [SideSlot<R>; 2],
    /// First data sequence number of each side, from its SYN /
    /// SYN-ACK (ISN + 1).
    origin: [Option<u32>; 2],
    /// Ports of the packet that created the stream state (for data
    /// released by a sweep).
    ports: Option<(u16, u16)>,
}

impl<R> StreamFlow<R> {
    fn new(ports: Option<(u16, u16)>) -> Self {
        Self {
            sides: [SideSlot::Empty, SideSlot::Empty],
            origin: [None, None],
            ports,
        }
    }
}

fn idx(side: FlowSide) -> usize {
    match side {
        FlowSide::Initiator => 0,
        FlowSide::Responder => 1,
    }
}

const SIDES: [FlowSide; 2] = [FlowSide::Initiator, FlowSide::Responder];

/// Copy one side's diagnostics into the per-side fields of `stats`.
fn fold_counters(
    stats: &mut FlowStats,
    side: FlowSide,
    c: &Counters,
    stop: Option<ReassemblyStop>,
) {
    match side {
        FlowSide::Initiator => {
            stats.reassembly_dropped_ooo_initiator = c.dropped;
            stats.reassembly_bytes_dropped_oversize_initiator = c.oversize;
            stats.reassembler_high_watermark_initiator = c.high_watermark;
            stats.retransmits_initiator = c.retransmits;
            stats.reassembly_gaps_initiator = c.gaps;
            stats.reassembly_gap_bytes_initiator = c.gap_bytes;
            stats.reassembly_stop_initiator = stop;
            stats.reassembly_out_of_window_initiator = c.out_of_window;
            stats.reassembly_ack_confirmed_gaps_initiator = c.ack_gaps;
            stats.reassembly_origin_resets_initiator = c.origin_resets;
        }
        FlowSide::Responder => {
            stats.reassembly_dropped_ooo_responder = c.dropped;
            stats.reassembly_bytes_dropped_oversize_responder = c.oversize;
            stats.reassembler_high_watermark_responder = c.high_watermark;
            stats.retransmits_responder = c.retransmits;
            stats.reassembly_gaps_responder = c.gaps;
            stats.reassembly_gap_bytes_responder = c.gap_bytes;
            stats.reassembly_stop_responder = stop;
            stats.reassembly_out_of_window_responder = c.out_of_window;
            stats.reassembly_ack_confirmed_gaps_responder = c.ack_gaps;
            stats.reassembly_origin_resets_responder = c.origin_resets;
        }
    }
}

fn fold_slot<R: Reassembler>(stats: &mut FlowStats, side: FlowSide, slot: &SideSlot<R>) {
    match slot {
        SideSlot::Empty => {}
        SideSlot::Live(l) => fold_counters(stats, side, &Counters::of(&l.r), l.r.stop_reason()),
        SideSlot::Done {
            stats: Some(d),
            stop,
            ..
        } => fold_counters(stats, side, &d.counters, *stop),
        SideSlot::Done {
            stats: None, stop, ..
        } => fold_counters(stats, side, &Counters::default(), *stop),
    }
}

/// Drop a side's reassembler, keeping its final diagnostics. Returns
/// the bytes it had contributed to the memcap pool.
fn tombstone<R: Reassembler>(slot: &mut SideSlot<R>, stop: Option<ReassemblyStop>) -> u64 {
    match std::mem::replace(slot, SideSlot::Empty) {
        SideSlot::Live(l) => {
            let counters = Counters::of(&l.r);
            let stop = stop.or(l.r.stop_reason());
            let nonzero = counters.gaps
                | counters.dropped
                | counters.oversize
                | counters.retransmits
                | counters.high_watermark
                | counters.out_of_window
                | counters.inconsistencies
                != 0;
            *slot = SideSlot::Done {
                stats: nonzero.then(|| Box::new(DoneStats { counters })),
                stop,
                reported: stop.is_none(),
            };
            l.accounted
        }
        SideSlot::Empty => {
            *slot = SideSlot::Done {
                stats: None,
                stop,
                reported: stop.is_none(),
            };
            0
        }
        done @ SideSlot::Done { .. } => {
            *slot = done;
            0
        }
    }
}

/// Sync flow driver: tracker + per-(flow, side) reassembler dispatch.
///
/// Use this when you want both flow events **and** TCP byte streams
/// in one synchronous loop (typical for pcap replay, embedded use,
/// non-tokio CLI tools). For L7 parsing on top, use
/// [`crate::session::SessionDriver`] or the typed
/// [`crate::driver::Driver`], which are built on it.
///
/// The tracker config is the single source of truth for reassembly
/// limits: the factory receives it through
/// [`ReassemblerFactory::apply_config`] on construction and on
/// [`Self::set_config`].
pub struct FlowDriver<E, F, S = ()>
where
    E: FlowExtractor,
    F: ReassemblerFactory<E::Key>,
    S: Send + 'static,
{
    tracker: FlowTracker<E, S>,
    factory: F,
    streams: HashMap<E::Key, StreamFlow<F::Reassembler>, RandomState>,
    emit_anomalies: bool,
    dedup: Option<crate::dedup::Dedup>,
    /// When `Some`, the running max of all timestamps the driver
    /// has emitted. `None` means monotonisation is off.
    monotonic_ts: Option<Timestamp>,
    /// Latest packet timestamp seen (stamps `finish()` output).
    max_ts: Timestamp,
    /// Running total of bytes buffered across every live reassembler
    /// (issue #26), for [`FlowTrackerConfig::reassembly_memcap`].
    global_memcap_bytes: u64,
    last_packet: Option<PacketInfo<E::Key>>,
    /// Packet time of the last scan for due [`FlowEvent::Tick`]s.
    last_tick_scan: Option<Timestamp>,
    /// Engine mode: in-order payloads are let through
    /// ([`Reassembler::segment_into`]) instead of buffered.
    #[cfg_attr(
        not(all(feature = "session", feature = "extractors")),
        allow(dead_code)
    )]
    passthrough: bool,
    /// Flows ended / forgotten as far as this driver knows; when the
    /// tracker's count differs, someone used the tracker directly
    /// and stream state is reconciled.
    seen_gone: u64,
    /// Scratch for per-packet anomalies.
    anomalies: Vec<(E::Key, AnomalyKind)>,
    kinds: Vec<AnomalyKind>,
}

// Common path — `S = ()`.
impl<E, F> FlowDriver<E, F, ()>
where
    E: FlowExtractor,
    F: ReassemblerFactory<E::Key>,
{
    /// Construct with default config and `S = ()` (no per-flow user
    /// state). Annotation-free.
    pub fn new(extractor: E, factory: F) -> Self {
        Self::with_config(extractor, factory, FlowTrackerConfig::default())
    }

    /// Construct with explicit config and `S = ()`.
    pub fn with_config(extractor: E, factory: F, config: FlowTrackerConfig) -> Self {
        Self::from_tracker(FlowTracker::with_config(extractor, config), factory)
    }
}

// Stateful path — `S: Default`.
impl<E, F, S> FlowDriver<E, F, S>
where
    E: FlowExtractor,
    F: ReassemblerFactory<E::Key>,
    S: Default + Send + 'static,
{
    /// Construct with default config and per-flow state initialised
    /// via `S::default()`.
    pub fn with_state(extractor: E, factory: F) -> Self {
        Self::with_state_and_config(extractor, factory, FlowTrackerConfig::default())
    }

    /// Construct with explicit config and per-flow state initialised
    /// via `S::default()`.
    pub fn with_state_and_config(extractor: E, factory: F, config: FlowTrackerConfig) -> Self {
        Self::from_tracker(FlowTracker::with_config(extractor, config), factory)
    }
}

impl<E, F, S> FlowDriver<E, F, S>
where
    E: FlowExtractor,
    F: ReassemblerFactory<E::Key>,
    S: Send + 'static,
{
    /// Construct with default config and a custom per-flow state
    /// initialiser.
    pub fn with_state_init<G>(extractor: E, factory: F, init: G) -> Self
    where
        G: FnMut(&E::Key) -> S + Send + Sync + 'static,
    {
        Self::with_state_init_and_config(extractor, factory, FlowTrackerConfig::default(), init)
    }

    /// Construct with explicit config and a custom per-flow state
    /// initialiser.
    pub fn with_state_init_and_config<G>(
        extractor: E,
        factory: F,
        config: FlowTrackerConfig,
        init: G,
    ) -> Self
    where
        G: FnMut(&E::Key) -> S + Send + Sync + 'static,
    {
        Self::from_tracker(
            FlowTracker::with_config_and_state(extractor, config, init),
            factory,
        )
    }

    /// Wrap an existing tracker (keeps its config, idle-timeout
    /// predicate and live flows).
    pub fn from_tracker(mut tracker: FlowTracker<E, S>, mut factory: F) -> Self {
        factory.apply_config(tracker.config());
        tracker.set_driver_owned(true);
        let seen_gone = tracker.stats().flows_ended + tracker.forgotten();
        Self {
            tracker,
            factory,
            streams: HashMap::with_hasher(RandomState::new()),
            emit_anomalies: false,
            dedup: None,
            monotonic_ts: None,
            max_ts: Timestamp::default(),
            global_memcap_bytes: 0,
            last_packet: None,
            last_tick_scan: None,
            passthrough: false,
            seen_gone,
            anomalies: Vec::new(),
            kinds: Vec::new(),
        }
    }

    /// Opt in to emitting [`FlowEvent::FlowAnomaly`] /
    /// [`FlowEvent::TrackerAnomaly`] for buffer overflows, gaps,
    /// late / stray segments, retransmits, overlap inconsistencies,
    /// high-watermark crossings, memcap hits and tracker eviction
    /// pressure. Default: `false` — no anomaly events emitted;
    /// counters still accumulate in [`crate::FlowStats`].
    ///
    /// Anomalies are coalesced per (flow, side, kind) per packet /
    /// sweep so a pathological flow doesn't swamp the stream.
    pub fn with_emit_anomalies(mut self, enable: bool) -> Self {
        self.emit_anomalies = enable;
        self
    }

    /// Set a per-key idle-timeout override on the underlying tracker
    /// (see [`FlowTracker::set_idle_timeout_fn`]).
    pub fn with_idle_timeout_fn<G>(mut self, f: G) -> Self
    where
        G: Fn(&E::Key, Option<crate::L4Proto>) -> Option<std::time::Duration>
            + Send
            + Sync
            + 'static,
    {
        self.tracker.set_idle_timeout_fn(f);
        self
    }

    /// Filter incoming `PacketView`s through a content-hash
    /// [`crate::Dedup`] before extraction. Views the dedup
    /// classifies as duplicates produce zero events; they count in
    /// [`Self::dedup`]`().dropped()` and in
    /// `flowscope_packets_deduplicated_total`. Useful for
    /// loopback captures (`tcpdump -i lo`) where every packet
    /// arrives twice via the kernel's outgoing/host reinjection.
    pub fn with_dedup(mut self, dedup: crate::dedup::Dedup) -> Self {
        self.dedup = Some(dedup);
        self
    }

    /// Borrow the dedup state. `None` when no dedup is configured.
    pub fn dedup(&self) -> Option<&crate::dedup::Dedup> {
        self.dedup.as_ref()
    }

    /// Opt in to strictly non-decreasing timestamps across the
    /// stream. Each packet's `view.timestamp` is clamped to
    /// `max(view.timestamp, last_emitted_timestamp)`; the clamp also
    /// applies to [`Self::sweep`]'s `now` argument. Default: off.
    pub fn with_monotonic_timestamps(mut self, enable: bool) -> Self {
        self.set_monotonic_timestamps(enable);
        self
    }

    /// In-place variant of [`Self::with_monotonic_timestamps`].
    pub fn set_monotonic_timestamps(&mut self, enable: bool) {
        self.monotonic_ts = enable.then(Timestamp::default);
    }

    /// In-place variant of [`Self::with_emit_anomalies`].
    pub fn set_emit_anomalies(&mut self, enable: bool) {
        self.emit_anomalies = enable;
    }

    /// In-place variant of [`Self::with_dedup`]; `None` removes it.
    pub fn set_dedup(&mut self, dedup: Option<crate::dedup::Dedup>) {
        self.dedup = dedup;
    }

    /// Replace the config: the tracker adopts it and the factory
    /// receives it through [`ReassemblerFactory::apply_config`].
    /// Reassemblers already created keep their settings.
    pub fn set_config(&mut self, config: FlowTrackerConfig) {
        self.factory.apply_config(&config);
        self.tracker.set_config(config);
    }

    /// Stop emitting events (the "shunt mode" of
    /// [`FlowTracker::pause_events`]); per-flow state is still
    /// released as flows end.
    pub fn pause_events(&mut self) {
        self.tracker.pause_events();
    }

    /// Resume emitting events after [`Self::pause_events`].
    pub fn resume_events(&mut self) {
        self.tracker.resume_events();
    }

    /// Engine mode (see [`PacketInfo::passthrough_bytes`]).
    #[cfg_attr(
        not(all(feature = "session", feature = "extractors")),
        allow(dead_code)
    )]
    pub(crate) fn set_passthrough(&mut self, on: bool) {
        self.passthrough = on;
    }

    fn clamp_view<'a>(&mut self, view: PacketView<'a>) -> PacketView<'a> {
        let Some(last) = self.monotonic_ts.as_mut() else {
            return view;
        };
        *last = (*last).max(view.timestamp);
        let mut clamped = view;
        clamped.timestamp = *last;
        clamped
    }

    /// Apply the monotonic clamp to a sweep's `now`.
    pub(crate) fn clamp_now(&mut self, now: Timestamp) -> Timestamp {
        let Some(last) = self.monotonic_ts.as_mut() else {
            return now;
        };
        *last = (*last).max(now);
        *last
    }

    /// Latest packet timestamp seen — what [`Self::finish`] stamps
    /// its output with.
    pub fn max_timestamp(&self) -> Timestamp {
        self.max_ts
    }

    /// Whether events of this kind reach the caller (see
    /// [`Self::emits`]).
    #[cfg_attr(
        not(all(feature = "session", feature = "extractors")),
        allow(dead_code)
    )]
    pub(crate) fn emits_mask(&self, bit: EventMask) -> bool {
        !self.tracker.events_paused() && !self.tracker.config().suppress_events.contains(bit)
    }

    /// Whether `ev` reaches the caller: the tracker's
    /// [`FlowTrackerConfig::suppress_events`] mask and
    /// [`FlowTracker::pause_events`] apply to the driver's output.
    pub(crate) fn emits(&self, ev: &FlowEvent<E::Key>) -> bool {
        let bit = match ev {
            FlowEvent::Ended { .. } => EventMask::ENDED,
            FlowEvent::FlowAnomaly { .. } => EventMask::FLOW_ANOMALY,
            FlowEvent::TrackerAnomaly { .. } => EventMask::TRACKER_ANOMALY,
            FlowEvent::Tick { .. } => EventMask::TICK,
            // Gated by the tracker itself.
            _ => return true,
        };
        !self.tracker.events_paused() && !self.tracker.config().suppress_events.contains(bit)
    }

    /// Process one packet. Drives the tracker and dispatches TCP
    /// payloads to the factory's reassemblers. Reassemblers are
    /// created on demand and cleaned up on `Ended`.
    pub fn track<'v>(&mut self, view: impl Into<PacketView<'v>>) -> FlowEvents<E::Key> {
        let mut events = self.track_pending(view);
        self.finalize(events.as_mut_slice());
        let ts = self.last_packet.as_ref().map(|p| p.ts);
        if let Some(ts) = ts
            && self.tracker.auto_sweep_due(ts)
        {
            events.extend(self.sweep(ts));
        }
        events
    }

    /// Lower-level: process one packet and return events **without**
    /// finalizing reassemblers. Reassemblers stay accessible (via
    /// [`Self::reassembler`] / [`Self::drain_stream`]) until
    /// [`Self::finalize`] is called — which is how a consumer
    /// harvests the last bytes of a flow that ends on this packet.
    ///
    /// For every `Ended` event in the result, both sides'
    /// reassemblers have already been flushed
    /// ([`Reassembler::flush_pending`]) and their final diagnostics
    /// folded into the event's `stats`. An `Ended` the event mask
    /// suppresses is finalized internally.
    ///
    /// You MUST call [`Self::finalize`] before the next
    /// `track_pending` / `sweep_pending` / `track` / `sweep` call.
    /// Auto-sweeps ([`FlowTrackerConfig::auto_sweep_interval`]) only
    /// run from [`Self::track`].
    pub fn track_pending<'v>(&mut self, view: impl Into<PacketView<'v>>) -> FlowEvents<E::Key> {
        self.track_pending_with(view, |_| true)
    }

    /// Like [`Self::track_pending`], but a reassembler is only
    /// **created** for a flow when `want` returns `true` for the
    /// packet that would create it (flows that already have stream
    /// state keep it). The session engines use it to buffer only
    /// flows some parser is interested in; answer consistently for
    /// every packet of a flow.
    pub fn track_pending_with<'v, W>(
        &mut self,
        view: impl Into<PacketView<'v>>,
        want: W,
    ) -> FlowEvents<E::Key>
    where
        W: FnMut(&PacketContext<'_, E::Key>) -> bool,
    {
        let mut events = self.track_raw(view, want);
        self.close_all(&mut events);
        events
    }

    /// Flush, fold and (when masked) finalize every `Ended` in
    /// `events`; drop output the mask suppresses.
    fn close_all<B: EventBuf<E::Key>>(&mut self, events: &mut B) {
        let mut i = 0;
        while i < events.len() {
            if let FlowEvent::Ended { .. } = events.get_mut(i) {
                let mut flush: SmallAnoms<E::Key> = SmallAnoms::new();
                let (key, reason) = {
                    let FlowEvent::Ended {
                        key, reason, stats, ..
                    } = events.get_mut(i)
                    else {
                        unreachable!()
                    };
                    let key = key.clone();
                    self.close_flow(&key, stats, &mut flush);
                    (key, *reason)
                };
                for a in flush {
                    if self.emits(&a) {
                        events.insert(i, a);
                        i += 1;
                    }
                }
                if !self.emits(events.get_mut(i)) {
                    self.finalize_flow(&key, reason);
                    events.remove(i);
                    continue;
                }
            } else if !self.emits(events.get_mut(i)) {
                events.remove(i);
                continue;
            }
            i += 1;
        }
    }

    /// Track one packet: tracker events with this packet's anomalies
    /// placed before the packet's own `Ended` (if any), ticks last.
    /// Ended flows are neither flushed nor finalized, and nothing is
    /// masked — the engine and [`Self::track_pending_with`] do that.
    pub(crate) fn track_raw<'v, W>(
        &mut self,
        view: impl Into<PacketView<'v>>,
        mut want: W,
    ) -> FlowEvents<E::Key>
    where
        W: FnMut(&PacketContext<'_, E::Key>) -> bool,
    {
        self.last_packet = None;
        let view: PacketView<'v> = view.into();
        if let Some(d) = self.dedup.as_mut()
            && !d.keep(view)
        {
            crate::obs::record_packet_deduplicated();
            return FlowEvents::new();
        }
        let view = self.clamp_view(view);
        let ts = view.timestamp;
        self.max_ts = self.max_ts.max(ts);
        let evicted_before = self.tracker.stats().flows_evicted;
        let memcap_cap = self.tracker.config().reassembly_memcap;
        let memcap_policy = self.tracker.config().reassembly_memcap_policy;
        let emit_anomalies = self.emit_anomalies;
        let passthrough = self.passthrough;

        let factory = &mut self.factory;
        let streams = &mut self.streams;
        let global = &mut self.global_memcap_bytes;
        let anomalies = &mut self.anomalies;
        let kinds = &mut self.kinds;
        anomalies.clear();
        let mut info: Option<PacketInfo<E::Key>> = None;
        // At most one `GlobalMemcapHit` per packet; captures the
        // bytes-in-flight at the trip.
        let mut memcap_tripped: Option<u64> = None;

        let mut events = self.tracker.track_with(view, |p| {
            let mut pass = None;
            // A new flow must not inherit stream state left behind by
            // an earlier flow with the same key (forgotten behind the
            // driver's back).
            if p.is_new
                && let Some(old) = streams.remove(p.key)
            {
                for slot in old.sides {
                    if let SideSlot::Live(l) = slot {
                        *global = global.saturating_sub(l.accounted);
                    }
                }
            }
            if let Some(tcp) = p.tcp {
                pass = feed_tcp(
                    p,
                    tcp,
                    &mut want,
                    factory,
                    streams,
                    global,
                    TcpFeed {
                        passthrough,
                        emit_anomalies,
                        memcap_cap,
                        memcap_policy,
                    },
                    &mut memcap_tripped,
                    anomalies,
                    kinds,
                );
            }
            info = Some(PacketInfo {
                key: p.key.clone(),
                side: p.side,
                orientation: p.orientation,
                l4: p.l4,
                tcp: p.tcp.copied(),
                l4_meta: p.l4_meta,
                ts: p.ts,
                is_new: p.is_new,
                passthrough: pass,
            });
        });

        // Anomalies of this packet go right before its own flow's
        // `Ended` (a FIN / RST packet), else after the tracker's
        // events.
        let at = info
            .as_ref()
            .and_then(|p| {
                events
                    .iter()
                    .position(|e| matches!(e, FlowEvent::Ended { key, .. } if key == &p.key))
            })
            .unwrap_or(events.len());
        let mut extra: SmallAnoms<E::Key> = SmallAnoms::new();
        if emit_anomalies {
            for (key, kind) in self.anomalies.drain(..) {
                crate::obs::record_anomaly(&kind);
                crate::obs::trace_anomaly(&kind);
                extra.push(FlowEvent::FlowAnomaly { key, kind, ts });
            }
            if let Some(bytes_in_flight) = memcap_tripped
                && let Some(cap) = memcap_cap
            {
                extra.push(tracker_anomaly(
                    AnomalyKind::GlobalMemcapHit {
                        bytes_in_flight,
                        cap,
                        policy: memcap_policy,
                    },
                    ts,
                ));
            }
            if let Some(a) = self.eviction_pressure(evicted_before, ts) {
                extra.push(a);
            }
        }
        for (n, a) in extra.into_iter().enumerate() {
            events.insert(at + n, a);
        }
        self.last_packet = info;
        self.note_gone(events.iter());

        // Periodic flow ticks (Plan 71), honouring the load-shed
        // gates (issue #79).
        if let Some(interval) = self.tracker.config().flow_tick_interval
            && !self.tracker.events_paused()
            && !self
                .tracker
                .config()
                .suppress_events
                .contains(EventMask::TICK)
        {
            self.emit_ticks(&mut events, ts, interval);
        }
        events
    }

    /// Count `Ended` events the driver has seen (reconcile guard).
    fn note_gone<'a>(&mut self, events: impl Iterator<Item = &'a FlowEvent<E::Key>>)
    where
        E::Key: 'a,
    {
        self.seen_gone += events
            .filter(|e| matches!(e, FlowEvent::Ended { .. }))
            .count() as u64;
    }

    fn eviction_pressure(&self, evicted_before: u64, ts: Timestamp) -> Option<FlowEvent<E::Key>> {
        let evicted_total = self.tracker.stats().flows_evicted;
        let evicted_in_tick = evicted_total.saturating_sub(evicted_before);
        (evicted_in_tick > 0).then(|| {
            tracker_anomaly(
                AnomalyKind::FlowTableEvictionPressure {
                    evicted_in_tick,
                    evicted_total,
                },
                ts,
            )
        })
    }

    /// Flush both sides of an ended flow (no hole will ever fill),
    /// fold their final diagnostics into `stats`, and push the
    /// anomalies the flush produced (when enabled) to `out`. Stream
    /// state stays until [`Self::finalize_flow`], so the last bytes
    /// can still be drained.
    pub(crate) fn close_flow<X: Extend<FlowEvent<E::Key>>>(
        &mut self,
        key: &E::Key,
        stats: &mut FlowStats,
        out: &mut X,
    ) {
        let ts = stats.last_seen;
        if let Some(flow) = self.streams.get_mut(key) {
            for (i, side) in SIDES.into_iter().enumerate() {
                if let SideSlot::Live(l) = &mut flow.sides[i] {
                    let before = self.emit_anomalies.then(|| Counters::of(&l.r));
                    l.r.flush_pending();
                    if let Some(before) = before {
                        self.kinds.clear();
                        before.diff(&l.r, side, &mut self.kinds);
                        out.extend(self.kinds.drain(..).map(|kind| {
                            crate::obs::record_anomaly(&kind);
                            crate::obs::trace_anomaly(&kind);
                            FlowEvent::FlowAnomaly {
                                key: key.clone(),
                                kind,
                                ts,
                            }
                        }));
                    }
                }
                fold_slot(stats, side, &flow.sides[i]);
            }
        }
        crate::obs::record_reassembly_diagnostics(stats);
    }

    /// Walk live flows; for any whose `last_tick_at` is past-due,
    /// emit a [`FlowEvent::Tick`] carrying a live [`FlowStats`]
    /// snapshot and mark the flow as ticked.
    ///
    /// The scan walks every flow, so it runs at most every quarter
    /// interval of packet time (a tick is at most 1.25 intervals
    /// late) instead of on every packet.
    fn emit_ticks(&mut self, events: &mut FlowEvents<E::Key>, now: Timestamp, interval: Duration) {
        if let Some(last) = self.last_tick_scan
            && now.saturating_sub(last) < interval / 4
        {
            return;
        }
        self.last_tick_scan = Some(now);
        let mut to_tick: Vec<(E::Key, FlowStats)> = Vec::new();
        for (key, entry) in self.tracker.flows() {
            let due = match entry.last_tick_at {
                None => true,
                Some(last) => now.saturating_sub(last) >= interval,
            };
            if due {
                to_tick.push((key.clone(), self.live_stats(key, &entry.stats)));
            }
        }
        for (key, stats) in to_tick {
            self.tracker.mark_ticked(&key, now);
            crate::obs::record_flow_tick(&stats);
            events.push(FlowEvent::Tick {
                key,
                stats,
                ts: now,
            });
        }
    }

    fn live_stats(&self, key: &E::Key, base: &FlowStats) -> FlowStats {
        let mut stats = base.clone();
        if let Some(flow) = self.streams.get(key) {
            for (i, side) in SIDES.into_iter().enumerate() {
                fold_slot(&mut stats, side, &flow.sides[i]);
            }
        }
        stats
    }

    /// Run the idle-timeout sweep and clean up reassemblers for
    /// ended flows.
    pub fn sweep(&mut self, now: Timestamp) -> Vec<FlowEvent<E::Key>> {
        let mut events = self.sweep_pending(now);
        self.finalize(events.as_mut_slice());
        events
    }

    /// Sweep every remaining flow to its end. Call once after the
    /// last [`track`](Self::track) when input is exhausted. Output is
    /// stamped with the latest packet timestamp seen (never
    /// `Timestamp::MAX`), and the monotonic clock is left alone.
    pub fn finish(&mut self) -> Vec<FlowEvent<E::Key>> {
        let mut events = self.finish_raw();
        self.close_all(&mut events);
        self.finalize(events.as_mut_slice());
        events
    }

    /// Tracker `finish` without flushing, folding or masking.
    pub(crate) fn finish_raw(&mut self) -> Vec<FlowEvent<E::Key>> {
        let evicted_before = self.tracker.stats().flows_evicted;
        let mut events = self.tracker.sweep(Timestamp::MAX);
        if self.emit_anomalies
            && let Some(a) = self.eviction_pressure(evicted_before, self.max_ts)
        {
            events.push(a);
        }
        self.note_gone(events.iter());
        events
    }

    /// Force-end the flow with this key. Returns the resulting
    /// `FlowEvent`s (one `Ended` with
    /// [`crate::EndReason::ForceClosed`]); empty if `key` was not
    /// active.
    pub fn force_close(&mut self, key: &E::Key, now: Timestamp) -> Vec<FlowEvent<E::Key>> {
        let mut events = self.force_close_pending(key, now);
        self.finalize(events.as_mut_slice());
        events
    }

    /// Lower-level [`Self::force_close`] that leaves the flow's
    /// reassemblers in place (flushed) so their last bytes can be
    /// drained; call [`Self::finalize`] afterwards.
    pub fn force_close_pending(&mut self, key: &E::Key, now: Timestamp) -> Vec<FlowEvent<E::Key>> {
        let mut events = self.force_close_raw(key, now);
        self.close_all(&mut events);
        events
    }

    pub(crate) fn force_close_raw(
        &mut self,
        key: &E::Key,
        now: Timestamp,
    ) -> Vec<FlowEvent<E::Key>> {
        let now = self.clamp_now(now);
        let Some(ended) = self.tracker.force_close(key, now) else {
            return Vec::new();
        };
        self.seen_gone += 1;
        vec![ended]
    }

    /// Lower-level sweep variant. Like [`Self::sweep`] but does NOT
    /// finalize ended flows' reassemblers. See [`Self::track_pending`]
    /// for the contract.
    ///
    /// Before idling flows out, every live reassembler gets
    /// [`Reassembler::advance_time`] so holes past their deadline are
    /// skipped even on a side that went quiet (the released bytes
    /// wait in the reassembler for [`Self::drain_stream`]).
    pub fn sweep_pending(&mut self, now: Timestamp) -> Vec<FlowEvent<E::Key>> {
        let now = self.clamp_now(now);
        let mut events = Vec::new();
        self.advance_streams(now, None, |r| events.extend(r.anomalies.drain(..)));
        events.extend(self.sweep_raw(now));
        self.close_all(&mut events);
        events
    }

    /// [`Self::sweep_pending`] that also hands over the bytes the
    /// sweep released: holes past their deadline are skipped by
    /// [`Reassembler::advance_time`], and the data waiting behind them
    /// (with the [`Chunk::Gap`](crate::Chunk::Gap) marking the hole) is
    /// drained into `buf` and passed to `f(key, side, buf)` — once per
    /// side with output, `buf` cleared before each. Without it, a side
    /// that went quiet behind a hole only delivers at its next packet
    /// or at flow end.
    ///
    /// Anomalies of the advanced sides are returned with the events
    /// (after the data `f` already saw). Same contract as
    /// [`Self::sweep_pending`]: call [`Self::finalize`] next.
    pub fn sweep_pending_drain<G>(
        &mut self,
        now: Timestamp,
        buf: &mut StreamChunks,
        mut f: G,
    ) -> Vec<FlowEvent<E::Key>>
    where
        G: FnMut(&E::Key, FlowSide, &mut StreamChunks),
    {
        let now = self.clamp_now(now);
        let mut events = Vec::new();
        self.advance_streams(now, Some(buf), |r| {
            events.extend(r.anomalies.drain(..));
            if let Some(data) = r.data.as_deref_mut()
                && !data.is_empty()
            {
                f(r.key, r.side, data);
            }
        });
        events.extend(self.sweep_raw(now));
        self.close_all(&mut events);
        events
    }

    /// Give every live reassembler of a still-tracked flow
    /// `advance_time(now)`. For each side that produced anomalies or
    /// (with `drain`) released output, `f` gets a [`Released`] —
    /// the side's anomalies and drained output together, so a caller
    /// can deliver them in order.
    pub(crate) fn advance_streams<G>(
        &mut self,
        now: Timestamp,
        mut drain: Option<&mut StreamChunks>,
        mut f: G,
    ) where
        G: FnMut(&mut Released<'_, E::Key>),
    {
        self.reconcile();
        let emit = self.emit_anomalies;
        let mut anomalies = SmallAnoms::new();
        for (key, flow) in self.streams.iter_mut() {
            let Some(entry) = self.tracker.get(key) else {
                continue;
            };
            let initiator = entry.initiator_orientation();
            for (i, side) in SIDES.into_iter().enumerate() {
                let SideSlot::Live(l) = &mut flow.sides[i] else {
                    continue;
                };
                let before = emit.then(|| Counters::of(&l.r));
                l.r.advance_time(now);
                if let Some(before) = before {
                    self.kinds.clear();
                    before.diff(&l.r, side, &mut self.kinds);
                    anomalies.extend(self.kinds.drain(..).map(|kind| {
                        crate::obs::record_anomaly(&kind);
                        crate::obs::trace_anomaly(&kind);
                        FlowEvent::FlowAnomaly {
                            key: key.clone(),
                            kind,
                            ts: now,
                        }
                    }));
                }
                let data = match drain.as_deref_mut() {
                    Some(buf) => {
                        buf.clear();
                        l.r.drain_into(buf);
                        resync(&mut self.global_memcap_bytes, l);
                        Some(buf)
                    }
                    None => None,
                };
                if anomalies.is_empty() && data.as_ref().is_none_or(|d| d.is_empty()) {
                    continue;
                }
                let mut released = Released {
                    key,
                    side,
                    orientation: match side {
                        FlowSide::Initiator => initiator,
                        FlowSide::Responder => initiator.flipped(),
                    },
                    ports: flow.ports,
                    anomalies: &mut anomalies,
                    data,
                };
                f(&mut released);
                anomalies.clear();
            }
        }
    }

    /// The tracker's idle sweep (driver-owned: every `Ended`),
    /// without flushing, folding or masking.
    pub(crate) fn sweep_raw(&mut self, now: Timestamp) -> Vec<FlowEvent<E::Key>> {
        let evicted_before = self.tracker.stats().flows_evicted;
        let mut events = self.tracker.sweep(now);
        if self.emit_anomalies
            && let Some(a) = self.eviction_pressure(evicted_before, now)
        {
            events.push(a);
        }
        self.note_gone(events.iter());
        events
    }

    /// Whether an auto-sweep ([`FlowTrackerConfig::auto_sweep_interval`])
    /// is due at `ts`.
    #[cfg_attr(
        not(all(feature = "session", feature = "extractors")),
        allow(dead_code)
    )]
    pub(crate) fn auto_sweep_due(&self, ts: Timestamp) -> bool {
        self.tracker.auto_sweep_due(ts)
    }

    /// Drop stream state of flows the tracker no longer holds, when
    /// the tracker was driven directly ([`Self::tracker_mut`]).
    fn reconcile(&mut self) {
        let gone = self.tracker.stats().flows_ended + self.tracker.forgotten();
        if gone == self.seen_gone {
            return;
        }
        self.seen_gone = gone;
        let tracker = &self.tracker;
        let global = &mut self.global_memcap_bytes;
        self.streams.retain(|key, flow| {
            if tracker.get(key).is_some() {
                return true;
            }
            for slot in &flow.sides {
                if let SideSlot::Live(l) = slot {
                    *global = global.saturating_sub(l.accounted);
                }
            }
            false
        });
    }

    /// Drop the reassemblers of every flow that ended in `events`
    /// (calling `fin` / `rst` on the way out) and refund their bytes
    /// to the memcap pool. Called automatically by [`Self::track`] /
    /// [`Self::sweep`]; callers of the `*_pending` variants must call
    /// it before the next `track*` / `sweep*` call.
    pub fn finalize(&mut self, events: &mut [FlowEvent<E::Key>]) {
        for ev in events.iter() {
            if let FlowEvent::Ended { key, reason, .. } = ev {
                self.finalize_flow(key, *reason);
            }
        }
    }

    /// [`Self::finalize`] for one ended flow: drop its reassemblers
    /// (`fin` for a graceful `reason`, `rst` otherwise) and refund
    /// their bytes to the memcap pool. No-op for unknown keys.
    pub fn finalize_flow(&mut self, key: &E::Key, reason: crate::EndReason) {
        if let Some(flow) = self.streams.remove(key) {
            for slot in flow.sides {
                if let SideSlot::Live(mut l) = slot {
                    self.global_memcap_bytes = self.global_memcap_bytes.saturating_sub(l.accounted);
                    if reason.is_graceful() {
                        l.r.fin();
                    } else {
                        l.r.rst();
                    }
                }
            }
        }
    }

    /// The packet most recently accepted by `track*` — `None` before
    /// the first packet, and after a packet that was deduplicated or
    /// matched no flow.
    pub fn last_packet(&self) -> Option<&PacketInfo<E::Key>> {
        self.last_packet.as_ref()
    }

    /// Running total of bytes currently buffered across every live
    /// reassembler (issue #26) — what the tracker-wide memcap is
    /// compared against.
    pub fn reassembly_memcap_bytes(&self) -> u64 {
        self.global_memcap_bytes
    }

    /// Ports of the packet that created a flow's stream state.
    #[cfg_attr(
        not(all(feature = "session", feature = "extractors")),
        allow(dead_code)
    )]
    pub(crate) fn stream_ports(&self, key: &E::Key) -> Option<(u16, u16)> {
        self.streams.get(key).and_then(|f| f.ports)
    }

    /// Flows with stream state (live or tombstoned sides).
    pub fn stream_count(&self) -> usize {
        self.streams.len()
    }

    /// Borrow the per-(flow, side) reassembler. `None` when no
    /// reassembler exists (no TCP payload seen on that side, the
    /// side was discarded / released, or the flow ended and was
    /// finalized).
    pub fn reassembler(&mut self, key: &E::Key, side: FlowSide) -> Option<&mut F::Reassembler> {
        match self.streams.get_mut(key)?.sides.get_mut(idx(side))? {
            SideSlot::Live(l) => Some(&mut l.r),
            _ => None,
        }
    }

    /// Move the reassembled output of one flow side (bytes, gaps,
    /// stop) onto the end of `out` — see [`Reassembler::drain_into`].
    /// A side stopped by the memcap reports its stop once. Returns
    /// `false` when there is nothing to report for the side. The
    /// memcap pool is re-synced immediately.
    pub fn drain_stream(&mut self, key: &E::Key, side: FlowSide, out: &mut StreamChunks) -> bool {
        let Some(flow) = self.streams.get_mut(key) else {
            return false;
        };
        match &mut flow.sides[idx(side)] {
            SideSlot::Empty => false,
            SideSlot::Live(l) => {
                l.r.drain_into(out);
                let current = l.r.current_bytes();
                self.global_memcap_bytes = self
                    .global_memcap_bytes
                    .saturating_sub(l.accounted)
                    .saturating_add(current);
                l.accounted = current;
                true
            }
            SideSlot::Done { stop, reported, .. } => {
                if *reported {
                    return false;
                }
                *reported = true;
                if let Some(stop) = stop {
                    out.set_stop(*stop);
                }
                true
            }
        }
    }

    /// Stop reassembling a flow because no consumer needs its bytes
    /// any more (e.g. every parser on it has closed). Both sides drop
    /// their reassembler — including a side that has not sent data
    /// yet — and later segments are ignored. Unlike a reassembly
    /// *stop*, this is not reported anywhere: it is the consumer's
    /// decision. Final counters are kept for the flow's stats.
    pub fn discard_stream(&mut self, key: &E::Key) {
        for side in SIDES {
            self.discard_side(key, side);
        }
    }

    /// [`Self::discard_stream`] for one side.
    pub fn discard_side(&mut self, key: &E::Key, side: FlowSide) {
        let flow = self
            .streams
            .entry(key.clone())
            .or_insert_with(|| StreamFlow::new(None));
        let slot = &mut flow.sides[idx(side)];
        if let SideSlot::Done { reported, .. } = slot {
            *reported = true;
            return;
        }
        let refund = tombstone(slot, None);
        if let SideSlot::Done { reported, .. } = slot {
            // A real stop the reassembler had stays in the stats, but
            // the consumer that discarded the side needs no report.
            *reported = true;
        }
        self.global_memcap_bytes = self.global_memcap_bytes.saturating_sub(refund);
    }

    /// Borrow the inner tracker (for stats, introspection).
    pub fn tracker(&self) -> &FlowTracker<E, S> {
        &self.tracker
    }

    /// Borrow the inner tracker mutably. Prefer the driver's own
    /// methods: only [`Self::set_config`] keeps the reassembler
    /// factory in sync, and flows ended or forgotten directly on the
    /// tracker skip the driver's end-of-flow flush (their stream
    /// state is dropped at the next sweep).
    pub fn tracker_mut(&mut self) -> &mut FlowTracker<E, S> {
        &mut self.tracker
    }

    /// True when anomaly emission is on.
    pub fn emits_anomalies(&self) -> bool {
        self.emit_anomalies
    }

    /// Iterate `(key, FlowStats)` for every live flow, combining the
    /// tracker's per-flow stats with **live** reassembler diagnostics
    /// (gaps, late / stray drops, oversize drops, peak watermark,
    /// retransmits, stop) so consumers get an up-to-date picture
    /// mid-flow. Lazy; each item clones the stats.
    pub fn snapshot_flow_stats(&self) -> impl Iterator<Item = (E::Key, FlowStats)> + '_ {
        self.tracker
            .flows()
            .map(move |(key, entry)| (key.clone(), self.live_stats(key, &entry.stats)))
    }

    /// Live stats of one flow (see [`Self::snapshot_flow_stats`]).
    pub fn flow_stats(&self, key: &E::Key) -> Option<FlowStats> {
        let entry = self.tracker.get(key)?;
        Some(self.live_stats(key, &entry.stats))
    }
}

pub(crate) type SmallAnoms<K> = smallvec::SmallVec<[FlowEvent<K>; 2]>;

/// One side's output of a sweep ([`FlowDriver::advance_streams`]).
#[cfg_attr(
    not(all(feature = "session", feature = "extractors")),
    allow(dead_code)
)]
pub(crate) struct Released<'a, K> {
    pub(crate) key: &'a K,
    pub(crate) side: FlowSide,
    pub(crate) orientation: Orientation,
    pub(crate) ports: Option<(u16, u16)>,
    /// Anomalies of this side (deliver before `data`).
    pub(crate) anomalies: &'a mut SmallAnoms<K>,
    /// Drained output, when draining.
    pub(crate) data: Option<&'a mut StreamChunks>,
}

fn tracker_anomaly<K>(kind: AnomalyKind, ts: Timestamp) -> FlowEvent<K> {
    crate::obs::record_anomaly(&kind);
    crate::obs::trace_anomaly(&kind);
    FlowEvent::TrackerAnomaly { kind, ts }
}

/// Settings [`feed_tcp`] reads.
#[derive(Clone, Copy)]
struct TcpFeed {
    passthrough: bool,
    emit_anomalies: bool,
    memcap_cap: Option<u64>,
    memcap_policy: MemcapPolicy,
}

/// Feed one TCP packet to its flow's stream state. Returns the
/// passthrough skip when the payload was let through.
#[allow(clippy::too_many_arguments)]
fn feed_tcp<K, F, W>(
    p: &PacketContext<'_, K>,
    tcp: &TcpInfo,
    want: &mut W,
    factory: &mut F,
    streams: &mut HashMap<K, StreamFlow<F::Reassembler>, RandomState>,
    global: &mut u64,
    cfg: TcpFeed,
    memcap_tripped: &mut Option<u64>,
    anomalies: &mut Vec<(K, AnomalyKind)>,
    kinds: &mut Vec<AnomalyKind>,
) -> Option<usize>
where
    K: std::hash::Hash + Eq + Clone,
    F: ReassemblerFactory<K>,
    W: FnMut(&PacketContext<'_, K>) -> bool,
{
    let flags = tcp.flags;
    let syn = flags.contains(TcpFlags::SYN);
    // A SYN's own data (TCP Fast Open) starts one past its sequence
    // number; an RST's payload is diagnostic text, not stream data.
    let data_seq = if syn {
        tcp.seq.wrapping_add(1)
    } else {
        tcp.seq
    };
    let payload: &[u8] = if flags.contains(TcpFlags::RST) {
        &[]
    } else {
        p.tcp_payload
    };
    let flow = match streams.get_mut(p.key) {
        Some(f) => f,
        None => {
            if !(syn || !payload.is_empty()) || !want(p) {
                return None;
            }
            streams
                .entry(p.key.clone())
                .or_insert_with(|| StreamFlow::new(p.ports))
        }
    };
    let si = idx(p.side);
    let pi = 1 - si;
    if syn {
        flow.origin[si] = Some(data_seq);
    }

    // The peer's ACK tells the other direction's reassembler which
    // of its bytes were delivered.
    if flags.contains(TcpFlags::ACK)
        && let SideSlot::Live(l) = &mut flow.sides[pi]
    {
        let before = cfg.emit_anomalies.then(|| Counters::of(&l.r));
        l.r.peer_ack(tcp.ack, p.ts);
        resync(global, l);
        if let Some(before) = before {
            kinds.clear();
            before.diff(&l.r, p.side.opposite(), kinds);
            anomalies.extend(kinds.drain(..).map(|k| (p.key.clone(), k)));
        }
    }

    let fin_end = flags
        .contains(TcpFlags::FIN)
        .then(|| data_seq.wrapping_add(payload.len() as u32));
    if payload.is_empty() {
        if let (Some(end), SideSlot::Live(l)) = (fin_end, &mut flow.sides[si]) {
            l.r.fin_seen(end, p.ts);
            resync(global, l);
        }
        return None;
    }

    if matches!(flow.sides[si], SideSlot::Empty) {
        let mut r = factory.new_reassembler(p.key, p.side);
        if let Some(origin) = flow.origin[si] {
            r.set_origin(origin);
        }
        flow.sides[si] = SideSlot::Live(Box::new(Live { r, accounted: 0 }));
    }
    let SideSlot::Live(l) = &mut flow.sides[si] else {
        // Discarded or released: later segments are ignored.
        return None;
    };

    // Re-sync this side's pool contribution: a consumer may have
    // drained it since the last segment (issue #186).
    resync(global, l);

    // `DropPacket` is the one policy that refuses a segment, so it
    // decides before handing it over.
    if cfg.memcap_policy == MemcapPolicy::DropPacket
        && cfg
            .memcap_cap
            .is_some_and(|cap| global.saturating_add(payload.len() as u64) > cap)
    {
        memcap_tripped.get_or_insert(*global);
        return None;
    }

    let before = cfg.emit_anomalies.then(|| Counters::of(&l.r));
    let outcome = if cfg.passthrough {
        l.r.segment_into(data_seq, payload, p.ts)
    } else {
        l.r.segment(data_seq, payload, p.ts);
        SegmentOutcome::Buffered
    };
    if let Some(end) = fin_end {
        l.r.fin_seen(end, p.ts);
    }
    resync(global, l);
    if let Some(before) = before {
        kinds.clear();
        before.diff(&l.r, p.side, kinds);
        anomalies.extend(kinds.drain(..).map(|k| (p.key.clone(), k)));
    }
    let pass = match outcome {
        SegmentOutcome::Passthrough { skip } => Some(skip),
        SegmentOutcome::Buffered => None,
    };

    if let Some(cap) = cfg.memcap_cap
        && *global > cap
    {
        memcap_tripped.get_or_insert(*global);
        match cfg.memcap_policy {
            MemcapPolicy::Ignore | MemcapPolicy::DropPacket => {}
            MemcapPolicy::PassThrough | MemcapPolicy::DropFlow => {
                // Drop the reassembler (whatever its `release` does):
                // the memory is freed and the side reports the stop.
                let refund = tombstone(&mut flow.sides[si], Some(ReassemblyStop::Memcap));
                *global = global.saturating_sub(refund);
                if cfg.memcap_policy == MemcapPolicy::DropFlow {
                    let refund = tombstone(&mut flow.sides[pi], Some(ReassemblyStop::Memcap));
                    *global = global.saturating_sub(refund);
                }
            }
        }
    }
    pass
}

fn resync<R: Reassembler>(global: &mut u64, l: &mut Live<R>) {
    let current = l.r.current_bytes();
    *global = global.saturating_sub(l.accounted).saturating_add(current);
    l.accounted = current;
}

/// The two event containers the driver produces (`FlowEvents` for
/// `track`, `Vec` for `sweep`), for helpers that edit them in place.
trait EventBuf<K> {
    fn len(&self) -> usize;
    fn get_mut(&mut self, i: usize) -> &mut FlowEvent<K>;
    fn insert(&mut self, i: usize, ev: FlowEvent<K>);
    fn remove(&mut self, i: usize) -> FlowEvent<K>;
}

impl<K> EventBuf<K> for Vec<FlowEvent<K>> {
    fn len(&self) -> usize {
        Vec::len(self)
    }
    fn get_mut(&mut self, i: usize) -> &mut FlowEvent<K> {
        &mut self[i]
    }
    fn insert(&mut self, i: usize, ev: FlowEvent<K>) {
        Vec::insert(self, i, ev);
    }
    fn remove(&mut self, i: usize) -> FlowEvent<K> {
        Vec::remove(self, i)
    }
}

impl<K> EventBuf<K> for FlowEvents<K> {
    fn len(&self) -> usize {
        smallvec::SmallVec::len(self)
    }
    fn get_mut(&mut self, i: usize) -> &mut FlowEvent<K> {
        &mut self[i]
    }
    fn insert(&mut self, i: usize, ev: FlowEvent<K>) {
        smallvec::SmallVec::insert(self, i, ev);
    }
    fn remove(&mut self, i: usize) -> FlowEvent<K> {
        smallvec::SmallVec::remove(self, i)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::FiveTuple;
    use crate::extract::parse::test_frames::*;
    use crate::reassembler::{BufferedReassembler, BufferedReassemblerFactory};
    use crate::{EndReason, FlowEvent, Timestamp};

    fn view(frame: &[u8], sec: u32) -> PacketView<'_> {
        PacketView::new(frame, Timestamp::new(sec, 0))
    }

    /// Plan 32 regression guard: `FlowDriver::new` must be fully
    /// inferable — no turbofish, no `let` type annotation. Plan 38
    /// restored the `S = ()` parameter via a split-ctor design; this
    /// guard still passes because the `new` ctor lives on the pinned
    /// `impl<E, F> FlowDriver<E, F, ()>` block.
    #[test]
    fn new_needs_no_type_annotation() {
        let mut d = FlowDriver::new(
            FiveTuple::bidirectional(),
            BufferedReassemblerFactory::default(),
        );
        let _ = d.track(view(b"", 0));
    }

    /// Plan 38: `FlowDriver::with_state_init` carries `S` through
    /// to the inner tracker.
    #[test]
    fn with_state_init_threads_s() {
        #[derive(Debug, PartialEq)]
        struct MyState(u64);
        let mut d: FlowDriver<_, _, MyState> = FlowDriver::with_state_init(
            FiveTuple::bidirectional(),
            BufferedReassemblerFactory::default(),
            |_key| MyState(7),
        );
        let _ = d.track(view(b"", 0));
        // tracker() returns &FlowTracker<E, MyState>, not <E, ()>.
        let tracker: &crate::FlowTracker<FiveTuple, MyState> = d.tracker();
        // Read the inner value through the typed accessor so the
        // field isn't dead code.
        let states: Vec<u64> = tracker.iter_active().map(|f| f.user.0).collect();
        let _ = states;
    }

    /// Plan 38: `with_state` works for any `S: Default`.
    #[test]
    fn with_state_uses_default() {
        #[derive(Debug, Default)]
        struct Counter(u32);
        let d: FlowDriver<_, _, Counter> = FlowDriver::with_state(
            FiveTuple::bidirectional(),
            BufferedReassemblerFactory::default(),
        );
        let tracker: &crate::FlowTracker<FiveTuple, Counter> = d.tracker();
        let counts: Vec<u32> = tracker.iter_active().map(|f| f.user.0).collect();
        let _ = counts;
    }

    /// Plan 33: `finish()` ends every still-open flow, and a second
    /// `finish()` is a no-op.
    #[test]
    fn finish_sweeps_open_flows() {
        let mut d = FlowDriver::new(
            FiveTuple::bidirectional(),
            BufferedReassemblerFactory::default(),
        );
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
        d.track(view(&syn, 0));
        let ended = d
            .finish()
            .into_iter()
            .filter(|e| matches!(e, FlowEvent::Ended { .. }))
            .count();
        assert_eq!(ended, 1, "finish() must end the open flow");
        assert!(d.finish().is_empty(), "second finish() yields nothing");
    }

    #[test]
    fn buffered_reassembly_in_order() {
        let mut d = FlowDriver::<_, _>::new(
            FiveTuple::bidirectional(),
            BufferedReassemblerFactory::default(),
        );
        // SYN, SYN-ACK, ACK
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
        let synack = ipv4_tcp(
            [0; 6],
            [0; 6],
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            80,
            1234,
            5000,
            1001,
            0x12,
            b"",
        );
        let ack = ipv4_tcp(
            [0; 6],
            [0; 6],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            1001,
            5001,
            0x10,
            b"",
        );
        // Initiator → responder data
        let req = ipv4_tcp(
            [0; 6],
            [0; 6],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            1001,
            5001,
            0x18,
            b"GET / HTTP/1.1\r\n\r\n",
        );
        // Responder → initiator data
        let resp = ipv4_tcp(
            [0; 6],
            [0; 6],
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            80,
            1234,
            5001,
            1019,
            0x18,
            b"HTTP/1.1 200 OK\r\n\r\nbody",
        );

        d.track(view(&syn, 0));
        d.track(view(&synack, 0));
        d.track(view(&ack, 0));
        d.track(view(&req, 0));
        d.track(view(&resp, 0));

        // The reassemblers are inside the driver; we pop them out
        // by ending the flow with FIN.
        let fin = ipv4_tcp(
            [0; 6],
            [0; 6],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            1019,
            5024,
            0x11,
            b"",
        );
        let fin_resp = ipv4_tcp(
            [0; 6],
            [0; 6],
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            80,
            1234,
            5024,
            1020,
            0x11,
            b"",
        );
        let last_ack = ipv4_tcp(
            [0; 6],
            [0; 6],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            1020,
            5025,
            0x10,
            b"",
        );

        let mut all_events = Vec::new();
        all_events.extend(d.track(view(&fin, 0)));
        all_events.extend(d.track(view(&fin_resp, 0)));
        all_events.extend(d.track(view(&last_ack, 0)));

        // Assertion: an Ended event was emitted (FIN/FIN/ACK closed the flow).
        let ended_count = all_events
            .iter()
            .filter(|e| matches!(e, FlowEvent::Ended { .. }))
            .count();
        assert_eq!(ended_count, 1);
    }

    #[test]
    fn no_dispatch_on_empty_payload() {
        // SYN/SYN-ACK have no payload — the reassemblers should not be
        // created. We don't have a direct way to introspect, but we can
        // capture via a test factory.
        struct CountingFactory(std::cell::RefCell<Vec<FlowSide>>);
        impl ReassemblerFactory<crate::extract::FiveTupleKey> for CountingFactory {
            type Reassembler = BufferedReassembler;
            fn new_reassembler(
                &mut self,
                _key: &crate::extract::FiveTupleKey,
                side: FlowSide,
            ) -> BufferedReassembler {
                self.0.borrow_mut().push(side);
                BufferedReassembler::new()
            }
        }
        // SAFETY-style: CountingFactory uses RefCell, not Cell, so shared
        // sequential access is fine inside a single test.
        unsafe impl Send for CountingFactory {}
        unsafe impl Sync for CountingFactory {}

        let factory = CountingFactory(std::cell::RefCell::new(Vec::new()));
        let mut d = FlowDriver::<_, _>::new(FiveTuple::bidirectional(), factory);
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
        d.track(view(&syn, 0));
        // No payload yet → no reassembler instantiated.
        assert!(d.factory.0.borrow().is_empty());
    }

    /// 3WHS + initiator data segment + RST.
    /// Returns the full event vector after the RST.
    fn drive_simple_tcp_with_data<F>(
        driver: &mut FlowDriver<FiveTuple, F>,
    ) -> Vec<FlowEvent<crate::extract::FiveTupleKey>>
    where
        F: ReassemblerFactory<crate::extract::FiveTupleKey>,
    {
        let mac = [0u8; 6];
        let ip_a = [10, 0, 0, 1];
        let ip_b = [10, 0, 0, 2];
        let syn = ipv4_tcp(mac, mac, ip_a, ip_b, 1234, 80, 1000, 0, 0x02, b"");
        let synack = ipv4_tcp(mac, mac, ip_b, ip_a, 80, 1234, 5000, 1001, 0x12, b"");
        let ack = ipv4_tcp(mac, mac, ip_a, ip_b, 1234, 80, 1001, 5001, 0x10, b"");
        // 200 bytes initiator data
        let payload = vec![b'A'; 200];
        let data = ipv4_tcp(mac, mac, ip_a, ip_b, 1234, 80, 1001, 5001, 0x18, &payload);
        // RST
        let rst = ipv4_tcp(mac, mac, ip_a, ip_b, 1234, 80, 1201, 5001, 0x04, b"");

        let mut events = Vec::new();
        for f in [&syn, &synack, &ack, &data, &rst] {
            events.extend(driver.track(view(f, 0)));
        }
        events
    }

    #[test]
    fn ended_event_carries_zero_diagnostics_for_clean_flow() {
        let mut d = FlowDriver::<_, _>::new(
            FiveTuple::bidirectional(),
            BufferedReassemblerFactory::default(),
        );
        let events = drive_simple_tcp_with_data(&mut d);
        let ended = events
            .into_iter()
            .find_map(|e| match e {
                FlowEvent::Ended { stats, .. } => Some(stats),
                _ => None,
            })
            .expect("one Ended event");
        assert_eq!(ended.reassembly_dropped_ooo_initiator, 0);
        assert_eq!(ended.reassembly_dropped_ooo_responder, 0);
        assert_eq!(ended.reassembly_bytes_dropped_oversize_initiator, 0);
        assert_eq!(ended.reassembly_bytes_dropped_oversize_responder, 0);
    }

    /// Pre-0.25 a DropFlow overflow synthesised `Ended {
    /// BufferOverflow }` and forgot the flow, so its next packet
    /// started a *new* flow mid-stream. Now the flow stays tracked
    /// until its transport end and the stop is recorded in its stats.
    #[test]
    fn drop_flow_overflow_stops_reassembly_but_keeps_the_flow() {
        let factory = BufferedReassemblerFactory::default()
            .with_max_buffer(64)
            .with_overflow_policy(crate::OverflowPolicy::DropFlow);
        let mut d = FlowDriver::<_, _>::new(FiveTuple::bidirectional(), factory);
        let events = drive_simple_tcp_with_data(&mut d);
        let started = events
            .iter()
            .filter(|e| matches!(e, FlowEvent::Started { .. }))
            .count();
        assert_eq!(started, 1, "the flow must not be re-created");
        let ended: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                FlowEvent::Ended { reason, stats, .. } => Some((*reason, stats.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(ended.len(), 1);
        let (reason, stats) = &ended[0];
        assert_eq!(
            *reason,
            EndReason::Rst,
            "the transport reason, not BufferOverflow"
        );
        assert_eq!(stats.reassembly_bytes_dropped_oversize_initiator, 200);
        assert_eq!(
            stats.reassembly_stop_initiator,
            Some(crate::ReassemblyStop::Overflow)
        );
    }

    #[test]
    fn anomaly_event_emitted_for_buffer_overflow_sliding_window() {
        let factory = BufferedReassemblerFactory::default().with_max_buffer(64);
        let mut d =
            FlowDriver::<_, _>::new(FiveTuple::bidirectional(), factory).with_emit_anomalies(true);
        let events = drive_simple_tcp_with_data(&mut d);
        let anomalies: Vec<_> = events
            .iter()
            .filter(|e| {
                matches!(
                    e,
                    FlowEvent::FlowAnomaly {
                        kind: AnomalyKind::BufferOverflow { .. },
                        ..
                    }
                )
            })
            .collect();
        assert_eq!(
            anomalies.len(),
            1,
            "expected exactly one BufferOverflow anomaly"
        );
        match anomalies[0] {
            FlowEvent::FlowAnomaly {
                kind:
                    AnomalyKind::BufferOverflow {
                        side,
                        bytes,
                        policy,
                    },
                ..
            } => {
                assert_eq!(*side, FlowSide::Initiator);
                assert_eq!(*bytes, 136);
                assert_eq!(*policy, OverflowPolicy::SlidingWindow);
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn no_anomaly_events_when_flag_off() {
        let factory = BufferedReassemblerFactory::default().with_max_buffer(64);
        let mut d = FlowDriver::<_, _>::new(FiveTuple::bidirectional(), factory);
        let events = drive_simple_tcp_with_data(&mut d);
        assert!(
            !events.iter().any(|e| e.anomaly_kind().is_some()),
            "expected no anomaly events when emit_anomalies is off"
        );
    }

    #[test]
    fn anomaly_event_for_buffer_overflow_drop_flow_carries_policy() {
        let factory = BufferedReassemblerFactory::default()
            .with_max_buffer(64)
            .with_overflow_policy(OverflowPolicy::DropFlow);
        let mut d =
            FlowDriver::<_, _>::new(FiveTuple::bidirectional(), factory).with_emit_anomalies(true);
        let events = drive_simple_tcp_with_data(&mut d);
        let anomaly = events
            .iter()
            .find(|e| {
                matches!(
                    e,
                    FlowEvent::FlowAnomaly {
                        kind: AnomalyKind::BufferOverflow { .. },
                        ..
                    }
                )
            })
            .expect("expected a BufferOverflow anomaly");
        match anomaly {
            FlowEvent::FlowAnomaly {
                kind: AnomalyKind::BufferOverflow { policy, .. },
                ..
            } => {
                assert_eq!(*policy, OverflowPolicy::DropFlow);
            }
            _ => unreachable!(),
        }
    }

    /// Plan 44: the `ReassemblerHighWatermark` anomaly fires from
    /// the driver when occupancy crosses the configured threshold.
    #[test]
    fn anomaly_event_for_reassembler_high_watermark() {
        // Cap=128, threshold=50% → fires at 64 bytes occupancy.
        let factory = BufferedReassemblerFactory::default()
            .with_max_buffer(128)
            .with_high_watermark_threshold(50);
        let mut d =
            FlowDriver::<_, _>::new(FiveTuple::bidirectional(), factory).with_emit_anomalies(true);
        let events = drive_simple_tcp_with_data(&mut d);
        let crossing = events.iter().find(|e| {
            matches!(
                e,
                FlowEvent::FlowAnomaly {
                    kind: AnomalyKind::ReassemblerHighWatermark { .. },
                    ..
                }
            )
        });
        let crossing = crossing.expect("expected a ReassemblerHighWatermark anomaly");
        match crossing {
            FlowEvent::FlowAnomaly {
                kind:
                    AnomalyKind::ReassemblerHighWatermark {
                        bytes,
                        cap,
                        threshold_pct,
                        ..
                    },
                ..
            } => {
                assert_eq!(*cap, 128);
                assert_eq!(*threshold_pct, 50);
                assert!(*bytes >= 64, "occupancy at crossing was {bytes}, want ≥64");
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn anomaly_event_emitted_for_table_eviction() {
        // max_flows = 2; create three distinct flows in-order.
        let config = FlowTrackerConfig {
            max_flows: 2,
            ..FlowTrackerConfig::default()
        };
        let mut d = FlowDriver::<_, _>::with_config(
            FiveTuple::bidirectional(),
            BufferedReassemblerFactory::default(),
            config,
        )
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
        let pressure: Vec<_> = events
            .iter()
            .filter(|e| {
                matches!(
                    e,
                    FlowEvent::TrackerAnomaly {
                        kind: AnomalyKind::FlowTableEvictionPressure { .. },
                        ..
                    }
                )
            })
            .collect();
        assert_eq!(pressure.len(), 1, "expected one eviction-pressure anomaly");
        match pressure[0] {
            FlowEvent::TrackerAnomaly {
                kind:
                    AnomalyKind::FlowTableEvictionPressure {
                        evicted_in_tick,
                        evicted_total,
                    },
                ..
            } => {
                assert_eq!(*evicted_in_tick, 1);
                assert_eq!(*evicted_total, 1);
                // TrackerAnomaly carries no key — its absence in the
                // destructure pattern is the assertion.
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn ended_event_carries_high_watermark() {
        let mut d = FlowDriver::<_, _>::new(
            FiveTuple::bidirectional(),
            BufferedReassemblerFactory::default(),
        );
        let events = drive_simple_tcp_with_data(&mut d);
        let ended = events
            .into_iter()
            .find_map(|e| match e {
                FlowEvent::Ended { stats, .. } => Some(stats),
                _ => None,
            })
            .expect("Ended");
        assert_eq!(ended.reassembler_high_watermark_initiator, 200);
        assert_eq!(ended.reassembler_high_watermark_responder, 0);
    }

    #[test]
    fn snapshot_flow_stats_returns_live_diagnostics_mid_flow() {
        let factory = BufferedReassemblerFactory::default().with_max_buffer(64);
        let mut d = FlowDriver::<_, _>::new(FiveTuple::bidirectional(), factory);
        // 3WHS + 200B initiator data — flow still alive.
        let mac = [0u8; 6];
        let frames = [
            ipv4_tcp(
                mac,
                mac,
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                1234,
                80,
                1000,
                0,
                0x02,
                b"",
            ),
            ipv4_tcp(
                mac,
                mac,
                [10, 0, 0, 2],
                [10, 0, 0, 1],
                80,
                1234,
                5000,
                1001,
                0x12,
                b"",
            ),
            ipv4_tcp(
                mac,
                mac,
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                1234,
                80,
                1001,
                5001,
                0x10,
                b"",
            ),
            ipv4_tcp(
                mac,
                mac,
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                1234,
                80,
                1001,
                5001,
                0x18,
                &[b'A'; 200],
            ),
        ];
        for f in &frames {
            d.track(view(f, 0));
        }
        let snapshot: Vec<_> = d.snapshot_flow_stats().collect();
        assert_eq!(snapshot.len(), 1, "flow still alive");
        let (_key, stats) = &snapshot[0];
        // sliding-window cap 64: post-rotation peak is 64
        assert_eq!(stats.reassembler_high_watermark_initiator, 64);
        // 200 - 64 = 136 dropped
        assert_eq!(stats.reassembly_bytes_dropped_oversize_initiator, 136);
    }

    #[test]
    fn snapshot_flow_stats_is_lazy() {
        let mut d = FlowDriver::<_, _>::new(
            FiveTuple::bidirectional(),
            BufferedReassemblerFactory::default(),
        );
        let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"x");
        d.track(view(&f, 0));
        let mut iter = d.snapshot_flow_stats();
        let first = iter.next();
        assert!(first.is_some());
        // Dropping the iterator without consuming it should not panic
        // or do unnecessary work.
        drop(iter);
    }

    #[test]
    fn dedup_filters_duplicate_packets() {
        use crate::Dedup;
        let mut d = FlowDriver::<_, _>::new(
            FiveTuple::bidirectional(),
            BufferedReassemblerFactory::default(),
        )
        .with_dedup(Dedup::loopback());
        let frame = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"x");
        let evs1 = d.track(view(&frame, 0));
        // Same frame 100 µs later (well within 1 ms window).
        let evs2 = d.track(PacketView::new(&frame, Timestamp::new(0, 100_000)));
        assert!(!evs1.is_empty(), "first copy generates events");
        assert!(evs2.is_empty(), "second copy is silently dropped");
        assert_eq!(d.dedup().unwrap().dropped(), 1);
    }

    #[test]
    fn driver_without_dedup_processes_both_copies() {
        let mut d = FlowDriver::<_, _>::new(
            FiveTuple::bidirectional(),
            BufferedReassemblerFactory::default(),
        );
        let frame = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"x");
        let evs1 = d.track(view(&frame, 0));
        let evs2 = d.track(PacketView::new(&frame, Timestamp::new(0, 100_000)));
        assert!(!evs1.is_empty());
        assert!(!evs2.is_empty(), "no dedup → both copies fully processed");
    }

    #[test]
    fn raw_timestamps_flow_through_by_default() {
        let mut d = FlowDriver::<_, _>::new(
            FiveTuple::bidirectional(),
            BufferedReassemblerFactory::default(),
        );
        let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"x");
        let _ = d.track(PacketView::new(&f, Timestamp::new(10, 0)));
        let evs2 = d.track(PacketView::new(&f, Timestamp::new(5, 0)));
        let ts2 = evs2
            .iter()
            .find_map(|e| match e {
                FlowEvent::Packet { ts, .. } => Some(*ts),
                _ => None,
            })
            .expect("Packet event");
        assert_eq!(ts2, Timestamp::new(5, 0), "raw ts preserved by default");
    }

    #[test]
    fn monotonic_timestamps_clamp_backwards_jumps() {
        let mut d = FlowDriver::<_, _>::new(
            FiveTuple::bidirectional(),
            BufferedReassemblerFactory::default(),
        )
        .with_monotonic_timestamps(true);
        let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"x");
        let _ = d.track(PacketView::new(&f, Timestamp::new(10, 0)));
        let evs2 = d.track(PacketView::new(&f, Timestamp::new(5, 0)));
        let ts2 = evs2
            .iter()
            .find_map(|e| match e {
                FlowEvent::Packet { ts, .. } => Some(*ts),
                _ => None,
            })
            .expect("Packet event");
        assert_eq!(ts2, Timestamp::new(10, 0), "backwards jump clamped");
    }

    #[test]
    fn monotonic_timestamps_forward_jumps_pass_through() {
        let mut d = FlowDriver::<_, _>::new(
            FiveTuple::bidirectional(),
            BufferedReassemblerFactory::default(),
        )
        .with_monotonic_timestamps(true);
        let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"x");
        let _ = d.track(PacketView::new(&f, Timestamp::new(5, 0)));
        let evs2 = d.track(PacketView::new(&f, Timestamp::new(10, 0)));
        let ts2 = evs2
            .iter()
            .find_map(|e| match e {
                FlowEvent::Packet { ts, .. } => Some(*ts),
                _ => None,
            })
            .expect("Packet event");
        assert_eq!(ts2, Timestamp::new(10, 0));
    }

    #[test]
    fn monotonic_timestamps_sweep_clamps_too() {
        let mut d = FlowDriver::<_, _>::new(
            FiveTuple::bidirectional(),
            BufferedReassemblerFactory::default(),
        )
        .with_monotonic_timestamps(true);
        let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"x");
        let _ = d.track(PacketView::new(&f, Timestamp::new(100, 0)));
        // sweep at t=50s (before the last packet). Internally
        // clamped to 100s; flow still alive (UDP idle = 60s).
        let ended = d.sweep(Timestamp::new(50, 0));
        assert_eq!(ended.len(), 0);
    }

    #[test]
    fn sliding_window_overflow_recorded_in_diagnostics() {
        let factory = BufferedReassemblerFactory::default().with_max_buffer(64);
        let mut d = FlowDriver::<_, _>::new(FiveTuple::bidirectional(), factory);
        let events = drive_simple_tcp_with_data(&mut d);
        // SlidingWindow doesn't end the flow early; the RST closes it.
        // Diagnostics still surface the dropped bytes on Ended.
        let ended = events
            .into_iter()
            .find_map(|e| match e {
                FlowEvent::Ended { reason, stats, .. } => Some((reason, stats)),
                _ => None,
            })
            .expect("an Ended event");
        assert_eq!(ended.0, EndReason::Rst);
        // 200 in - 64 cap = 136 dropped.
        assert_eq!(
            ended.1.reassembly_bytes_dropped_oversize_initiator, 136,
            "stats: {:?}",
            ended.1
        );
    }

    /// 3WHS + initiator data + retransmit of the same data + RST.
    /// Drives a single flow where the second data segment is a true
    /// retransmit (`seq + len <= expected_seq`).
    fn drive_tcp_with_retransmit<F>(
        driver: &mut FlowDriver<FiveTuple, F>,
    ) -> Vec<FlowEvent<crate::extract::FiveTupleKey>>
    where
        F: ReassemblerFactory<crate::extract::FiveTupleKey>,
    {
        let mac = [0u8; 6];
        let ip_a = [10, 0, 0, 1];
        let ip_b = [10, 0, 0, 2];
        let syn = ipv4_tcp(mac, mac, ip_a, ip_b, 1234, 80, 1000, 0, 0x02, b"");
        let synack = ipv4_tcp(mac, mac, ip_b, ip_a, 80, 1234, 5000, 1001, 0x12, b"");
        let ack = ipv4_tcp(mac, mac, ip_a, ip_b, 1234, 80, 1001, 5001, 0x10, b"");
        let payload = b"GET / HTTP/1.1\r\n\r\n";
        let data = ipv4_tcp(mac, mac, ip_a, ip_b, 1234, 80, 1001, 5001, 0x18, payload);
        // Retransmit: same seq, same payload.
        let retx = ipv4_tcp(mac, mac, ip_a, ip_b, 1234, 80, 1001, 5001, 0x18, payload);
        let rst = ipv4_tcp(
            mac,
            mac,
            ip_a,
            ip_b,
            1234,
            80,
            1001 + payload.len() as u32,
            5001,
            0x04,
            b"",
        );

        let mut events = Vec::new();
        for (i, f) in [&syn, &synack, &ack, &data, &retx, &rst].iter().enumerate() {
            events.extend(driver.track(view(f, i as u32)));
        }
        events
    }

    #[test]
    fn ended_event_carries_retransmit_count() {
        let mut d = FlowDriver::<_, _>::new(
            FiveTuple::bidirectional(),
            BufferedReassemblerFactory::default(),
        );
        let events = drive_tcp_with_retransmit(&mut d);
        let stats = events
            .into_iter()
            .find_map(|e| match e {
                FlowEvent::Ended { stats, .. } => Some(stats),
                _ => None,
            })
            .expect("an Ended event");
        assert_eq!(stats.retransmits_initiator, 1);
        assert_eq!(stats.retransmits_responder, 0);
    }

    #[test]
    fn retransmit_anomaly_emitted_on_duplicate_segment() {
        let mut d = FlowDriver::<_, _>::new(
            FiveTuple::bidirectional(),
            BufferedReassemblerFactory::default(),
        )
        .with_emit_anomalies(true);
        let events = drive_tcp_with_retransmit(&mut d);
        let anomalies: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                FlowEvent::FlowAnomaly {
                    kind: AnomalyKind::RetransmittedSegment { side, count },
                    ..
                } => Some((*side, *count)),
                _ => None,
            })
            .collect();
        assert_eq!(
            anomalies.len(),
            1,
            "expected exactly one RetransmittedSegment anomaly, got {anomalies:?}"
        );
        assert_eq!(anomalies[0], (FlowSide::Initiator, 1));
    }

    #[test]
    fn no_retransmit_anomaly_for_clean_flow() {
        let mut d = FlowDriver::<_, _>::new(
            FiveTuple::bidirectional(),
            BufferedReassemblerFactory::default(),
        )
        .with_emit_anomalies(true);
        let events = drive_simple_tcp_with_data(&mut d);
        assert!(
            !events.iter().any(|e| matches!(
                e,
                FlowEvent::FlowAnomaly {
                    kind: AnomalyKind::RetransmittedSegment { .. },
                    ..
                }
            )),
            "expected no RetransmittedSegment anomaly on a clean flow"
        );
    }

    #[test]
    fn no_ticks_when_interval_unset() {
        let mut d = FlowDriver::<_, _>::new(
            FiveTuple::bidirectional(),
            BufferedReassemblerFactory::default(),
        );
        let f =
            crate::extract::parse::test_frames::ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"x");
        let events = d.track(view(&f, 0));
        assert!(!events.iter().any(|e| matches!(e, FlowEvent::Tick { .. })));
    }

    #[test]
    fn first_packet_fires_tick_when_enabled() {
        let cfg = FlowTrackerConfig {
            flow_tick_interval: Some(Duration::from_secs(10)),
            ..FlowTrackerConfig::default()
        };
        let mut d = FlowDriver::<_, _>::with_config(
            FiveTuple::bidirectional(),
            BufferedReassemblerFactory::default(),
            cfg,
        );
        let f =
            crate::extract::parse::test_frames::ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"x");
        let events = d.track(view(&f, 0));
        assert!(
            events.iter().any(|e| matches!(e, FlowEvent::Tick { .. })),
            "first packet should emit initial tick, got: {:?}",
            events
        );
    }

    #[test]
    fn tick_suppressed_by_event_mask() {
        // issue #79: EventMask::TICK shed the driver-emitted Tick even
        // though the interval is configured.
        let cfg = FlowTrackerConfig {
            flow_tick_interval: Some(Duration::from_secs(10)),
            suppress_events: EventMask::TICK,
            ..FlowTrackerConfig::default()
        };
        let mut d = FlowDriver::<_, _>::with_config(
            FiveTuple::bidirectional(),
            BufferedReassemblerFactory::default(),
            cfg,
        );
        let f =
            crate::extract::parse::test_frames::ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"x");
        let events = d.track(view(&f, 0));
        assert!(
            !events.iter().any(|e| matches!(e, FlowEvent::Tick { .. })),
            "Tick masked off, got: {events:?}"
        );
        // Flow is still tracked.
        assert_eq!(d.tracker().flow_count(), 1);
    }

    #[test]
    fn pause_via_tracker_mut_sheds_ticks() {
        // issue #79: a runtime pause through tracker_mut() shuts off the
        // driver's Tick emission too.
        let cfg = FlowTrackerConfig {
            flow_tick_interval: Some(Duration::from_secs(10)),
            ..FlowTrackerConfig::default()
        };
        let mut d = FlowDriver::<_, _>::with_config(
            FiveTuple::bidirectional(),
            BufferedReassemblerFactory::default(),
            cfg,
        );
        d.tracker_mut().pause_events();
        let f =
            crate::extract::parse::test_frames::ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"x");
        let events = d.track(view(&f, 0));
        assert!(
            events.is_empty(),
            "paused driver sheds all, got: {events:?}"
        );
        assert_eq!(d.tracker().flow_count(), 1, "accounting continued");
    }

    #[test]
    fn tick_interval_respected() {
        let cfg = FlowTrackerConfig {
            flow_tick_interval: Some(Duration::from_secs(10)),
            ..FlowTrackerConfig::default()
        };
        let mut d = FlowDriver::<_, _>::with_config(
            FiveTuple::bidirectional(),
            BufferedReassemblerFactory::default(),
            cfg,
        );
        let f =
            crate::extract::parse::test_frames::ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"x");
        // First packet at t=0 fires the initial tick.
        let _initial = d.track(view(&f, 0));
        // At t=5s the interval hasn't elapsed.
        let ev_5s = d.track(view(&f, 5));
        // At t=15s it has.
        let ev_15s = d.track(view(&f, 15));
        assert!(
            !ev_5s.iter().any(|e| matches!(e, FlowEvent::Tick { .. })),
            "no tick before interval elapsed"
        );
        assert!(
            ev_15s.iter().any(|e| matches!(e, FlowEvent::Tick { .. })),
            "tick after interval elapsed"
        );
    }

    #[test]
    fn tick_carries_full_stats_including_reassembler_diagnostics() {
        let cfg = FlowTrackerConfig {
            flow_tick_interval: Some(Duration::from_secs(1)),
            ..FlowTrackerConfig::default()
        };
        let factory = BufferedReassemblerFactory::default().with_max_buffer(64);
        let mut d = FlowDriver::<_, _>::with_config(FiveTuple::bidirectional(), factory, cfg);
        let mac = [0u8; 6];
        let ip_a = [10, 0, 0, 1];
        let ip_b = [10, 0, 0, 2];
        let payload = vec![b'A'; 200];
        let frames = [
            ipv4_tcp(mac, mac, ip_a, ip_b, 1234, 80, 1000, 0, 0x02, b""),
            ipv4_tcp(mac, mac, ip_b, ip_a, 80, 1234, 5000, 1001, 0x12, b""),
            ipv4_tcp(mac, mac, ip_a, ip_b, 1234, 80, 1001, 5001, 0x10, b""),
            ipv4_tcp(mac, mac, ip_a, ip_b, 1234, 80, 1001, 5001, 0x18, &payload),
        ];
        let mut last_tick_stats = None;
        for (i, f) in frames.iter().enumerate() {
            for ev in d.track(view(f, i as u32 + 10)) {
                if let FlowEvent::Tick { stats, .. } = ev {
                    last_tick_stats = Some(stats);
                }
            }
        }
        let stats = last_tick_stats.expect("at least one Tick should fire");
        // 200 bytes pushed into a 64-byte cap → 136 dropped via
        // SlidingWindow.
        assert!(
            stats.reassembly_bytes_dropped_oversize_initiator > 0,
            "tick stats should surface oversize bytes, got {:?}",
            stats
        );
    }

    #[test]
    fn snapshot_flow_stats_surfaces_live_retransmits() {
        let mut d = FlowDriver::<_, _>::new(
            FiveTuple::bidirectional(),
            BufferedReassemblerFactory::default(),
        );
        // 3WHS + initiator data + retransmit, but NO RST — flow still live.
        let mac = [0u8; 6];
        let ip_a = [10, 0, 0, 1];
        let ip_b = [10, 0, 0, 2];
        let syn = ipv4_tcp(mac, mac, ip_a, ip_b, 1234, 80, 1000, 0, 0x02, b"");
        let synack = ipv4_tcp(mac, mac, ip_b, ip_a, 80, 1234, 5000, 1001, 0x12, b"");
        let ack = ipv4_tcp(mac, mac, ip_a, ip_b, 1234, 80, 1001, 5001, 0x10, b"");
        let data = ipv4_tcp(mac, mac, ip_a, ip_b, 1234, 80, 1001, 5001, 0x18, b"hi");
        let retx = ipv4_tcp(mac, mac, ip_a, ip_b, 1234, 80, 1001, 5001, 0x18, b"hi");
        for f in [&syn, &synack, &ack, &data, &retx] {
            d.track(view(f, 0));
        }
        let mut found = false;
        for (_k, stats) in d.snapshot_flow_stats() {
            if stats.retransmits_initiator == 1 {
                found = true;
            }
        }
        assert!(found, "live snapshot should surface 1 initiator retransmit");
    }
}

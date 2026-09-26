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

use std::collections::HashMap;
use std::time::Duration;

use ahash::RandomState;

use crate::Timestamp;
use crate::event::{
    AnomalyKind, EventMask, FlowEvent, FlowSide, FlowStats, MemcapPolicy, OverflowPolicy,
    ReassemblyStop,
};
use crate::extractor::{FlowExtractor, L4Meta, L4Proto, Orientation, TcpInfo};
use crate::reassembler::{Reassembler, ReassemblerFactory, StreamChunks};
use crate::tracker::{FlowEvents, FlowTracker, FlowTrackerConfig};
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
}

/// Per-reassembler diagnostic counters, captured before a segment is
/// fed (or a sweep runs) and diffed afterwards into anomaly events.
#[derive(Clone, Copy, Default)]
struct Counters {
    dropped: u64,
    oversize: u64,
    crossings: u64,
    retransmits: u64,
    inconsistencies: u64,
    gaps: u64,
    gap_bytes: u64,
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

/// A reassembler plus the bytes it last contributed to the
/// tracker-wide memcap pool.
struct Slot<R> {
    r: R,
    accounted: u64,
    /// Set by [`FlowDriver::discard_stream`]: nobody needs this flow's
    /// bytes any more, so segments are ignored. Not a
    /// [`ReassemblyStop`] — nothing went wrong.
    discarded: bool,
    /// The stop reason the reassembler had when it was discarded
    /// (a real overflow / memcap stop stays reported; the release
    /// done by the discard itself does not).
    stop_at_discard: Option<ReassemblyStop>,
}

/// Copy a reassembler's diagnostics into the per-side fields of
/// `stats`.
fn fold_side<R: Reassembler>(stats: &mut FlowStats, side: FlowSide, slot: &Slot<R>) {
    let r = &slot.r;
    let stop = if slot.discarded {
        slot.stop_at_discard
    } else {
        r.stop_reason()
    };
    match side {
        FlowSide::Initiator => {
            stats.reassembly_dropped_ooo_initiator = r.dropped_segments();
            stats.reassembly_bytes_dropped_oversize_initiator = r.bytes_dropped_oversize();
            stats.reassembler_high_watermark_initiator = r.high_watermark();
            stats.retransmits_initiator = r.retransmits();
            stats.reassembly_gaps_initiator = r.gaps();
            stats.reassembly_gap_bytes_initiator = r.gap_bytes();
            stats.reassembly_stop_initiator = stop;
        }
        FlowSide::Responder => {
            stats.reassembly_dropped_ooo_responder = r.dropped_segments();
            stats.reassembly_bytes_dropped_oversize_responder = r.bytes_dropped_oversize();
            stats.reassembler_high_watermark_responder = r.high_watermark();
            stats.retransmits_responder = r.retransmits();
            stats.reassembly_gaps_responder = r.gaps();
            stats.reassembly_gap_bytes_responder = r.gap_bytes();
            stats.reassembly_stop_responder = stop;
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
    reassemblers: HashMap<(E::Key, FlowSide), Slot<F::Reassembler>, RandomState>,
    emit_anomalies: bool,
    dedup: Option<crate::dedup::Dedup>,
    /// When `Some`, the running max of all timestamps the driver
    /// has emitted. `None` means monotonisation is off.
    monotonic_ts: Option<Timestamp>,
    /// Running total of bytes buffered across every live reassembler
    /// (issue #26), for [`FlowTrackerConfig::reassembly_memcap`].
    global_memcap_bytes: u64,
    last_packet: Option<PacketInfo<E::Key>>,
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
    pub fn from_tracker(tracker: FlowTracker<E, S>, mut factory: F) -> Self {
        factory.apply_config(tracker.config());
        Self {
            tracker,
            factory,
            reassemblers: HashMap::with_hasher(RandomState::new()),
            emit_anomalies: false,
            dedup: None,
            monotonic_ts: None,
            global_memcap_bytes: 0,
            last_packet: None,
        }
    }

    /// Opt in to emitting [`FlowEvent::FlowAnomaly`] /
    /// [`FlowEvent::TrackerAnomaly`] for buffer overflows, gaps,
    /// late segments, retransmits, overlap inconsistencies,
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
    /// classifies as duplicates produce zero events. Useful for
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

    fn clamp_view<'a>(&mut self, view: PacketView<'a>) -> PacketView<'a> {
        let Some(last) = self.monotonic_ts.as_mut() else {
            return view;
        };
        *last = (*last).max(view.timestamp);
        let mut clamped = view;
        clamped.timestamp = *last;
        clamped
    }

    fn clamp_now(&mut self, now: Timestamp) -> Timestamp {
        let Some(last) = self.monotonic_ts.as_mut() else {
            return now;
        };
        *last = (*last).max(now);
        *last
    }

    /// Process one packet. Drives the tracker and dispatches TCP
    /// payloads to the factory's reassemblers. Reassemblers are
    /// created on demand and cleaned up on `Ended`.
    pub fn track<'v>(&mut self, view: impl Into<PacketView<'v>>) -> FlowEvents<E::Key> {
        let mut events = self.track_pending(view);
        self.finalize(events.as_mut_slice());
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
    /// folded into the event's `stats`.
    ///
    /// You MUST call [`Self::finalize`] before the next
    /// `track_pending` / `sweep_pending` / `track` / `sweep` call.
    pub fn track_pending<'v>(&mut self, view: impl Into<PacketView<'v>>) -> FlowEvents<E::Key> {
        self.track_pending_with(view, |_| true)
    }

    /// Like [`Self::track_pending`], but a reassembler is only
    /// **created** for a flow side when `want` returns `true` for the
    /// packet that would create it (sides that already have one keep
    /// receiving segments). The session engines use it to buffer
    /// only flows some parser is interested in; answer consistently
    /// for every packet of a flow.
    pub fn track_pending_with<'v, W>(
        &mut self,
        view: impl Into<PacketView<'v>>,
        mut want: W,
    ) -> FlowEvents<E::Key>
    where
        W: FnMut(&crate::tracker::PacketContext<'_, E::Key>) -> bool,
    {
        self.last_packet = None;
        let view: PacketView<'v> = view.into();
        if let Some(d) = self.dedup.as_mut()
            && !d.keep(view)
        {
            return FlowEvents::new();
        }
        let view = self.clamp_view(view);
        let ts = view.timestamp;
        let evicted_before = self.tracker.stats().flows_evicted;
        let memcap_cap = self.tracker.config().reassembly_memcap;
        let memcap_policy = self.tracker.config().reassembly_memcap_policy;
        let emit_anomalies = self.emit_anomalies;

        let factory = &mut self.factory;
        let reassemblers = &mut self.reassemblers;
        let global_bytes = &mut self.global_memcap_bytes;
        let mut info: Option<PacketInfo<E::Key>> = None;
        let mut anomalies: Vec<(E::Key, AnomalyKind)> = Vec::new();
        let mut kinds: Vec<AnomalyKind> = Vec::new();
        // At most one `GlobalMemcapHit` per packet; captures the
        // bytes-in-flight at the trip.
        let mut memcap_tripped: Option<u64> = None;
        // Memcap `DropFlow` releases the *other* side too, which the
        // closure can't borrow while holding this side.
        let mut release_peer: Option<(E::Key, FlowSide)> = None;

        let mut events = self.tracker.track_with(view, |p| {
            info = Some(PacketInfo {
                key: p.key.clone(),
                side: p.side,
                orientation: p.orientation,
                l4: p.l4,
                tcp: p.tcp.copied(),
                l4_meta: p.l4_meta,
                ts: p.ts,
                is_new: p.is_new,
            });
            let (Some(tcp), false) = (p.tcp, p.tcp_payload.is_empty()) else {
                return;
            };
            let slot_key = (p.key.clone(), p.side);
            if !reassemblers.contains_key(&slot_key) && !want(p) {
                return;
            }
            let slot = reassemblers.entry(slot_key).or_insert_with(|| Slot {
                r: factory.new_reassembler(p.key, p.side),
                accounted: 0,
                discarded: false,
                stop_at_discard: None,
            });
            if slot.discarded {
                return;
            }

            // Re-sync this side's pool contribution: a consumer may
            // have drained it since the last segment (issue #186).
            *global_bytes = global_bytes
                .saturating_sub(slot.accounted)
                .saturating_add(slot.r.current_bytes());
            slot.accounted = slot.r.current_bytes();

            // `DropPacket` is the one policy that refuses a segment,
            // so it decides before handing it over.
            let would_exceed = memcap_cap
                .is_some_and(|cap| global_bytes.saturating_add(p.tcp_payload.len() as u64) > cap);
            if would_exceed && memcap_policy == MemcapPolicy::DropPacket {
                memcap_tripped.get_or_insert(*global_bytes);
                return;
            }

            let before = emit_anomalies.then(|| Counters::of(&slot.r));
            slot.r.segment(tcp.seq, p.tcp_payload, p.ts);
            *global_bytes = global_bytes
                .saturating_sub(slot.accounted)
                .saturating_add(slot.r.current_bytes());
            slot.accounted = slot.r.current_bytes();

            if let Some(cap) = memcap_cap
                && *global_bytes > cap
            {
                memcap_tripped.get_or_insert(*global_bytes);
                match memcap_policy {
                    MemcapPolicy::Ignore | MemcapPolicy::DropPacket => {}
                    MemcapPolicy::PassThrough | MemcapPolicy::DropFlow => {
                        slot.r.release();
                        *global_bytes = global_bytes
                            .saturating_sub(slot.accounted)
                            .saturating_add(slot.r.current_bytes());
                        slot.accounted = slot.r.current_bytes();
                        if memcap_policy == MemcapPolicy::DropFlow {
                            release_peer = Some((p.key.clone(), p.side.opposite()));
                        }
                    }
                }
            }
            if let Some(before) = before {
                kinds.clear();
                before.diff(&slot.r, p.side, &mut kinds);
                anomalies.extend(kinds.drain(..).map(|k| (p.key.clone(), k)));
            }
        });

        if let Some(peer) = release_peer
            && let Some(slot) = self.reassemblers.get_mut(&peer)
        {
            slot.r.release();
            self.global_memcap_bytes = self
                .global_memcap_bytes
                .saturating_sub(slot.accounted)
                .saturating_add(slot.r.current_bytes());
            slot.accounted = slot.r.current_bytes();
        }
        self.last_packet = info;

        if self.emit_anomalies {
            for (key, kind) in anomalies {
                crate::obs::record_anomaly(&kind);
                crate::obs::trace_anomaly(&kind);
                events.push(FlowEvent::FlowAnomaly { key, kind, ts });
            }
            if let Some(bytes_in_flight) = memcap_tripped
                && let Some(cap) = memcap_cap
            {
                self.push_tracker_anomaly(
                    &mut events,
                    AnomalyKind::GlobalMemcapHit {
                        bytes_in_flight,
                        cap,
                        policy: memcap_policy,
                    },
                    ts,
                );
            }
            self.push_eviction_pressure(&mut events, evicted_before, ts);
        }

        self.close_ended(&mut events);

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

    fn push_tracker_anomaly<X: Extend<FlowEvent<E::Key>>>(
        &self,
        events: &mut X,
        kind: AnomalyKind,
        ts: Timestamp,
    ) {
        crate::obs::record_anomaly(&kind);
        crate::obs::trace_anomaly(&kind);
        events.extend([FlowEvent::TrackerAnomaly { kind, ts }]);
    }

    fn push_eviction_pressure<X: Extend<FlowEvent<E::Key>>>(
        &self,
        events: &mut X,
        evicted_before: u64,
        ts: Timestamp,
    ) {
        let evicted_total = self.tracker.stats().flows_evicted;
        let evicted_in_tick = evicted_total.saturating_sub(evicted_before);
        if evicted_in_tick > 0 {
            self.push_tracker_anomaly(
                events,
                AnomalyKind::FlowTableEvictionPressure {
                    evicted_in_tick,
                    evicted_total,
                },
                ts,
            );
        }
    }

    /// For each `Ended` event: flush both sides' reassemblers (the
    /// flow is over, no hole will ever fill) and fold their final
    /// diagnostics into the event's stats. Gaps the flush had to
    /// skip are reported (when anomalies are on) right before the
    /// `Ended`. The reassemblers stay in place until
    /// [`Self::finalize`], so the last bytes can still be drained.
    fn close_ended<B: EventBuf<E::Key>>(&mut self, events: &mut B) {
        let mut i = 0;
        while i < events.len() {
            let mut anomalies: Vec<FlowEvent<E::Key>> = Vec::new();
            if let FlowEvent::Ended { key, stats, .. } = events.get_mut(i) {
                let ts = stats.last_seen;
                for side in [FlowSide::Initiator, FlowSide::Responder] {
                    if let Some(slot) = self.reassemblers.get_mut(&(key.clone(), side)) {
                        let before = self.emit_anomalies.then(|| Counters::of(&slot.r));
                        slot.r.flush_pending();
                        fold_side(stats, side, slot);
                        if let Some(before) = before {
                            let mut kinds = Vec::new();
                            before.diff(&slot.r, side, &mut kinds);
                            for kind in kinds {
                                crate::obs::record_anomaly(&kind);
                                crate::obs::trace_anomaly(&kind);
                                anomalies.push(FlowEvent::FlowAnomaly {
                                    key: key.clone(),
                                    kind,
                                    ts,
                                });
                            }
                        }
                    }
                }
                crate::obs::record_reassembly_diagnostics(stats);
            }
            for a in anomalies {
                events.insert(i, a);
                i += 1;
            }
            i += 1;
        }
    }

    /// Walk live flows; for any whose `last_tick_at` is past-due,
    /// emit a [`FlowEvent::Tick`] carrying a live [`FlowStats`]
    /// snapshot and mark the flow as ticked.
    fn emit_ticks(&mut self, events: &mut FlowEvents<E::Key>, now: Timestamp, interval: Duration) {
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
        for side in [FlowSide::Initiator, FlowSide::Responder] {
            if let Some(slot) = self.reassemblers.get(&(key.clone(), side)) {
                fold_side(&mut stats, side, slot);
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
    /// last [`track`](Self::track) when input is exhausted —
    /// equivalent to `sweep(Timestamp::MAX)`.
    pub fn finish(&mut self) -> Vec<FlowEvent<E::Key>> {
        self.sweep(Timestamp::MAX)
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
        let now = self.clamp_now(now);
        let Some(ended) = self.tracker.force_close(key, now) else {
            return Vec::new();
        };
        let mut events = vec![ended];
        self.close_ended(&mut events);
        events
    }

    /// Lower-level sweep variant. Like [`Self::sweep`] but does NOT
    /// finalize ended flows' reassemblers. See [`Self::track_pending`]
    /// for the contract.
    ///
    /// Before idling flows out, every live reassembler gets
    /// [`Reassembler::advance_time`] so out-of-order holes past their
    /// deadline are skipped even on a side that went quiet.
    pub fn sweep_pending(&mut self, now: Timestamp) -> Vec<FlowEvent<E::Key>> {
        let now = self.clamp_now(now);
        let emit = self.emit_anomalies;
        let mut anomalies: Vec<FlowEvent<E::Key>> = Vec::new();
        let mut kinds: Vec<AnomalyKind> = Vec::new();
        for ((key, side), slot) in self.reassemblers.iter_mut() {
            let before = emit.then(|| Counters::of(&slot.r));
            slot.r.advance_time(now);
            if let Some(before) = before {
                before.diff(&slot.r, *side, &mut kinds);
                for kind in kinds.drain(..) {
                    crate::obs::record_anomaly(&kind);
                    crate::obs::trace_anomaly(&kind);
                    anomalies.push(FlowEvent::FlowAnomaly {
                        key: key.clone(),
                        kind,
                        ts: now,
                    });
                }
            }
        }
        let evicted_before = self.tracker.stats().flows_evicted;
        let mut events = self.tracker.sweep(now);
        self.reconcile_with_tracker(&events);
        if emit {
            events.extend(anomalies);
            self.push_eviction_pressure(&mut events, evicted_before, now);
        }
        self.close_ended(&mut events);
        events
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
        for side in [FlowSide::Initiator, FlowSide::Responder] {
            if let Some(mut slot) = self.reassemblers.remove(&(key.clone(), side)) {
                self.global_memcap_bytes = self.global_memcap_bytes.saturating_sub(slot.accounted);
                if reason.is_graceful() {
                    slot.r.fin();
                } else {
                    slot.r.rst();
                }
            }
        }
    }

    /// Keys of every live reassembler, for engines that sweep them.
    pub(crate) fn reassembler_keys(&self) -> impl Iterator<Item = (E::Key, FlowSide)> + '_ {
        self.reassemblers.keys().cloned()
    }

    /// Drop per-flow resources whose flow the tracker no longer holds.
    ///
    /// Cleanup normally rides on `FlowEvent::Ended` — but that event
    /// is gated on [`EventMask::ENDED`](crate::EventMask), while the
    /// tracker removes the flow either way. With `Ended` suppressed
    /// (load shedding, issue #79) the reassemblers for reaped flows
    /// would otherwise be held for the life of the driver.
    /// Reassemblers of flows that ended in `pending` survive until
    /// [`Self::finalize`].
    fn reconcile_with_tracker(&mut self, pending: &[FlowEvent<E::Key>]) {
        let mut ending: std::collections::HashSet<&E::Key, RandomState> =
            std::collections::HashSet::with_hasher(RandomState::new());
        ending.extend(pending.iter().filter_map(|e| match e {
            FlowEvent::Ended { key, .. } => Some(key),
            _ => None,
        }));
        let tracker = &self.tracker;
        let global = &mut self.global_memcap_bytes;
        self.reassemblers.retain(|(key, _), slot| {
            if tracker.get(key).is_some() || ending.contains(key) {
                return true;
            }
            *global = global.saturating_sub(slot.accounted);
            false
        });
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

    /// Borrow the per-(flow, side) reassembler. `None` when no
    /// reassembler exists (no TCP payload seen on that side, or the
    /// flow ended and was finalized).
    pub fn reassembler(&mut self, key: &E::Key, side: FlowSide) -> Option<&mut F::Reassembler> {
        self.reassemblers
            .get_mut(&(key.clone(), side))
            .map(|slot| &mut slot.r)
    }

    /// Move the reassembled output of one flow side (bytes, gaps,
    /// stop) onto the end of `out` — see [`Reassembler::drain_into`].
    /// Returns `false` when the side has no reassembler. The memcap
    /// pool is re-synced immediately.
    pub fn drain_stream(&mut self, key: &E::Key, side: FlowSide, out: &mut StreamChunks) -> bool {
        let Some(slot) = self.reassemblers.get_mut(&(key.clone(), side)) else {
            return false;
        };
        if slot.discarded {
            return false;
        }
        slot.r.drain_into(out);
        self.global_memcap_bytes = self
            .global_memcap_bytes
            .saturating_sub(slot.accounted)
            .saturating_add(slot.r.current_bytes());
        slot.accounted = slot.r.current_bytes();
        true
    }

    /// Stop reassembling a flow because no consumer needs its bytes
    /// any more (e.g. every parser on it has closed). Both sides stop
    /// buffering and release their memory, including a side that has
    /// not sent data yet; later segments are ignored. Unlike a
    /// reassembly *stop*, this is not reported anywhere — it is the
    /// consumer's decision. Counters keep their final values.
    pub fn discard_stream(&mut self, key: &E::Key) {
        for side in [FlowSide::Initiator, FlowSide::Responder] {
            let slot = self
                .reassemblers
                .entry((key.clone(), side))
                .or_insert_with(|| Slot {
                    r: self.factory.new_reassembler(key, side),
                    accounted: 0,
                    discarded: false,
                    stop_at_discard: None,
                });
            if slot.discarded {
                continue;
            }
            slot.discarded = true;
            slot.stop_at_discard = slot.r.stop_reason();
            slot.r.release();
            self.global_memcap_bytes = self.global_memcap_bytes.saturating_sub(slot.accounted);
            slot.accounted = 0;
        }
    }

    /// Borrow the inner tracker (for stats, introspection).
    pub fn tracker(&self) -> &FlowTracker<E, S> {
        &self.tracker
    }

    /// Borrow the inner tracker mutably. Prefer [`Self::set_config`]
    /// over `tracker_mut().set_config(..)`: only the former keeps the
    /// reassembler factory in sync.
    pub fn tracker_mut(&mut self) -> &mut FlowTracker<E, S> {
        &mut self.tracker
    }

    /// True when anomaly emission is on.
    pub fn emits_anomalies(&self) -> bool {
        self.emit_anomalies
    }

    /// Iterate `(key, FlowStats)` for every live flow, combining the
    /// tracker's per-flow stats with **live** reassembler diagnostics
    /// (gaps, late drops, oversize drops, peak watermark,
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

/// The two event containers the driver produces (`FlowEvents` for
/// `track`, `Vec` for `sweep`), for helpers that insert into them.
trait EventBuf<K> {
    fn len(&self) -> usize;
    fn get_mut(&mut self, i: usize) -> &mut FlowEvent<K>;
    fn insert(&mut self, i: usize, ev: FlowEvent<K>);
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
}

impl<E, S> FlowDriver<E, crate::reassembler::BufferedReassemblerFactory, S>
where
    E: FlowExtractor,
    S: Send + 'static,
{
    /// Drain buffered bytes for the given (key, side) and return
    /// them as a `Vec<u8>`, **discarding gap markers** — prefer
    /// [`Self::drain_stream`], which keeps them. Returns an empty
    /// `Vec` when no reassembler exists or the buffer is empty.
    pub fn drain_buffer(&mut self, key: &E::Key, side: FlowSide) -> Vec<u8> {
        let mut out = StreamChunks::new();
        self.drain_stream(key, side, &mut out);
        out.data().to_vec()
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

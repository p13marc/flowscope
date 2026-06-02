//! [`FlowDriver`] — sync wrapper that bundles a [`FlowTracker`] with
//! a [`ReassemblerFactory`] and dispatches TCP segments to the right
//! reassembler.
//!
//! The async equivalent lives in `netring`'s `FlowStream::with_async_reassembler`.

use std::collections::HashMap;
use std::time::Duration;

use ahash::RandomState;

use crate::Timestamp;
use crate::event::{AnomalyKind, EndReason, FlowEvent, FlowSide, OverflowPolicy};
use crate::extractor::FlowExtractor;
use crate::reassembler::{Reassembler, ReassemblerFactory};
use crate::tracker::{FlowEvents, FlowTracker, FlowTrackerConfig};
use crate::view::PacketView;

/// Sync flow driver: tracker + per-(flow, side) reassembler dispatch.
///
/// Use this when you want both flow events **and** TCP byte streams
/// in one synchronous loop (typical for pcap replay, embedded use,
/// non-tokio CLI tools).
///
/// For tokio integration, see `netring::FlowStream::with_async_reassembler`.
/// Snapshot of per-reassembler diagnostic counters + tracker
/// eviction total at the start of a tick. Compared against the
/// post-tick state to coalesce anomaly events.
/// Per-reassembler diagnostic counters captured at snapshot time.
/// Diff against post-tick values to derive per-tick anomaly events.
#[derive(Clone, Copy, Default)]
struct ReassemblerCounters {
    dropped: u64,
    oversize: u64,
    crossings: u64,
    retransmits: u64,
}

struct AnomalySnapshot<K>
where
    K: Eq + std::hash::Hash + Clone,
{
    per_side: HashMap<(K, FlowSide), ReassemblerCounters, RandomState>,
    evicted_total: u64,
}

impl<K> Default for AnomalySnapshot<K>
where
    K: Eq + std::hash::Hash + Clone,
{
    fn default() -> Self {
        Self {
            per_side: HashMap::with_hasher(RandomState::new()),
            evicted_total: 0,
        }
    }
}

pub struct FlowDriver<E, F, S = ()>
where
    E: FlowExtractor,
    F: ReassemblerFactory<E::Key>,
    S: Send + 'static,
{
    tracker: FlowTracker<E, S>,
    factory: F,
    reassemblers: HashMap<(E::Key, FlowSide), F::Reassembler, RandomState>,
    emit_anomalies: bool,
    dedup: Option<crate::dedup::Dedup>,
    /// When `Some`, the running max of all timestamps the driver
    /// has emitted. Each incoming view's timestamp is clamped to
    /// this max. `None` means monotonisation is off (raw NIC
    /// timestamps flow through unmodified).
    monotonic_ts: Option<Timestamp>,
}

// Common path — `S = ()`. Constructors live on this pinned impl
// block so call sites need no type annotation for the (vastly
// common) "no per-flow user state" case.
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
        Self {
            tracker: FlowTracker::with_config(extractor, config),
            factory,
            reassemblers: HashMap::with_hasher(RandomState::new()),
            emit_anomalies: false,
            dedup: None,
            monotonic_ts: None,
        }
    }
}

// Stateful path — `S: Default`. Convenience for the common case
// where per-flow state can be built without knowing the key.
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
        Self {
            tracker: FlowTracker::with_config(extractor, config),
            factory,
            reassemblers: HashMap::with_hasher(RandomState::new()),
            emit_anomalies: false,
            dedup: None,
            monotonic_ts: None,
        }
    }
}

// Generic path — `S: Send + 'static` only. Covers parsers whose
// state isn't `Default` or that want to derive state from the flow
// key. All non-construction methods live on this block so they
// apply to every `S`.
impl<E, F, S> FlowDriver<E, F, S>
where
    E: FlowExtractor,
    F: ReassemblerFactory<E::Key>,
    S: Send + 'static,
{
    /// Construct with default config and a custom per-flow state
    /// initialiser. Use when `S` isn't `Default` or when state
    /// should be derived from the flow key.
    pub fn with_state_init<G>(extractor: E, factory: F, init: G) -> Self
    where
        G: FnMut(&E::Key) -> S + Send + 'static,
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
        G: FnMut(&E::Key) -> S + Send + 'static,
    {
        Self {
            tracker: FlowTracker::with_config_and_state(extractor, config, init),
            factory,
            reassemblers: HashMap::with_hasher(RandomState::new()),
            emit_anomalies: false,
            dedup: None,
            monotonic_ts: None,
        }
    }

    /// Opt in to emitting [`FlowEvent::FlowAnomaly`] /
    /// [`FlowEvent::TrackerAnomaly`] for buffer overflows,
    /// out-of-order drops, and tracker eviction pressure. Default:
    /// `false` — no anomaly events emitted; counters still accumulate
    /// in [`crate::FlowStats`].
    ///
    /// Anomalies are coalesced per (flow, side, kind) per tick so a
    /// pathological flow doesn't swamp the stream.
    pub fn with_emit_anomalies(mut self, enable: bool) -> Self {
        self.emit_anomalies = enable;
        self
    }

    /// Set a per-key idle-timeout override on the underlying tracker
    /// (see [`FlowTracker::set_idle_timeout_fn`]). Builder-style
    /// passthrough — chains nicely with [`Self::new`] /
    /// [`Self::with_config`] / [`Self::with_emit_anomalies`].
    pub fn with_idle_timeout_fn<G>(mut self, f: G) -> Self
    where
        G: Fn(&E::Key, Option<crate::L4Proto>) -> Option<std::time::Duration> + Send + 'static,
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

    /// Borrow the dedup state (e.g. for `.dropped()` /
    /// `.buffered()` stats). `None` when no dedup is configured.
    pub fn dedup(&self) -> Option<&crate::dedup::Dedup> {
        self.dedup.as_ref()
    }

    /// Opt in to strictly non-decreasing timestamps across the
    /// stream. Each packet's `view.timestamp` is clamped to
    /// `max(view.timestamp, last_emitted_timestamp)`.
    ///
    /// Useful for downstream consumers that build timelines
    /// from `FlowEvent` and want a guarantee that successive
    /// events never go backwards in time. Default: off (raw NIC
    /// timestamps flow through unmodified). The clamp also
    /// applies to [`Self::sweep`]'s `now` argument.
    pub fn with_monotonic_timestamps(mut self, enable: bool) -> Self {
        self.monotonic_ts = if enable {
            Some(Timestamp::default())
        } else {
            None
        };
        self
    }

    /// Clamp a view's timestamp against the running max if
    /// monotonisation is on; otherwise return the view unchanged.
    fn clamp_view<'a>(&mut self, view: PacketView<'a>) -> PacketView<'a> {
        let Some(last) = self.monotonic_ts.as_mut() else {
            return view;
        };
        *last = (*last).max(view.timestamp);
        PacketView::new(view.frame, *last)
    }

    /// Clamp a `now` argument used by [`Self::sweep`] against the
    /// running max.
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
    /// finalizing reassemblers. Reassemblers remain accessible (via
    /// [`Self::reassembler`] / [`Self::drain_buffer`]) until
    /// [`Self::finalize`] is called.
    ///
    /// You MUST call [`Self::finalize`] before the next
    /// `track_pending` / `sweep_pending` / `track` / `sweep` call —
    /// otherwise reassemblers for ended flows are never cleaned up.
    /// Typical use: [`crate::FlowSessionDriver`] calls
    /// `track_pending`, drains buffered bytes from reassemblers, then
    /// calls `finalize`.
    pub fn track_pending<'v>(&mut self, view: impl Into<PacketView<'v>>) -> FlowEvents<E::Key> {
        let view: PacketView<'v> = view.into();
        // Dedup before extraction — duplicates produce no events.
        if let Some(d) = self.dedup.as_mut() {
            if !d.keep(view) {
                return FlowEvents::new();
            }
        }
        // Monotonic timestamp clamp (Plan 48) — applied to the
        // view's timestamp before tracker dispatch.
        let view = self.clamp_view(view);
        let ts = view.timestamp;
        let snapshot = self.snapshot_anomaly_state();
        let factory = &mut self.factory;
        let reassemblers = &mut self.reassemblers;
        let mut events = self
            .tracker
            .track_with_payload(view, |key, side, seq, payload| {
                let r = reassemblers
                    .entry((key.clone(), side))
                    .or_insert_with(|| factory.new_reassembler(key, side));
                r.segment(seq, payload, ts);
            });

        // Emit anomaly events (per-tick coalesced) before synthesising
        // BufferOverflow ends — the overflow that caused the
        // BufferOverflow anomaly should appear before the Ended event.
        if self.emit_anomalies {
            let anomalies = Self::diff_anomaly_state(snapshot, reassemblers, &self.tracker, ts);
            for a in anomalies {
                if let Some(kind) = a.anomaly_kind() {
                    crate::obs::record_anomaly(kind);
                    crate::obs::trace_anomaly(kind);
                }
                events.push(a);
            }
        }

        // Synthesise `Ended { reason: BufferOverflow }` for any
        // reassembler that just poisoned and isn't already ending.
        let synthesised =
            Self::synthesise_buffer_overflow_ends(&events, reassemblers, &mut self.tracker);
        for ev in synthesised {
            events.push(ev);
        }

        // Periodic flow ticks (Plan 71). Opt-in via
        // `FlowTrackerConfig::flow_tick_interval`. Emitted after
        // anomaly + BufferOverflow synthesis so consumers see the
        // tick AFTER any anomalies / ends for the same packet.
        if let Some(interval) = self.tracker.config().flow_tick_interval {
            self.emit_ticks(&mut events, ts, interval);
        }

        events
    }

    /// Walk live flows; for any whose `last_tick_at` is past-due,
    /// emit a [`FlowEvent::Tick`] carrying a patched [`FlowStats`]
    /// snapshot and mark the flow as ticked.
    fn emit_ticks(&mut self, events: &mut FlowEvents<E::Key>, now: Timestamp, interval: Duration) {
        // Collect (key, stats) pairs first to release the tracker
        // borrow before calling mark_ticked.
        let mut to_tick: Vec<(E::Key, crate::FlowStats)> = Vec::new();
        for (key, entry) in self.tracker.flows() {
            let due = match entry.last_tick_at {
                None => true,
                Some(last) => now.saturating_sub(last) >= interval,
            };
            if !due {
                continue;
            }
            let mut stats = entry.stats.clone();
            if let Some(r) = self.reassemblers.get(&(key.clone(), FlowSide::Initiator)) {
                stats.reassembly_dropped_ooo_initiator = r.dropped_segments();
                stats.reassembly_bytes_dropped_oversize_initiator = r.bytes_dropped_oversize();
                stats.reassembler_high_watermark_initiator = r.high_watermark();
                stats.retransmits_initiator = r.retransmits();
            }
            if let Some(r) = self.reassemblers.get(&(key.clone(), FlowSide::Responder)) {
                stats.reassembly_dropped_ooo_responder = r.dropped_segments();
                stats.reassembly_bytes_dropped_oversize_responder = r.bytes_dropped_oversize();
                stats.reassembler_high_watermark_responder = r.high_watermark();
                stats.retransmits_responder = r.retransmits();
            }
            to_tick.push((key.clone(), stats));
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

    /// Run the idle-timeout sweep and clean up reassemblers for
    /// ended flows.
    pub fn sweep(&mut self, now: Timestamp) -> Vec<FlowEvent<E::Key>> {
        let mut events = self.sweep_pending(now);
        self.finalize(events.as_mut_slice());
        events
    }

    /// Sweep every remaining flow to its end. Call once after the
    /// last [`track`](Self::track) when input is exhausted —
    /// equivalent to `sweep(Timestamp::MAX)`. Every still-open flow
    /// is emitted as [`FlowEvent::Ended`].
    pub fn finish(&mut self) -> Vec<FlowEvent<E::Key>> {
        self.sweep(Timestamp::MAX)
    }

    /// Lower-level sweep variant. Like [`Self::sweep`] but does NOT
    /// finalize ended flows' reassemblers. See [`Self::track_pending`]
    /// for the contract.
    pub fn sweep_pending(&mut self, now: Timestamp) -> Vec<FlowEvent<E::Key>> {
        // Plan 48: clamp `now` to the running max when
        // monotonisation is on.
        let now = self.clamp_now(now);
        let snapshot = self.snapshot_anomaly_state();
        let mut events = self.tracker.sweep(now);
        if self.emit_anomalies {
            let anomalies =
                Self::diff_anomaly_state(snapshot, &self.reassemblers, &self.tracker, now);
            for a in &anomalies {
                if let Some(kind) = a.anomaly_kind() {
                    crate::obs::record_anomaly(kind);
                    crate::obs::trace_anomaly(kind);
                }
            }
            events.extend(anomalies);
        }
        let synthesised = Self::synthesise_buffer_overflow_ends(
            &events,
            &mut self.reassemblers,
            &mut self.tracker,
        );
        events.extend(synthesised);
        events
    }

    /// Patch reassembly diagnostics into every `Ended` event and
    /// drop the corresponding reassemblers (calling `fin` / `rst`).
    /// Called automatically by [`Self::track`] / [`Self::sweep`];
    /// callers using [`Self::track_pending`] / [`Self::sweep_pending`]
    /// must call this before the next `track*` / `sweep*` call.
    pub fn finalize(&mut self, events: &mut [FlowEvent<E::Key>]) {
        Self::finalize_ended_flows(events, &mut self.reassemblers);
    }

    /// Borrow the per-(flow, side) reassembler. Returns `None` when
    /// no reassembler exists (no TCP payload has been seen on that
    /// side, or the flow has already ended and been finalized).
    ///
    /// Most useful between [`Self::track_pending`] and
    /// [`Self::finalize`], where reassemblers for ended flows
    /// haven't been dropped yet.
    pub fn reassembler(&mut self, key: &E::Key, side: FlowSide) -> Option<&mut F::Reassembler> {
        self.reassemblers.get_mut(&(key.clone(), side))
    }

    /// Snapshot the per-reassembler diagnostic counters and the
    /// tracker's eviction total ahead of a `track`/`sweep` call so
    /// the post-call diff can be coalesced into anomaly events.
    fn snapshot_anomaly_state(&self) -> AnomalySnapshot<E::Key> {
        if !self.emit_anomalies {
            return AnomalySnapshot::default();
        }
        let mut per_side: HashMap<(E::Key, FlowSide), ReassemblerCounters, RandomState> =
            HashMap::with_hasher(RandomState::new());
        for ((key, side), r) in &self.reassemblers {
            per_side.insert(
                (key.clone(), *side),
                ReassemblerCounters {
                    dropped: r.dropped_segments(),
                    oversize: r.bytes_dropped_oversize(),
                    crossings: r.high_watermark_crossings(),
                    retransmits: r.retransmits(),
                },
            );
        }
        AnomalySnapshot {
            per_side,
            evicted_total: self.tracker.stats().flows_evicted,
        }
    }

    /// Diff the snapshot against current state and synthesise one
    /// anomaly event per (flow, side, kind) with non-zero delta plus
    /// at most one `FlowTableEvictionPressure` event for the tick.
    fn diff_anomaly_state(
        snapshot: AnomalySnapshot<E::Key>,
        reassemblers: &HashMap<(E::Key, FlowSide), F::Reassembler, RandomState>,
        tracker: &FlowTracker<E, S>,
        ts: Timestamp,
    ) -> Vec<FlowEvent<E::Key>> {
        let mut out = Vec::new();
        // Per-flow / per-side counter deltas.
        for ((key, side), r) in reassemblers {
            let prev = snapshot
                .per_side
                .get(&(key.clone(), *side))
                .copied()
                .unwrap_or_default();
            let cur = ReassemblerCounters {
                dropped: r.dropped_segments(),
                oversize: r.bytes_dropped_oversize(),
                crossings: r.high_watermark_crossings(),
                retransmits: r.retransmits(),
            };
            let dropped_delta = cur.dropped.saturating_sub(prev.dropped);
            let oversize_delta = cur.oversize.saturating_sub(prev.oversize);
            let crossing_delta = cur.crossings.saturating_sub(prev.crossings);
            let retransmit_delta = cur.retransmits.saturating_sub(prev.retransmits);
            if oversize_delta > 0 {
                // Look up the policy via the tracker config; falls
                // back to the default (SlidingWindow) when unset.
                let policy = if r.is_poisoned() {
                    OverflowPolicy::DropFlow
                } else {
                    OverflowPolicy::SlidingWindow
                };
                out.push(FlowEvent::FlowAnomaly {
                    key: key.clone(),
                    kind: AnomalyKind::BufferOverflow {
                        side: *side,
                        bytes: oversize_delta,
                        policy,
                    },
                    ts,
                });
            }
            if dropped_delta > 0 {
                out.push(FlowEvent::FlowAnomaly {
                    key: key.clone(),
                    kind: AnomalyKind::OutOfOrderSegment {
                        side: *side,
                        count: dropped_delta,
                    },
                    ts,
                });
            }
            if crossing_delta > 0 {
                // Threshold must be configured for crossings to
                // ever increment. Pull cap + pct from the
                // reassembler to enrich the anomaly payload.
                if let Some((cap, threshold_pct)) = r.high_watermark_threshold() {
                    out.push(FlowEvent::FlowAnomaly {
                        key: key.clone(),
                        kind: AnomalyKind::ReassemblerHighWatermark {
                            side: *side,
                            bytes: r.bytes_in_flight(),
                            cap,
                            threshold_pct,
                        },
                        ts,
                    });
                }
            }
            if retransmit_delta > 0 {
                out.push(FlowEvent::FlowAnomaly {
                    key: key.clone(),
                    kind: AnomalyKind::RetransmittedSegment {
                        side: *side,
                        count: retransmit_delta,
                    },
                    ts,
                });
            }
        }
        // Tracker-global eviction pressure.
        let evicted_total = tracker.stats().flows_evicted;
        let evicted_delta = evicted_total.saturating_sub(snapshot.evicted_total);
        if evicted_delta > 0 {
            out.push(FlowEvent::TrackerAnomaly {
                kind: AnomalyKind::FlowTableEvictionPressure {
                    evicted_in_tick: evicted_delta,
                    evicted_total,
                },
                ts,
            });
        }
        out
    }

    /// Build a list of `Ended { reason: BufferOverflow }` events for
    /// any reassembler that's poisoned but whose flow hasn't already
    /// ended in `existing`.
    fn synthesise_buffer_overflow_ends(
        existing: &[FlowEvent<E::Key>],
        reassemblers: &mut HashMap<(E::Key, FlowSide), F::Reassembler, RandomState>,
        tracker: &mut FlowTracker<E, S>,
    ) -> Vec<FlowEvent<E::Key>> {
        // Collect keys whose reassembler is poisoned.
        let mut poisoned_keys: Vec<E::Key> = Vec::new();
        for ((key, _side), r) in reassemblers.iter() {
            if r.is_poisoned() && !poisoned_keys.contains(key) {
                poisoned_keys.push(key.clone());
            }
        }
        if poisoned_keys.is_empty() {
            return Vec::new();
        }
        // Skip keys already ending in this tick.
        let already_ending: std::collections::HashSet<E::Key> = existing
            .iter()
            .filter_map(|ev| match ev {
                FlowEvent::Ended { key, .. } => Some(key.clone()),
                _ => None,
            })
            .collect();
        let mut out = Vec::new();
        for key in poisoned_keys {
            if already_ending.contains(&key) {
                continue;
            }
            let Some(stats) = tracker.snapshot_stats(&key) else {
                continue;
            };
            let history = tracker.snapshot_history(&key).unwrap_or_default();
            tracker.forget(&key);
            crate::obs::record_flow_ended(EndReason::BufferOverflow, &stats);
            crate::obs::trace_flow_ended(EndReason::BufferOverflow, &stats);
            out.push(FlowEvent::Ended {
                key,
                reason: EndReason::BufferOverflow,
                stats,
                history,
            });
        }
        out
    }

    /// Patch reassembly diagnostics into the `FlowStats` of every
    /// `Ended` event in `events`, then drop the corresponding
    /// reassemblers (calling `fin` / `rst` on the way out).
    fn finalize_ended_flows(
        events: &mut [FlowEvent<E::Key>],
        reassemblers: &mut HashMap<(E::Key, FlowSide), F::Reassembler, RandomState>,
    ) {
        for ev in events.iter_mut() {
            // Patch in reassembly diagnostics + drop reassemblers.
            if let FlowEvent::Ended {
                key, reason, stats, ..
            } = ev
            {
                for side in [FlowSide::Initiator, FlowSide::Responder] {
                    if let Some(mut r) = reassemblers.remove(&(key.clone(), side)) {
                        let dropped = r.dropped_segments();
                        let oversize = r.bytes_dropped_oversize();
                        let watermark = r.high_watermark();
                        let retransmits = r.retransmits();
                        match side {
                            FlowSide::Initiator => {
                                stats.reassembly_dropped_ooo_initiator = dropped;
                                stats.reassembly_bytes_dropped_oversize_initiator = oversize;
                                stats.reassembler_high_watermark_initiator = watermark;
                                stats.retransmits_initiator = retransmits;
                            }
                            FlowSide::Responder => {
                                stats.reassembly_dropped_ooo_responder = dropped;
                                stats.reassembly_bytes_dropped_oversize_responder = oversize;
                                stats.reassembler_high_watermark_responder = watermark;
                                stats.retransmits_responder = retransmits;
                            }
                        }
                        match reason {
                            EndReason::Fin | EndReason::IdleTimeout | EndReason::ParserDone => {
                                r.fin()
                            }
                            EndReason::Rst
                            | EndReason::Evicted
                            | EndReason::BufferOverflow
                            | EndReason::ParseError => r.rst(),
                        }
                    }
                }
                // Emit reassembly-diagnostic metrics post-patch.
                // `record_flow_ended` already fired from inside the
                // tracker (or from `synthesise_buffer_overflow_ends`)
                // with unpatched stats; this pass surfaces the
                // reassembler-derived fields once they're filled in.
                crate::obs::record_reassembly_diagnostics(stats);
            }
        }
    }

    /// Borrow the inner tracker (for stats, introspection).
    pub fn tracker(&self) -> &FlowTracker<E, S> {
        &self.tracker
    }

    /// Borrow the inner tracker mutably.
    pub fn tracker_mut(&mut self) -> &mut FlowTracker<E, S> {
        &mut self.tracker
    }

    /// True when [`Self::with_emit_anomalies`] was called with
    /// `true`. Used by wrappers (e.g. [`crate::FlowSessionDriver`])
    /// that need to mirror the same anomaly-emission policy.
    pub fn emits_anomalies(&self) -> bool {
        self.emit_anomalies
    }

    /// Iterate `(key, FlowStats)` for every live flow. Unlike
    /// [`crate::FlowTracker::all_flow_stats`], this combines the
    /// tracker's per-flow stats with **live** reassembler
    /// diagnostics (OOO drops, oversize-byte drops, peak
    /// watermark) so consumers get an up-to-date picture mid-flow.
    ///
    /// Returns a lazy iterator. Each item clones the underlying
    /// [`crate::FlowStats`] (cheap — owned `u64`s + two
    /// `Timestamp`s) and patches in the reassembler-derived
    /// fields. Collect with `.collect::<Vec<_>>()` if you need to
    /// hold the snapshot past further `track()` calls.
    pub fn snapshot_flow_stats(&self) -> impl Iterator<Item = (E::Key, crate::FlowStats)> + '_ {
        self.tracker.flows().map(move |(key, entry)| {
            let mut stats = entry.stats.clone();
            if let Some(r) = self.reassemblers.get(&(key.clone(), FlowSide::Initiator)) {
                stats.reassembly_dropped_ooo_initiator = r.dropped_segments();
                stats.reassembly_bytes_dropped_oversize_initiator = r.bytes_dropped_oversize();
                stats.reassembler_high_watermark_initiator = r.high_watermark();
                stats.retransmits_initiator = r.retransmits();
            }
            if let Some(r) = self.reassemblers.get(&(key.clone(), FlowSide::Responder)) {
                stats.reassembly_dropped_ooo_responder = r.dropped_segments();
                stats.reassembly_bytes_dropped_oversize_responder = r.bytes_dropped_oversize();
                stats.reassembler_high_watermark_responder = r.high_watermark();
                stats.retransmits_responder = r.retransmits();
            }
            (key.clone(), stats)
        })
    }
}

impl<E, S> FlowDriver<E, crate::reassembler::BufferedReassemblerFactory, S>
where
    E: FlowExtractor,
    S: Send + 'static,
{
    /// Drain buffered bytes for the given (key, side) and return
    /// them as a `Vec<u8>`. Returns an empty `Vec` when no
    /// reassembler exists for that key/side or the buffer is empty.
    ///
    /// Specialisation of [`Self::reassembler`] for the
    /// [`crate::BufferedReassemblerFactory`] case — calls
    /// [`crate::BufferedReassembler::take`] on the reassembler.
    /// Used by [`crate::FlowSessionDriver`] between `track_pending`
    /// and `finalize` to harvest payload bytes before ended-flow
    /// reassemblers are dropped.
    pub fn drain_buffer(&mut self, key: &E::Key, side: FlowSide) -> Vec<u8> {
        self.reassemblers
            .get_mut(&(key.clone(), side))
            .map(|r| r.take())
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::FiveTuple;
    use crate::extract::parse::test_frames::*;
    use crate::reassembler::{BufferedReassembler, BufferedReassemblerFactory};
    use crate::{FlowEvent, Timestamp};

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
        #[allow(dead_code)]
        struct MyState(u64);
        let mut d: FlowDriver<_, _, MyState> = FlowDriver::with_state_init(
            FiveTuple::bidirectional(),
            BufferedReassemblerFactory::default(),
            |_key| MyState(7),
        );
        let _ = d.track(view(b"", 0));
        // tracker() returns &FlowTracker<E, MyState>, not <E, ()>.
        let _tracker: &crate::FlowTracker<FiveTuple, MyState> = d.tracker();
    }

    /// Plan 38: `with_state` works for any `S: Default`.
    #[test]
    fn with_state_uses_default() {
        #[derive(Debug, Default)]
        #[allow(dead_code)]
        struct Counter(u32);
        let d: FlowDriver<_, _, Counter> = FlowDriver::with_state(
            FiveTuple::bidirectional(),
            BufferedReassemblerFactory::default(),
        );
        let _tracker: &crate::FlowTracker<FiveTuple, Counter> = d.tracker();
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

    #[test]
    fn ended_event_with_buffer_overflow_reason_drop_flow_policy() {
        // Cap = 64; initiator pushes 200 bytes — should poison and
        // synthesise Ended { reason: BufferOverflow }.
        let factory = BufferedReassemblerFactory::default()
            .with_max_buffer(64)
            .with_overflow_policy(crate::OverflowPolicy::DropFlow);
        let mut d = FlowDriver::<_, _>::new(FiveTuple::bidirectional(), factory);
        let events = drive_simple_tcp_with_data(&mut d);
        let ended = events
            .iter()
            .find_map(|e| match e {
                FlowEvent::Ended { reason, stats, .. } => Some((*reason, stats.clone())),
                _ => None,
            })
            .expect("an Ended event");
        // The first end-of-life event for this flow should be BufferOverflow
        // (the data segment poisons the reassembler before the RST arrives).
        assert_eq!(ended.0, EndReason::BufferOverflow);
        // Diagnostic counters surface the dropped bytes.
        assert!(
            ended.1.reassembly_bytes_dropped_oversize_initiator > 0,
            "expected oversize bytes recorded, got {}",
            ended.1.reassembly_bytes_dropped_oversize_initiator
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

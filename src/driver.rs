//! [`FlowDriver`] — sync wrapper that bundles a [`FlowTracker`] with
//! a [`ReassemblerFactory`] and dispatches TCP segments to the right
//! reassembler.
//!
//! The async equivalent lives in `netring`'s `FlowStream::with_async_reassembler`.

use std::collections::HashMap;

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
struct AnomalySnapshot<K>
where
    K: Eq + std::hash::Hash + Clone,
{
    per_side: HashMap<(K, FlowSide), (u64, u64), RandomState>,
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
}

impl<E, F, S> FlowDriver<E, F, S>
where
    E: FlowExtractor,
    F: ReassemblerFactory<E::Key>,
    S: Default + Send + 'static,
{
    /// Construct with default config and `S::default()` per-flow state.
    pub fn new(extractor: E, factory: F) -> Self {
        Self::with_config(extractor, factory, FlowTrackerConfig::default())
    }

    /// Construct with explicit config.
    pub fn with_config(extractor: E, factory: F, config: FlowTrackerConfig) -> Self {
        Self {
            tracker: FlowTracker::with_config(extractor, config),
            factory,
            reassemblers: HashMap::with_hasher(RandomState::new()),
            emit_anomalies: false,
        }
    }
}

impl<E, F, S> FlowDriver<E, F, S>
where
    E: FlowExtractor,
    F: ReassemblerFactory<E::Key>,
    S: Send + 'static,
{
    /// Opt in to emitting [`FlowEvent::Anomaly`] for buffer overflows,
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

    /// Process one packet. Drives the tracker and dispatches TCP
    /// payloads to the factory's reassemblers. Reassemblers are
    /// created on demand and cleaned up on `Ended`.
    pub fn track(&mut self, view: PacketView<'_>) -> FlowEvents<E::Key> {
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
                r.segment(seq, payload);
            });

        // Emit anomaly events (per-tick coalesced) before synthesising
        // BufferOverflow ends — the overflow that caused the
        // BufferOverflow anomaly should appear before the Ended event.
        if self.emit_anomalies {
            let anomalies = Self::diff_anomaly_state(snapshot, reassemblers, &self.tracker, ts);
            for a in anomalies {
                if let FlowEvent::Anomaly { kind, .. } = &a {
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
        // Patch reassembly diagnostics + drop the reassemblers for
        // ended flows.
        Self::finalize_ended_flows(events.as_mut_slice(), reassemblers);

        events
    }

    /// Run the idle-timeout sweep and clean up reassemblers for
    /// ended flows.
    pub fn sweep(&mut self, now: Timestamp) -> Vec<FlowEvent<E::Key>> {
        let snapshot = self.snapshot_anomaly_state();
        let mut events = self.tracker.sweep(now);
        if self.emit_anomalies {
            let anomalies =
                Self::diff_anomaly_state(snapshot, &self.reassemblers, &self.tracker, now);
            for a in &anomalies {
                if let FlowEvent::Anomaly { kind, .. } = a {
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
        Self::finalize_ended_flows(events.as_mut_slice(), &mut self.reassemblers);
        events
    }

    /// Snapshot the per-reassembler diagnostic counters and the
    /// tracker's eviction total ahead of a `track`/`sweep` call so
    /// the post-call diff can be coalesced into anomaly events.
    fn snapshot_anomaly_state(&self) -> AnomalySnapshot<E::Key> {
        if !self.emit_anomalies {
            return AnomalySnapshot::default();
        }
        let mut per_side: HashMap<(E::Key, FlowSide), (u64, u64), RandomState> =
            HashMap::with_hasher(RandomState::new());
        for ((key, side), r) in &self.reassemblers {
            per_side.insert(
                (key.clone(), *side),
                (r.dropped_segments(), r.bytes_dropped_oversize()),
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
                .unwrap_or((0, 0));
            let cur = (r.dropped_segments(), r.bytes_dropped_oversize());
            let dropped_delta = cur.0.saturating_sub(prev.0);
            let oversize_delta = cur.1.saturating_sub(prev.1);
            if oversize_delta > 0 {
                // Look up the policy via the tracker config; falls
                // back to the default (SlidingWindow) when unset.
                let policy = if r.is_poisoned() {
                    OverflowPolicy::DropFlow
                } else {
                    OverflowPolicy::SlidingWindow
                };
                out.push(FlowEvent::Anomaly {
                    key: Some(key.clone()),
                    kind: AnomalyKind::BufferOverflow {
                        side: *side,
                        bytes: oversize_delta,
                        policy,
                    },
                    ts,
                });
            }
            if dropped_delta > 0 {
                out.push(FlowEvent::Anomaly {
                    key: Some(key.clone()),
                    kind: AnomalyKind::OutOfOrderSegment {
                        side: *side,
                        count: dropped_delta,
                    },
                    ts,
                });
            }
        }
        // Tracker-global eviction pressure.
        let evicted_total = tracker.stats().flows_evicted;
        let evicted_delta = evicted_total.saturating_sub(snapshot.evicted_total);
        if evicted_delta > 0 {
            out.push(FlowEvent::Anomaly {
                key: None,
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
                        match side {
                            FlowSide::Initiator => {
                                stats.reassembly_dropped_ooo_initiator = dropped;
                                stats.reassembly_bytes_dropped_oversize_initiator = oversize;
                            }
                            FlowSide::Responder => {
                                stats.reassembly_dropped_ooo_responder = dropped;
                                stats.reassembly_bytes_dropped_oversize_responder = oversize;
                            }
                        }
                        match reason {
                            EndReason::Fin | EndReason::IdleTimeout => r.fin(),
                            EndReason::Rst | EndReason::Evicted | EndReason::BufferOverflow => {
                                r.rst()
                            }
                        }
                    }
                }
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
            events.extend(driver.track(view(f, 0)).into_iter());
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
                    FlowEvent::Anomaly {
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
            FlowEvent::Anomaly {
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
            !events
                .iter()
                .any(|e| matches!(e, FlowEvent::Anomaly { .. })),
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
                    FlowEvent::Anomaly {
                        kind: AnomalyKind::BufferOverflow { .. },
                        ..
                    }
                )
            })
            .expect("expected a BufferOverflow anomaly");
        match anomaly {
            FlowEvent::Anomaly {
                kind: AnomalyKind::BufferOverflow { policy, .. },
                ..
            } => {
                assert_eq!(*policy, OverflowPolicy::DropFlow);
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
            events.extend(d.track(view(&frame, 0)).into_iter());
        }
        let pressure: Vec<_> = events
            .iter()
            .filter(|e| {
                matches!(
                    e,
                    FlowEvent::Anomaly {
                        kind: AnomalyKind::FlowTableEvictionPressure { .. },
                        ..
                    }
                )
            })
            .collect();
        assert_eq!(pressure.len(), 1, "expected one eviction-pressure anomaly");
        match pressure[0] {
            FlowEvent::Anomaly {
                kind:
                    AnomalyKind::FlowTableEvictionPressure {
                        evicted_in_tick,
                        evicted_total,
                    },
                key,
                ..
            } => {
                assert_eq!(*evicted_in_tick, 1);
                assert_eq!(*evicted_total, 1);
                assert!(key.is_none());
            }
            _ => unreachable!(),
        }
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
}

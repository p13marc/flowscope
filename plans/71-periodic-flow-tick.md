# Plan 71 — Periodic `FlowTick` event

## Summary

Today `FlowStats` only surfaces on `FlowEvent::Ended` /
`SessionEvent::Closed`. `FlowDriver::snapshot_flow_stats()`
exists for pull-style consumers, but two independent consumers
(`des-rs` 2026-05-14 feedback item #1, `simple-nms` 2026-08-11
wishlist F1.5) have now asked for **push-style** periodic
emission so the metrics-export loop can wake up on the same
event stream as the flow lifecycle.

This plan adds an opt-in tick:

- `FlowTrackerConfig::flow_tick_interval: Option<Duration>`
  (default `None` — feature off).
- When `Some(d)`, the driver emits one `FlowEvent::Tick {
  key, stats, ts }` per flow per tick where
  `view.timestamp - last_tick_at >= d`.
- `FlowSessionDriver` / `FlowDatagramDriver` forward as
  `SessionEvent::FlowTick { key, stats, ts }`.

The previous decision to ship only the snapshot accessor
(Plan 46) was right at the time (one consumer), but two
consumers asking is a real signal and the implementation cost
turned out to be smaller than originally estimated.

## Status

Not started. Targets 0.5.0.

## Prerequisites

- Plan 46 (snapshot accessors + high-watermark) — shipped in
  0.3.0. `FlowStats` is the carrier for tick events; the
  snapshot accessor stays as the pull alternative for
  consumers that prefer it.

## Out of scope

- Lazy / streaming `FlowTick` payloads. The tick carries an
  owned `FlowStats` clone — same shape as `Ended.stats`.
  Consumers wanting to project to a smaller payload do so on
  their side.
- Per-flow tick interval overrides. The interval is global per
  driver. Future plan could add a predicate
  (`tick_interval_fn: Fn(&K) -> Option<Duration>`) if real
  demand surfaces, but the global knob covers both reported
  use cases.
- Tick-during-sweep. `sweep()` already pre-empts the natural
  tick rhythm; we don't fire ticks from inside `sweep()`. If a
  flow goes idle between ticks, the next tick after the idle
  period catches up. The sweep emits `Ended` for idle-timed-out
  flows; ticks fire only for live flows.

---

## Files

### MODIFIED

- `src/tracker.rs` — `FlowTrackerConfig` gains
  `flow_tick_interval: Option<Duration>`. `FlowEntry` gains
  `last_tick_at: Option<Timestamp>` (None until first tick
  fires for the flow).
- `src/event.rs` — new `FlowEvent::Tick { key, stats, ts }`
  variant.
- `src/session.rs` — new `SessionEvent::FlowTick { key, stats,
  ts }` variant.
- `src/driver.rs` — after each `track_pending` returns, walk
  live flows and append `FlowEvent::Tick` for any past-due
  (`view.timestamp - last_tick_at >= interval`). Update
  `last_tick_at`.
- `src/session_driver.rs` — translate `FlowEvent::Tick` to
  `SessionEvent::FlowTick` (mirror of the existing
  `FlowEvent::Anomaly` → `SessionEvent::Anomaly` forwarding).
- `src/datagram_driver.rs` — same translation.
- `src/obs.rs` — new `flowscope_flow_ticks_total` counter
  fires from a small `record_flow_tick(key, stats)` helper
  (one increment per tick event).
- `docs/SESSION_GUIDE.md` — new "Periodic flow ticks"
  subsection.
- `docs/OBSERVABILITY.md` — document the new counter.
- `CHANGELOG.md` — 0.5.0 entry.

### NEW

None.

---

## API

### `src/tracker.rs`

```rust
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FlowTrackerConfig {
    // ... existing fields ...
    /// When `Some(d)`, the driver emits one [`FlowEvent::Tick`]
    /// per live flow whenever `view.timestamp - last_tick_at >= d`.
    /// `None` (default) — no tick events emitted.
    ///
    /// Tick timing is driven by packet arrivals — a flow that
    /// goes silent between ticks emits no ticks during the
    /// silence. Use the [`FlowTracker::sweep`] / idle-timeout
    /// machinery for silence detection.
    pub flow_tick_interval: Option<Duration>,
}
```

### `src/event.rs`

```rust
#[derive(Debug, Clone)]
pub enum FlowEvent<K> {
    Started { /* ... */ },
    Packet { /* ... */ },
    Established { /* ... */ },
    StateChange { /* ... */ },
    Ended { /* ... */ },
    Anomaly { /* ... */ },
    /// New in 0.5.0. Periodic snapshot of [`FlowStats`] for a
    /// live flow. Emitted only when
    /// [`FlowTrackerConfig::flow_tick_interval`] is `Some`.
    ///
    /// `stats` is an owned clone — consumers can keep it past
    /// the next `track()` call. Reassembly diagnostic fields
    /// (OOO drops, oversize bytes, watermark, retransmits) are
    /// patched in just like on `Ended`, so each tick is a
    /// self-contained snapshot.
    Tick {
        key: K,
        stats: FlowStats,
        ts: Timestamp,
    },
}
```

### `src/session.rs`

```rust
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SessionEvent<K, M> {
    Started { /* ... */ },
    Application { /* ... */ },
    Closed { /* ... */ },
    Anomaly { /* ... */ },
    /// New in 0.5.0. Periodic [`FlowStats`] snapshot for a
    /// live session. Mirrors [`crate::FlowEvent::Tick`].
    FlowTick {
        key: K,
        stats: FlowStats,
        ts: Timestamp,
    },
}
```

### `src/driver.rs` — tick emission

```rust
impl<E, F, S> FlowDriver<E, F, S>
where
    E: FlowExtractor,
    F: ReassemblerFactory<E::Key>,
    S: Send + 'static,
{
    pub fn track_pending(&mut self, view: PacketView<'_>) -> FlowEvents<E::Key> {
        // ... existing dedup + monotonic-ts + tracker dispatch ...
        let mut events = self.tracker.track_with_payload(view, /* ... */);

        // Existing: anomaly diff, BufferOverflow synthesis.

        // New (Plan 71): tick emission. Only when configured.
        if let Some(interval) = self.tracker.config().flow_tick_interval {
            self.emit_ticks(&mut events, ts, interval);
        }

        events
    }

    fn emit_ticks(
        &mut self,
        events: &mut FlowEvents<E::Key>,
        now: Timestamp,
        interval: Duration,
    ) {
        // Walk live flows; emit Tick for each past-due. The
        // tracker exposes a small new mut accessor for
        // `last_tick_at`.
        let mut to_tick: Vec<(E::Key, FlowStats)> = Vec::new();
        for (key, entry) in self.tracker.flows() {
            let due = match entry.last_tick_at {
                None => true,
                Some(last) => now.saturating_sub(last) >= interval,
            };
            if !due {
                continue;
            }
            // Build a full FlowStats snapshot (including
            // reassembler diagnostics) — reuse the same logic
            // as `snapshot_flow_stats`.
            let stats = self.build_snapshot_for(key);
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
}
```

### `src/tracker.rs` — small accessor

```rust
impl<E: FlowExtractor, S> FlowTracker<E, S> {
    /// Update the `last_tick_at` timestamp for a live flow.
    /// Used by the driver after emitting a `Tick` event.
    /// Returns `false` when the key is unknown.
    pub(crate) fn mark_ticked(&mut self, key: &E::Key, now: Timestamp) -> bool {
        if let Some(entry) = self.flows.peek_mut(key) {
            entry.last_tick_at = Some(now);
            true
        } else {
            false
        }
    }
}
```

`mark_ticked` is `pub(crate)` — only the driver needs it. The
`last_tick_at` field on `FlowEntry` is `pub` (matching the
existing convention; consumers can read it but the driver
manages writes).

### `src/session_driver.rs` — forwarding

```rust
fn translate_events(
    &mut self,
    flow_events: &[FlowEvent<E::Key>],
) -> Vec<SessionEvent<E::Key, P::Message>> {
    let mut out = Vec::new();
    for ev in flow_events {
        match ev {
            // ... existing variants ...
            FlowEvent::Tick { key, stats, ts } => {
                out.push(SessionEvent::FlowTick {
                    key: key.clone(),
                    stats: stats.clone(),
                    ts: *ts,
                });
            }
        }
    }
    out
}
```

### `src/obs.rs`

```rust
pub const METRIC_FLOW_TICKS: &str = "flowscope_flow_ticks_total";

#[cfg(feature = "metrics")]
pub(crate) fn record_flow_tick(_stats: &FlowStats) {
    metrics::counter!(METRIC_FLOW_TICKS).increment(1);
}

#[cfg(not(feature = "metrics"))]
#[inline(always)]
pub(crate) fn record_flow_tick(_stats: &FlowStats) {}
```

---

## Implementation steps

1. **`FlowTrackerConfig::flow_tick_interval`** field +
   `FlowEntry::last_tick_at`. Default values preserve current
   behaviour.
2. **`FlowEvent::Tick`** + **`SessionEvent::FlowTick`**
   variants. Both enums are already `#[non_exhaustive]`; the
   additions are forward-compatible at the enum level.
   External match blocks need a new arm or wildcard.
3. **`FlowDriver::emit_ticks`** helper. Reuses
   `snapshot_flow_stats`-style stats-build but writes results
   into the event stream.
4. **`FlowTracker::mark_ticked`** pub(crate) accessor.
5. **`FlowSessionDriver` / `FlowDatagramDriver`** — translate
   `FlowEvent::Tick` to `SessionEvent::FlowTick`.
6. **`obs::record_flow_tick`** + `METRIC_FLOW_TICKS`. One
   counter per tick fired.
7. **Tests**: unit on tick timing, integration through both
   drivers, metric smoke test.
8. **SESSION_GUIDE.md** "Periodic flow ticks" subsection.
9. **OBSERVABILITY.md** new metric.
10. **CHANGELOG.md** 0.5.0 entry.

---

## Tests

```rust
#[test]
fn no_ticks_when_interval_unset() {
    let mut d = FlowDriver::<_, _>::new(
        FiveTuple::bidirectional(),
        BufferedReassemblerFactory::default(),
    );
    let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"x");
    let events = d.track(PacketView::new(&f, Timestamp::new(0, 0)));
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
    let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"x");
    let events = d.track(PacketView::new(&f, Timestamp::new(0, 0)));
    let tick = events.iter().find(|e| matches!(e, FlowEvent::Tick { .. }));
    assert!(tick.is_some(), "first packet should emit initial tick");
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
    let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"x");
    d.track(PacketView::new(&f, Timestamp::new(0, 0))); // tick @ 0
    let ev_5s = d.track(PacketView::new(&f, Timestamp::new(5, 0)));
    let ev_15s = d.track(PacketView::new(&f, Timestamp::new(15, 0)));
    assert!(!ev_5s.iter().any(|e| matches!(e, FlowEvent::Tick { .. })));
    assert!(ev_15s.iter().any(|e| matches!(e, FlowEvent::Tick { .. })));
}

#[test]
fn tick_carries_full_stats_including_reassembler_diagnostics() {
    let factory = BufferedReassemblerFactory::default().with_max_buffer(64);
    let cfg = FlowTrackerConfig {
        flow_tick_interval: Some(Duration::from_secs(1)),
        ..FlowTrackerConfig::default()
    };
    let mut d = FlowDriver::<_, _>::with_config(
        FiveTuple::bidirectional(),
        factory,
        cfg,
    );
    // 3WHS + 200B initiator data → reassembler hits cap.
    // Advance time, send a marker packet, expect Tick with
    // oversize bytes patched in.
    // ... (test scaffold mirrors the existing snapshot test) ...
}

#[test]
fn session_driver_forwards_tick_as_flow_tick() {
    let cfg = FlowTrackerConfig {
        flow_tick_interval: Some(Duration::from_secs(10)),
        ..FlowTrackerConfig::default()
    };
    let mut d = FlowSessionDriver::<_, LineParser>::with_config(
        FiveTuple::bidirectional(),
        cfg,
    );
    // Drive a flow; expect SessionEvent::FlowTick.
    // ...
}
```

Metrics integration test (extending
`tests/metrics_integration.rs`):

```rust
assert!(counter_value(&rows, METRIC_FLOW_TICKS, None) >= 1);
```

---

## Acceptance criteria

- [ ] `FlowTrackerConfig::flow_tick_interval: Option<Duration>`
      field exists; default `None`.
- [ ] `FlowEvent::Tick { key, stats, ts }` variant exists.
- [ ] `SessionEvent::FlowTick { key, stats, ts }` variant exists.
- [ ] When `flow_tick_interval = None`, no Tick events are
      emitted (existing tests + behaviour unchanged).
- [ ] When set, first packet for a flow emits a Tick; subsequent
      packets emit Ticks only after `interval` elapsed
      (sequence-comparison on `Timestamp`).
- [ ] Tick payload carries reassembler-diagnostic fields
      (OOO, oversize bytes, watermark, retransmits per Plan 70).
- [ ] `FlowSessionDriver` and `FlowDatagramDriver` forward as
      `SessionEvent::FlowTick`.
- [ ] `flowscope_flow_ticks_total` counter increments per emit.
- [ ] SESSION_GUIDE.md "Periodic flow ticks" subsection added.
- [ ] OBSERVABILITY.md documents the new counter.
- [ ] CHANGELOG entry under 0.5.0.
- [ ] `cargo clippy --all-features --all-targets -- -D warnings` clean.

---

## Risks

1. **Tick volume.** At 100k live flows × 10s interval, that's
   10k ticks/second. The driver's `emit_ticks` walks live flows
   linearly — acceptable below ~50k flows, possibly a hot spot
   above. Mitigation: a future plan could add a per-flow
   "next tick deadline" min-heap if needed. For 0.5.0, the
   linear walk is fine and matches the existing
   `snapshot_flow_stats` cost model.
2. **`emit_ticks` allocation pattern.** Per the sketch, the
   to_tick Vec collects then drains. Could be avoided with a
   smarter borrow-iteration pattern, but the simple shape is
   easier to read and the allocation is bounded by live-flow
   count.
3. **Timestamp source = packet timestamp.** Ticks fire on
   packet arrival, not wall clock. A flow that goes silent
   doesn't tick — silence is detected via the existing
   `idle_timeout_*` machinery, which is the right tool for
   that question. Document.
4. **Interaction with `with_monotonic_timestamps`.** Tick
   timing uses the clamped `ts` (post-monotonisation). Same
   convention as the rest of the driver. Document.
5. **`#[non_exhaustive]` on the enums** already exists; the
   new variants don't require wildcard arms internally (our
   own `match` blocks need updating; clippy catches that).
6. **Conflict with `on_tick` parser hook (Plan 36).** Different
   layer: `SessionParser::on_tick` is per-parser and called by
   the driver under the same `flow_tick_interval` knob. Plan
   71's `FlowEvent::Tick` is per-flow stats. The two are
   orthogonal but related — both wake up at the same interval.
   Document.

---

## Effort

- LOC: ~180 (config field + 2 enum variants + driver helper +
  forwarding + metric + tests).
- Time: 1 day.

---

## Provenance

Two consumers asked for this:
- `docs/feedback-2026-05-14-des-rs.md` item #1 (the
  "periodic emission" half I previously declined as snapshot-
  only).
- `docs/feedback-2026-08-11-simple-nms.md` item F1.5.

Two-consumer demand is the threshold for revisiting a
declined ask. The snapshot accessor (Plan 46) stays as the
pull alternative; ticks are the push alternative. Both ship.

Plan 71's design notes mention "fixed the previously-noted
sync-driver-clock issue" — the answer is to drive tick timing
off the packet's timestamp rather than wall time. That makes
the sync driver work cleanly with no system-clock dependency.

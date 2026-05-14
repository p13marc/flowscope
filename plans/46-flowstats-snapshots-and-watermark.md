# Plan 46 — FlowStats live snapshots + reassembler high-watermark

## Summary

Two coupled additions to the `FlowStats` surface:

1. **Reassembler high-watermark fields** on `FlowStats`. Tracks
   the peak buffer occupancy ever observed per side. Trivial to
   maintain (one `max(prev, cur)` per segment) and extremely
   valuable for `max_reassembler_buffer` tuning.
2. **Live snapshot accessors** so consumers can observe a flow's
   `FlowStats` mid-lifetime, not only on `Ended`. Long-lived flows
   (hours-long DES publisher connections, persistent TLS tunnels,
   gRPC streams) never emit `Ended` in practice; the stats are
   already there, just inaccessible.

Both go through `FlowDriver` and `FlowSessionDriver` so the live
snapshots include current reassembler diagnostics
(`reassembly_dropped_ooo_*`, `bytes_dropped_oversize`,
high-watermark).

## Status

Not started. Targets 0.3.0 ([Plan 45](./45-release-0.3.0.md)).

## Prerequisites

- Plan 42 §2 — `FlowStats` is `#[non_exhaustive]`, reassembly
  diagnostic fields surfaced on `Ended`. Shipped in 0.2.0.
- Plan 42 §1 — `BufferedReassembler` with overflow accounting.
  Shipped in 0.2.0.

## Out of scope

- Periodic `FlowTick` event emission on the stream. The feedback
  report (item #1) proposed two API shapes — periodic events and
  a snapshot accessor. This plan ships only the snapshot accessor;
  see [Plan 45](./45-release-0.3.0.md) §Rejected proposals for the
  rationale.
- Per-message accumulation of histogram-style stats (latency
  percentiles, message size distributions). Out of band — that's
  a metrics-feature responsibility, not `FlowStats`.
- Surfacing watermark on every per-packet `FlowEvent`. Watermark
  belongs in `FlowStats` (which already lands on `Ended` and via
  the new snapshot accessors); adding it to every `Packet` event
  inflates the hot path for no consumer use case.

---

## Files

### MODIFIED

- `src/event.rs` — add two new fields to `FlowStats`
  (`reassembler_high_watermark_initiator`,
  `reassembler_high_watermark_responder`).
- `src/reassembler.rs` — new `Reassembler::high_watermark()` trait
  method (default 0); `BufferedReassembler` tracks the watermark
  internally on every `append_with_cap`.
- `src/tracker.rs` — bulk snapshot accessor
  `FlowTracker::all_flow_stats()`.
- `src/driver.rs` — live snapshot accessor
  `FlowDriver::snapshot_flow_stats()` that combines tracker stats
  with live reassembler diagnostics. Patch the watermark fields
  into `Ended` events alongside the existing diagnostic patching.
- `src/session_driver.rs` — corresponding
  `FlowSessionDriver::snapshot_flow_stats()`.
- `src/obs.rs` — extend `record_flow_ended` to include the new
  watermark fields in the `flowscope_reassembler_high_watermark_*`
  metric.
- `docs/SESSION_GUIDE.md` — extend "Reassembly health" with a
  paragraph on live snapshots and watermark tuning.
- `docs/OBSERVABILITY.md` — document the new metric.
- `CHANGELOG.md` — 0.3.0 entry.

### NEW

None.

---

## API

### `src/event.rs` — `FlowStats` additions

```rust
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct FlowStats {
    // existing fields ...
    pub reassembly_dropped_ooo_initiator: u64,
    pub reassembly_dropped_ooo_responder: u64,
    pub reassembly_bytes_dropped_oversize_initiator: u64,
    pub reassembly_bytes_dropped_oversize_responder: u64,

    /// New in 0.3.0. Peak in-flight buffer occupancy ever observed
    /// for the initiator-side reassembler. Useful for tuning
    /// [`crate::FlowTrackerConfig::max_reassembler_buffer`].
    ///
    /// Populated by [`crate::FlowDriver`] / [`crate::FlowSessionDriver`]
    /// when the flow ends and on live-snapshot accessors. Zero when
    /// the consumer used [`crate::FlowTracker`] directly without a
    /// reassembler factory.
    pub reassembler_high_watermark_initiator: u64,
    pub reassembler_high_watermark_responder: u64,
}
```

`FlowStats` is already `#[non_exhaustive]` (from Plan 42 §2), so
adding the fields is purely additive for external consumers.

### `src/reassembler.rs` — trait method

```rust
pub trait Reassembler: Send + 'static {
    // existing methods ...

    /// Peak buffer occupancy ever observed for this side. Default: 0
    /// (custom reassemblers may not track this).
    ///
    /// A default-zero return means "this implementation doesn't
    /// track that counter," not "the buffer never had bytes in it."
    fn high_watermark(&self) -> u64 {
        0
    }
}
```

### `src/reassembler.rs` — `BufferedReassembler` implementation

```rust
#[derive(Debug, Default)]
pub struct BufferedReassembler {
    // existing fields ...
    high_watermark: u64,
}

impl BufferedReassembler {
    /// Peak buffer occupancy ever observed.
    pub fn high_watermark(&self) -> u64 {
        self.high_watermark
    }

    // append_with_cap updates the watermark *after* the
    // buffer mutation so it reflects the post-segment state:
    fn append_with_cap(&mut self, payload: &[u8]) {
        // ... existing buffer manipulation ...
        self.high_watermark = self.high_watermark.max(self.buffer.len() as u64);
    }
}

impl Reassembler for BufferedReassembler {
    // existing overrides ...

    fn high_watermark(&self) -> u64 {
        Self::high_watermark(self)
    }
}
```

The watermark update lives at the bottom of `append_with_cap` so
it captures occupancy after rotation in `SlidingWindow` mode (i.e.
the max ever seen post-rotation, which is the meaningful number
for cap tuning).

### `src/tracker.rs` — bulk snapshot

```rust
impl<E: FlowExtractor, S> FlowTracker<E, S> {
    /// Iterate `(key, &FlowStats)` over every live flow without
    /// touching LRU order. Reassembly diagnostic fields
    /// (`reassembly_dropped_ooo_*`, `bytes_dropped_oversize_*`,
    /// `reassembler_high_watermark_*`) are **stale** through this
    /// accessor — the tracker doesn't own the reassemblers.
    ///
    /// For live reassembly diagnostics, use
    /// [`crate::FlowDriver::snapshot_flow_stats`] or
    /// [`crate::FlowSessionDriver::snapshot_flow_stats`] which
    /// combine the tracker stats with live reassembler state.
    pub fn all_flow_stats(&self) -> impl Iterator<Item = (&E::Key, &FlowStats)> {
        self.flows.iter().map(|(k, e)| (k, &e.stats))
    }
}
```

The existing `FlowTracker::flows()` returns `(K, FlowEntry)` —
the new accessor projects to just the `FlowStats`, which is the
common case for stats consumers.

### `src/driver.rs` — live snapshot with reassembler context

```rust
impl<E, F, S> FlowDriver<E, F, S>
where
    E: FlowExtractor,
    F: ReassemblerFactory<E::Key>,
    S: Send + 'static,
{
    /// Return a `FlowStats` snapshot for every live flow. Unlike
    /// [`crate::FlowTracker::all_flow_stats`], this combines the
    /// tracker's per-flow stats with **live** reassembler
    /// diagnostics (OOO drops, oversize-byte drops, peak watermark)
    /// so consumers get an up-to-date picture mid-flow.
    ///
    /// Returned values are owned `FlowStats` clones, decoupling
    /// the borrow lifetime from the driver. Allocation is
    /// proportional to live-flow count; for very large flow
    /// tables (>>10k flows) prefer iterating
    /// [`crate::FlowTracker::all_flow_stats`] and patching
    /// reassembler fields manually.
    pub fn snapshot_flow_stats(&self) -> Vec<(E::Key, FlowStats)> {
        let mut out = Vec::with_capacity(self.tracker.flow_count());
        for (key, entry) in self.tracker.flows() {
            let mut stats = entry.stats.clone();
            for side in [FlowSide::Initiator, FlowSide::Responder] {
                if let Some(r) = self.reassemblers.get(&(key.clone(), side)) {
                    let dropped = r.dropped_segments();
                    let oversize = r.bytes_dropped_oversize();
                    let watermark = r.high_watermark();
                    match side {
                        FlowSide::Initiator => {
                            stats.reassembly_dropped_ooo_initiator = dropped;
                            stats.reassembly_bytes_dropped_oversize_initiator = oversize;
                            stats.reassembler_high_watermark_initiator = watermark;
                        }
                        FlowSide::Responder => {
                            stats.reassembly_dropped_ooo_responder = dropped;
                            stats.reassembly_bytes_dropped_oversize_responder = oversize;
                            stats.reassembler_high_watermark_responder = watermark;
                        }
                    }
                }
            }
            out.push((key.clone(), stats));
        }
        out
    }
}
```

### `src/session_driver.rs` — same surface

```rust
impl<E, P, S> FlowSessionDriver<E, P, S> {
    pub fn snapshot_flow_stats(&self) -> Vec<(E::Key, FlowStats)> {
        // same implementation, just borrows the inner FlowDriver's
        // reassemblers (assuming Plan 51's refactor lands — then
        // this delegates to self.driver.snapshot_flow_stats())
    }
}
```

### `src/driver.rs` — `finalize_ended_flows` extension

Extend the existing patch loop to copy the watermark fields too.
One additional pair of writes per side per Ended event.

```rust
fn finalize_ended_flows(/* ... */) {
    for ev in events.iter_mut() {
        if let FlowEvent::Ended { key, reason, stats, .. } = ev {
            for side in [FlowSide::Initiator, FlowSide::Responder] {
                if let Some(mut r) = reassemblers.remove(&(key.clone(), side)) {
                    let dropped = r.dropped_segments();
                    let oversize = r.bytes_dropped_oversize();
                    let watermark = r.high_watermark();  // new
                    match side {
                        FlowSide::Initiator => {
                            stats.reassembly_dropped_ooo_initiator = dropped;
                            stats.reassembly_bytes_dropped_oversize_initiator = oversize;
                            stats.reassembler_high_watermark_initiator = watermark;  // new
                        }
                        FlowSide::Responder => {
                            // mirror ...
                        }
                    }
                    // existing fin/rst dispatch
                }
            }
        }
    }
}
```

### `src/obs.rs` — metric

```rust
pub const METRIC_REASSEMBLER_HIGH_WATERMARK: &str =
    "flowscope_reassembler_high_watermark_bytes";
```

In `record_flow_ended` (already feature-gated on `metrics`), when
either watermark > 0 record as a histogram (per-side label):

```rust
metrics::histogram!(METRIC_REASSEMBLER_HIGH_WATERMARK, "side" => "initiator")
    .record(stats.reassembler_high_watermark_initiator as f64);
metrics::histogram!(METRIC_REASSEMBLER_HIGH_WATERMARK, "side" => "responder")
    .record(stats.reassembler_high_watermark_responder as f64);
```

A histogram (not counter) so consumers can compute percentiles
across flows for tuning.

---

## Implementation steps

1. **Add `high_watermark` field + `high_watermark()` accessor** on
   `BufferedReassembler`. Update `append_with_cap` to write the
   max. Add `Reassembler::high_watermark()` trait method with
   default 0; override on `BufferedReassembler`.
2. **Extend `FlowStats`** with the two new fields. Default 0 via
   `#[derive(Default)]`.
3. **Update `FlowDriver::finalize_ended_flows`** to patch the
   watermark into `Ended.stats`. Same shape as existing oversize
   patching.
4. **Add `FlowTracker::all_flow_stats()`**. Trivial — projects
   over the existing `flows()` iterator.
5. **Add `FlowDriver::snapshot_flow_stats()`** that combines
   tracker stats with live reassembler diagnostics.
6. **Add `FlowSessionDriver::snapshot_flow_stats()`** that does
   the same. If Plan 51 lands the `FlowDriver` refactor first,
   delegate to the inner driver. Otherwise inline the logic
   (and refactor later when Plan 51 lands).
7. **Wire the metric**: add `METRIC_REASSEMBLER_HIGH_WATERMARK`
   constant, extend `record_flow_ended` to emit the histogram.
8. **Add tests** (see Tests section).
9. **Update SESSION_GUIDE.md** — extend "Reassembly health" with
   a paragraph on watermark tuning and the live snapshot
   accessors.
10. **Update OBSERVABILITY.md** — document the new metric.
11. **CHANGELOG entry** under 0.3.0.

---

## Tests

### `src/reassembler.rs` (unit)

```rust
#[test]
fn high_watermark_tracks_peak_buffer() {
    let mut r = BufferedReassembler::new();
    r.segment(0, &[b'a'; 50]);
    assert_eq!(r.high_watermark(), 50);
    let _ = r.take(); // drains buffer but does not reset watermark
    assert_eq!(r.high_watermark(), 50);
    r.segment(50, &[b'b'; 20]);
    assert_eq!(r.high_watermark(), 50, "20 < 50, watermark unchanged");
    r.segment(70, &[b'c'; 100]);
    assert_eq!(r.high_watermark(), 120);
}

#[test]
fn high_watermark_reflects_post_rotation_state_for_sliding_window() {
    // Cap = 100, sliding window. Push 80, then 80 more → 60 dropped
    // from front, buffer ends at 100. Watermark is 100.
    let mut r = BufferedReassembler::new().with_max_buffer(100);
    r.segment(0, &[b'a'; 80]);
    assert_eq!(r.high_watermark(), 80);
    r.segment(80, &[b'b'; 80]);
    assert_eq!(r.high_watermark(), 100);
}

#[test]
fn high_watermark_zero_for_drop_flow_after_poison() {
    // Cap = 100, drop-flow. Push 80, then 80 more → poison.
    // Watermark is 80 (pre-overflow peak); post-poison segments
    // are no-ops.
    let mut r = BufferedReassembler::new()
        .with_max_buffer(100)
        .with_overflow_policy(OverflowPolicy::DropFlow);
    r.segment(0, &[b'a'; 80]);
    assert_eq!(r.high_watermark(), 80);
    r.segment(80, &[b'b'; 80]);
    assert!(r.is_poisoned());
    assert_eq!(r.high_watermark(), 80);
    r.segment(160, &[b'c'; 10]);
    assert_eq!(r.high_watermark(), 80, "no-op segments don't bump watermark");
}
```

### `src/driver.rs` (integration)

```rust
#[test]
fn ended_event_carries_high_watermark() {
    let factory = BufferedReassemblerFactory::default();
    let mut d = FlowDriver::<_, _>::new(FiveTuple::bidirectional(), factory);
    let events = drive_simple_tcp_with_data(&mut d);
    let ended = events
        .into_iter()
        .find_map(|e| match e {
            FlowEvent::Ended { stats, .. } => Some(stats),
            _ => None,
        })
        .expect("an Ended event");
    assert_eq!(ended.reassembler_high_watermark_initiator, 200);
    assert_eq!(ended.reassembler_high_watermark_responder, 0);
}

#[test]
fn snapshot_flow_stats_returns_live_diagnostics_mid_flow() {
    let factory = BufferedReassemblerFactory::default().with_max_buffer(64);
    let mut d = FlowDriver::<_, _>::new(FiveTuple::bidirectional(), factory);
    // 3WHS + 200B initiator data — flow is still alive after this.
    for f in build_3whs() {
        d.track(view(&f, 0));
    }
    let mac = [0u8; 6];
    let data = ipv4_tcp(
        mac, mac,
        [10, 0, 0, 1], [10, 0, 0, 2],
        1234, 80, 1001, 5001, 0x18,
        &vec![b'A'; 200],
    );
    d.track(view(&data, 0));
    let snapshot = d.snapshot_flow_stats();
    assert_eq!(snapshot.len(), 1, "flow is still alive");
    let (_key, stats) = &snapshot[0];
    // Watermark reflects post-rotation peak (sliding window cap = 64).
    assert_eq!(stats.reassembler_high_watermark_initiator, 64);
    // Bytes dropped: 200 - 64 = 136
    assert_eq!(stats.reassembly_bytes_dropped_oversize_initiator, 136);
}

#[test]
fn all_flow_stats_tracker_only_does_not_populate_reassembler_fields() {
    let mut t = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
    for f in build_3whs() {
        t.track(view(&f, 0));
    }
    let stats: Vec<_> = t.all_flow_stats().collect();
    assert_eq!(stats.len(), 1);
    let (_, s) = &stats[0];
    // Tracker doesn't own reassemblers → reassembler fields are 0.
    assert_eq!(s.reassembler_high_watermark_initiator, 0);
}
```

### `src/session_driver.rs` (integration)

```rust
#[test]
fn session_driver_snapshot_includes_watermark() {
    let mut d = FlowSessionDriver::<_, LineParser>::new(FiveTuple::bidirectional());
    for f in build_3whs() {
        d.track(view(&f, 0));
    }
    let mac = [0u8; 6];
    let data = ipv4_tcp(
        mac, mac,
        [10, 0, 0, 1], [10, 0, 0, 2],
        1234, 80, 1001, 5001, 0x18,
        b"hello\n",
    );
    d.track(view(&data, 0));
    let snapshot = d.snapshot_flow_stats();
    assert_eq!(snapshot.len(), 1);
    let (_, stats) = &snapshot[0];
    assert!(stats.reassembler_high_watermark_initiator > 0);
}
```

### Doctest in `BufferedReassembler::high_watermark`

```rust
/// ```
/// use flowscope::{Reassembler, BufferedReassembler};
/// let mut r = BufferedReassembler::new();
/// r.segment(0, &[0u8; 100]);
/// assert_eq!(r.high_watermark(), 100);
/// let _ = r.take();
/// assert_eq!(r.high_watermark(), 100); // not reset by take()
/// ```
```

---

## Acceptance criteria

- [ ] `Reassembler::high_watermark()` trait method exists with
      default-zero impl; `BufferedReassembler` overrides it.
- [ ] `BufferedReassembler::high_watermark` field tracks the
      post-segment peak across in-order segments and post-rotation
      occupancy under `SlidingWindow`.
- [ ] `FlowStats::reassembler_high_watermark_{initiator,responder}`
      fields exist; populated by `FlowDriver` on `Ended` and via
      `snapshot_flow_stats`.
- [ ] `FlowTracker::all_flow_stats()` returns a borrow-iterator
      over `(key, &FlowStats)` for every live flow.
- [ ] `FlowDriver::snapshot_flow_stats()` returns owned clones
      with reassembler diagnostics merged in.
- [ ] `FlowSessionDriver::snapshot_flow_stats()` mirrors the
      driver-side accessor.
- [ ] `flowscope_reassembler_high_watermark_bytes` histogram metric
      fires on every `Ended` with side label.
- [ ] SESSION_GUIDE.md "Reassembly health" extended.
- [ ] OBSERVABILITY.md documents the new metric.
- [ ] CHANGELOG entry under 0.3.0.
- [ ] `cargo clippy --all-features --all-targets -- -D warnings` clean.

---

## Risks

1. **Watermark semantics under `SlidingWindow`.** "Peak buffer
   occupancy" is ambiguous — instantaneous peak (pre-rotation) vs
   post-rotation peak. This plan picks post-rotation (after
   `append_with_cap` finishes mutating the buffer). Rationale:
   that's the value users tuning `max_reassembler_buffer` care
   about — "how full does the buffer actually get in steady state."
   Document the choice in the rustdoc.
2. **Snapshot allocation cost.** `snapshot_flow_stats` allocates
   one `Vec` of `(K, FlowStats)` per call. At 10k flows × ~80 bytes
   per `FlowStats` clone = ~800 KB per call. Document this; suggest
   `FlowTracker::all_flow_stats()` for borrowed iteration when
   reassembler diagnostics aren't needed.
3. **`E::Key: Clone` requirement.** Already in the trait bound
   (`FlowExtractor::Key: Clone`). No new constraint.
4. **Snapshot during driver mutation.** `snapshot_flow_stats`
   takes `&self`, not `&mut self` — safe to call between
   `track()` calls. Document that it must NOT be called from
   within a `payload_cb` closure (currently no API path that
   allows this — the closure receives `&mut FlowTracker` indirectly
   via the tracker's borrow, but the driver's `&self` is
   inaccessible).
5. **`Reassembler` trait additions.** Adding a default-zero method
   is purely additive and matches the project convention recorded
   in INDEX.md (single-vocabulary discipline). No third-party
   impls break.

---

## Effort

- LOC: ~250 (reassembler watermark + FlowStats fields + 3 new
  accessors + driver patch loop extension + metric + ~80 LOC tests).
- Time: 1 day.

---

## Provenance

Reported as items #1 (snapshots) and #2 (high-watermark) in
`flowscope-feedback-2026-05-14.md` (des-rs team). Item #1 was
proposed in two API shapes: this plan picks the snapshot accessor
shape ([Plan 45](./45-release-0.3.0.md) §Rejected proposals
explains why we didn't pick the periodic event shape).

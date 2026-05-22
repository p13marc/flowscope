# Plan 44 — `BufferedReassembler::with_high_watermark_threshold`

## 1. Summary

`FlowStats` already carries `reassembler_high_watermark_*` (peak
buffer occupancy per side), but only at flow-end. For tuning
`max_reassembler_buffer` in production, operators want **live**
signal: "buffer crossed 80 % of cap, here's how close we are" —
before `BufferOverflow` bites and forces a `SlidingWindow` drop or
`DropFlow` end.

Add a configurable threshold on `BufferedReassembler` (off by
default). When occupancy crosses the threshold from below, fire one
anomaly per crossing (de-bounced) carrying side, current bytes,
cap, and the threshold percent. Surfaces through the existing
anomaly event + metrics vocabulary.

## 2. Status

Not started.

## 3. Prerequisites

None — independent of the driver `S` work (plan 38) and the anomaly
event split (plan 43). If plan 43 lands first the new
`ReassemblerHighWatermark` variant routes into the new
`FlowAnomaly` event; if not, into the existing `Anomaly { key:
Some(_), … }`. Mechanical.

## 4. Out of scope

- Surfacing watermark on the non-`BufferedReassembler` `Reassembler`
  impls. Custom impls opt in by setting the threshold on their own
  configuration; the trait method `bytes_in_flight` is defaulted.
- Per-flow-key threshold overrides. Global setting on the factory.
- Falling-edge anomalies (when occupancy drops below threshold).
  Possible later; out of scope for this plan.

## 5. Files

| File | Change |
|------|--------|
| `src/reassembler.rs` | Add defaulted `Reassembler::bytes_in_flight() -> u64`; implement on `BufferedReassembler`; add `with_high_watermark_threshold(u8)`; corresponding `BufferedReassemblerFactory::with_high_watermark_threshold`. |
| `src/event.rs` | Add `AnomalyKind::ReassemblerHighWatermark { side, bytes, cap, threshold_pct }`. |
| `src/driver.rs` | `snapshot_anomaly_state` and `diff_anomaly_state` consult `bytes_in_flight()` + per-side "already-fired" state to emit one crossing event per below→above transition. |
| `src/obs.rs` | `anomaly_label` arm for the new variant (project convention: single vocabulary across event + metrics). |
| `src/tracker.rs` | `FlowTrackerConfig::reassembler_high_watermark_pct: Option<u8>` so the default factory picks it up via `FlowDriver::with_config`. |
| Tests in `reassembler.rs`, `driver.rs` | Threshold crossing fires once; doesn't spam on repeated above-threshold ticks. |
| `docs/SESSION_GUIDE.md` (recovery-after-buffer-cap section), `docs/OBSERVABILITY.md` (metric vocabulary). |
| `CHANGELOG.md` | Additive entry. |

## 6. API

```rust
// ── Reassembler trait ───────────────────────────────────────
pub trait Reassembler: Send + 'static {
    // … existing methods …

    /// Current bytes buffered, awaiting parser consumption.
    /// Default: `0` for impls that don't track it.
    fn bytes_in_flight(&self) -> u64 { 0 }
}

// ── BufferedReassembler ────────────────────────────────────
impl BufferedReassembler {
    /// Fire an [`AnomalyKind::ReassemblerHighWatermark`] anomaly
    /// when buffer occupancy crosses `percent` % of `max_buffer`,
    /// once per below→above transition. Default off.
    ///
    /// No effect unless `with_max_buffer` is also set. Values
    /// outside `1..=100` are clamped to `1..=100`.
    pub fn with_high_watermark_threshold(mut self, percent: u8) -> Self;
}

impl BufferedReassemblerFactory {
    pub fn with_high_watermark_threshold(mut self, percent: u8) -> Self;
}

// ── FlowTrackerConfig ───────────────────────────────────────
pub struct FlowTrackerConfig {
    // … existing fields …
    /// Companion to `max_reassembler_buffer`: when set, the default
    /// [`BufferedReassemblerFactory`] used by
    /// [`crate::FlowDriver::with_config`] fires a
    /// `ReassemblerHighWatermark` anomaly when buffer occupancy
    /// crosses this percentage of `max_reassembler_buffer`. No
    /// effect unless `max_reassembler_buffer` is `Some`.
    pub reassembler_high_watermark_pct: Option<u8>,
}

// ── AnomalyKind ─────────────────────────────────────────────
#[non_exhaustive]
pub enum AnomalyKind {
    // … existing …
    /// Reassembler buffer occupancy crossed the configured
    /// threshold of its cap (one crossing = one event).
    ReassemblerHighWatermark {
        side: FlowSide,
        /// Current `bytes_in_flight` at the moment of the crossing.
        bytes: u64,
        /// Configured `max_buffer` cap.
        cap: u64,
        /// The configured threshold percent (e.g. `80`).
        threshold_pct: u8,
    },
}
```

## 7. Implementation steps

1. **`Reassembler::bytes_in_flight()`** — add defaulted method
   returning `0`. Implement on `BufferedReassembler` as `self.buf.
   len() as u64`. The `NoopReassembler` in `datagram_driver.rs`
   inherits the default — UDP doesn't reassemble.
2. **`BufferedReassembler` state** — add a `threshold_pct:
   Option<u8>` field and a per-side `above_threshold: [bool; 2]`
   tracking which sides have already fired. Reset to `false` when
   occupancy drops back below threshold (so a second crossing
   re-arms the event).
3. **`with_high_watermark_threshold`** — setter; clamp 1..=100.
4. **`BufferedReassemblerFactory::with_high_watermark_threshold`** —
   carries the value through to each new `BufferedReassembler`.
5. **`FlowTrackerConfig::reassembler_high_watermark_pct`** — new
   field (default `None`). `FlowDriver::with_config` propagates to
   the factory.
6. **`AnomalyKind::ReassemblerHighWatermark`** — new variant on
   the existing `#[non_exhaustive]` enum.
7. **Driver wiring** — `snapshot_anomaly_state` records per-side
   `(bytes_in_flight, above_threshold)` per reassembler.
   `diff_anomaly_state` detects below→above transitions and emits
   the anomaly. (BufferedReassembler can also set an internal
   "fired" flag and expose it through a defaulted-zero counter
   accessor — mirrors how `bytes_dropped_oversize` and
   `dropped_segments` are surfaced. Pick whichever feels more
   consistent during implementation; recommend the in-reassembler
   flag + a counter accessor for symmetry with the existing
   counter-delta pattern.)
8. **`obs.rs::anomaly_label`** — add an arm:
   `ReassemblerHighWatermark { .. } => "reassembler_high_watermark"`.
9. **Docs** — `SESSION_GUIDE.md` "Recovery after buffer cap"
   section gains a note about the threshold as an early-warning
   signal. `OBSERVABILITY.md` adds the metric label.
10. **`CHANGELOG.md`** — "Added" entry.

## 8. Tests

- **Trait default**: `NoopReassembler::bytes_in_flight() == 0`.
- **`BufferedReassembler` reports current occupancy** matching the
  segments fed in (minus what's been `take`n).
- **Threshold off** (default): no anomaly fires no matter how full
  the buffer.
- **Threshold on + crossing**: configure 80 %, feed enough bytes
  to push past 80 % of cap; assert exactly **one**
  `ReassemblerHighWatermark` anomaly with the right side, bytes
  ≥ threshold-bytes, correct cap and pct.
- **De-bounce**: while still above threshold, more segments don't
  fire additional events. After draining below threshold and
  refilling above, a second anomaly fires.
- **Per-side independence**: initiator above, responder below →
  initiator event only.
- **Driver-level**: with `with_emit_anomalies(true)`, the anomaly
  reaches the `FlowEvent::Anomaly` / (post-plan-43) `FlowAnomaly`
  stream.

## 9. Acceptance criteria

- The new threshold is off by default; existing behaviour
  unchanged.
- A test exercises the full pipeline: `FlowDriver` with the
  configured threshold, drive bytes through, assert the anomaly
  fires once at the crossing.
- The metric label exists in `obs.rs::anomaly_label`.
- `cargo build/test/clippy/fmt/doc --all-features` clean.

## 10. Risks

- **Counter-vs-flag plumbing.** The existing
  `dropped_segments` / `bytes_dropped_oversize` pattern uses
  counters checked at tick boundaries. A "threshold crossing
  count" counter fits that pattern; a boolean "currently above"
  state fits the de-bounce contract. Implement both internally:
  counter for events, boolean for the de-bounce edge. Document
  clearly.
- **`bytes_in_flight` semantics with `SlidingWindow`.** Under
  `SlidingWindow` the buffer is auto-trimmed when full, so
  `bytes_in_flight` may oscillate around cap. The "one event per
  crossing" contract handles this — once above, stays armed until
  drained below.
- **Threshold = 100 %.** Equivalent to a "we're at cap" signal.
  Useful sentinel; allow it.

## 11. Effort

S–M — ~120 lines including driver wiring + tests.

## 12. Provenance

[`docs/feedback-2026-05-22-netring.md`](../docs/feedback-2026-05-22-netring.md)
item **#9**.

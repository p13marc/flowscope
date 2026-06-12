# Plan 173 — `FlowStats` throughput accessors

**Cycle:** 0.14.0 pre-release polish
**Priority:** P1 (operations-layer ergonomic finish)
**Effort:** ~quarter day
**Status:** drafted (NEW — added in consolidation review)

## Motivation

Plan 168 shipped `FlowStats::bytes_for(side)` / `pkts_for` /
`mean_pkt_size_for` / `direction_skew`. Adjacent to those is
the throughput question: "what's the bytes-per-second / packets-
per-second over the flow's lifetime?"

Every L4 monitor / report computes this manually:

```rust
let bps = stats.total_bytes() as f64 / stats.duration_secs().max(f64::EPSILON);
let bps_init = stats.bytes_for(FlowSide::Initiator) as f64
                 / stats.duration_secs().max(f64::EPSILON);
```

The `max(EPSILON)` dance is the easy-to-forget bit — without
it, single-packet flows divide-by-zero into NaN/Infinity.
Every consumer rolls this themselves and ~half forget the
guard.

## Proposed shape

```rust
impl FlowStats {
    /// Average bytes/second over the flow's lifetime.
    /// Returns `0.0` for zero-duration flows (single-packet
    /// or instantaneous). Mirrors the `as f64 / duration_secs`
    /// pattern with safe handling of the zero case.
    pub fn throughput_bps(&self) -> f64;

    /// Average packets/second over the flow's lifetime.
    /// Returns `0.0` for zero-duration flows.
    pub fn throughput_pps(&self) -> f64;

    /// Average bytes/second attributed to the given side.
    /// Returns `0.0` for zero-duration flows.
    pub fn throughput_bps_for(&self, side: FlowSide) -> f64;

    /// Average packets/second attributed to the given side.
    /// Returns `0.0` for zero-duration flows.
    pub fn throughput_pps_for(&self, side: FlowSide) -> f64;
}
```

## Files touched

- `src/event.rs` — four new methods on `FlowStats`

## Implementation notes

- Single safe-divide helper:
  ```rust
  fn safe_div(num: u64, den: f64) -> f64 {
      if den > 0.0 { num as f64 / den } else { 0.0 }
  }
  ```
  All four accessors delegate.
- No new dependencies, no struct changes.

## Tests

Extend `tests/flow_stats.rs` (or whichever covers
plan 168's accessors):
- Multi-second flow: `throughput_bps ≈ total_bytes /
  duration_secs`.
- Zero-duration flow: all four return `0.0`, not NaN/∞.
- Sanity: `throughput_bps == throughput_bps_for(Initiator) +
  throughput_bps_for(Responder)` (within floating-point
  tolerance).

## Acceptance criteria

- Four methods compile + pass tests.
- Zero-duration flows return `0.0` exactly (no NaN/Infinity).
- Documentation cross-links `bytes_for` ↔ `throughput_bps_for`
  + `pkts_for` ↔ `throughput_pps_for`.

## Non-goals

- Mean-throughput-windows (last-N-seconds throughput) — that's
  what `RollingRate` is for. Throughput-over-lifetime is a
  separate question.
- `throughput_bps_for_initiator` / `for_responder` non-`for`
  variants — `FlowSide` enum dispatch is the project idiom.

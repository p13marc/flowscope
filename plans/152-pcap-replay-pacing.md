# Plan 152 — `PcapFlowSource::with_speed_factor` pacing

## Summary

Add `PcapFlowSource::with_speed_factor(f64)` for time-realistic
replay. `1.0` = real-time; `2.0` = 2× speed; `f64::INFINITY` =
as-fast-as-possible (current behaviour, default). Implementation
sleeps between iterator items based on pcap-recorded inter-
arrival times.

**Dropped from wishlist**: `replay_at_wall_clock(SystemTime)` —
low value; consumer-side trivial via a `Timestamp` offset
transform on emit.

## Status

Not started. P2 for 0.13.

## Prerequisites

None.

## Out of scope

- **Multi-file pcap merge.** Downstream tools handle this.
- **Frame-level pacing precision beyond `std::thread::sleep`
  granularity.** Best-effort; documented (~1 ms on Linux,
  ~15 ms on Windows).
- **`replay_at_wall_clock`** (dropped — consumer-side trivial).
- **Async-aware sleep.** `std::thread::sleep` blocks the
  current thread; in a tokio task this monopolises the worker.
  Documented as a hard caveat — tokio users iterate the source
  inside `tokio::task::spawn_blocking`, or use a polling
  consumer that translates pcap pacing to `tokio::time::sleep`
  upstream. We do not add a `with_speed_factor_async` because
  it would require flowscope to take a tokio dep (forbidden).

## Files

| Action | Path | Purpose |
|---|---|---|
| Modify | `src/pcap/source.rs` | Add `speed_factor: Option<f64>` + `prev_pcap_ts: Option<Timestamp>` fields; rewrite `next()` to honor them |
| New | `examples/00-getting-started/pcap_replay_realtime.rs` | Showcase |
| Modify | `tests/pcap_integration.rs` | Pacing test with tolerance |

## API

```rust
impl<R: Read> PcapFlowSource<R> {
    /// Pace packet emission at `factor` × real-time.
    ///
    /// `1.0` = original timing; `2.0` = double speed;
    /// `f64::INFINITY` = as-fast-as-possible (default).
    ///
    /// Sleeps `std::thread::sleep(dt / factor)` between
    /// consecutive packets, where `dt` is the pcap-recorded
    /// inter-arrival. Precision is bounded by the OS scheduler
    /// (~1 ms on Linux, ~15 ms on Windows).
    ///
    /// Suitable for demos and behaviour-realistic offline
    /// replay; not for microsecond-precise traffic regeneration.
    ///
    /// # Async caveat
    ///
    /// `std::thread::sleep` blocks the current thread. Iterating
    /// a paced `PcapFlowSource` inside a tokio task without
    /// `spawn_blocking` will monopolise the worker. Either:
    ///
    /// - Iterate inside `tokio::task::spawn_blocking`, or
    /// - Run on `#[tokio::main(flavor = "current_thread")]` with
    ///   a dedicated thread for the source.
    pub fn with_speed_factor(mut self, factor: f64) -> Self {
        assert!(factor > 0.0, "speed_factor must be > 0");
        self.speed_factor = Some(factor);
        self
    }
}
```

## Implementation steps

1. Add `speed_factor: Option<f64>` + `prev_pcap_ts:
   Option<Timestamp>` to `PcapFlowSource`.
2. In `ViewIter::next()`: if `speed_factor` is set and the new
   factor is finite, compute `dt = current_ts - prev_pcap_ts`;
   sleep `dt / factor`.
3. Update `prev_pcap_ts` after emit.
4. Tests: assert that 100ms of pcap traffic at 2× takes ~50ms
   wall-clock ± tolerance.
5. Example showing `with_speed_factor(1.0)` over a synthetic
   trace.

## Tests

- `default_speed_factor_is_unbounded_no_pacing`.
- `with_speed_factor_2x_halves_inter_arrival_time` (timing-
  based; ±20% tolerance).
- `with_speed_factor_panics_on_zero_or_negative`.

## Acceptance criteria

- `cargo test --all-features` clean.
- Example compiles + runs.
- netring 0.21 Phase E pcap source can wire `.with_speed_factor(1.0)`.

## Risks

**R1: Test flakiness on slow CI.** Timing-based tests are
flaky. Mitigation: generous tolerance (±20%) + skip on
`#[cfg(miri)]`.

## Effort

- LOC delta: +120.
- Time estimate: **0.5 day**.

## Provenance

Wishlist plan 152, narrowed to drop `replay_at_wall_clock`.

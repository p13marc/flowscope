# Plan 164 — `correlate::RollingRate<K, V>` primitive

## Summary

Per-key per-second rate over a rolling window. Mirrors the
existing `correlate::TimeBucketedCounter<K>` shape but:

- Generic over `V` (accept user-supplied byte counts or
  request counts or latency sums — not just `+= 1`).
- Returns `f64` rate (sum-over-window / window-secs).
- Same bucket-reuse discipline (zero-alloc per-`record` when
  the timestamp falls in the same bucket as the previous
  call).

Powers the bandwidth-by-app pattern netring 0.22 flags as the
operationally-most-common monitor primitive.

## Status

Not started. P1 for 0.14.

## Prerequisites

None.

## Out of scope

- **Bounded LRU eviction.** Ship `new_unbounded` first (parallel
  to other `correlate::*::new_unbounded` ctors). Add
  `with_capacity` only when a consumer hits memory pressure.
- **Per-key persistence across cycle boundaries.** Pure
  in-memory; no snapshot/restore. Consumers using
  `RollingRate` for SLO reporting handle persistence
  externally.

## Files

| Action | Path | Purpose |
|---|---|---|
| New | `src/correlate/rolling_rate.rs` | `RollingRate<K, V>` primitive |
| Modify | `src/correlate/mod.rs` | `pub use rolling_rate::RollingRate;` |
| Modify | `src/prelude.rs` | Add `RollingRate` to the tracker-feature prelude (plan 167 sweep) |
| New | `tests/correlate_rolling_rate.rs` | Bucket-rotation + rate-computation tests |

## API

```rust
// src/correlate/rolling_rate.rs
use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::ops::AddAssign;
use std::time::Duration;

use crate::Timestamp;

/// Per-key rolling rate over a sliding time window. Records
/// user-supplied `V` increments; reports `(sum_over_window /
/// window_secs)` as `f64` per-second rate.
///
/// Backed by `VecDeque<(Timestamp, HashMap<K, V>)>` —
/// identical bucket-reuse trick to
/// [`crate::correlate::TimeBucketedCounter`]. Zero allocation
/// per-`record` when the timestamp falls in the same bucket
/// as the previous call.
///
/// Generic `V` lets the same primitive serve:
/// - `RollingRate<&'static str, u64>` for bandwidth
///   (bytes/sec).
/// - `RollingRate<&'static str, u64>` for request rate
///   (count/sec — call `record(k, 1, now)`).
/// - `RollingRate<K, f64>` for latency-sum tracking, etc.
///
/// Plan 164 (0.14).
pub struct RollingRate<K, V>
where
    K: Hash + Eq,
    V: Default + Copy + AddAssign + Into<f64>,
{
    window: Duration,
    bucket_width: Duration,
    by_key: VecDeque<(Timestamp, HashMap<K, V>)>,
}

impl<K, V> RollingRate<K, V>
where
    K: Hash + Eq + Clone,
    V: Default + Copy + AddAssign + Into<f64>,
{
    /// New unbounded `RollingRate` with the given window and
    /// per-bucket width.
    ///
    /// `bucket_width` should evenly divide `window`. Common
    /// choice: `window = 60s`, `bucket_width = 1s` (matches
    /// the Prometheus `rate(…)` default).
    pub fn new_unbounded(window: Duration, bucket_width: Duration) -> Self {
        assert!(bucket_width > Duration::ZERO, "bucket_width must be > 0");
        assert!(window >= bucket_width, "window must be >= bucket_width");
        Self {
            window,
            bucket_width,
            by_key: VecDeque::new(),
        }
    }

    /// Record `v` against `k` at time `now`. Adds to the
    /// current bucket; creates a new bucket if `now` advanced
    /// past the previous bucket's window.
    ///
    /// Zero-allocation when `now` falls in the same bucket as
    /// the previous call.
    pub fn record(&mut self, k: K, v: V, now: Timestamp) {
        self.evict_expired(now);
        if let Some((bucket_ts, map)) = self.by_key.back_mut() {
            if Self::same_bucket(*bucket_ts, now, self.bucket_width) {
                *map.entry(k).or_default() += v;
                return;
            }
        }
        // New bucket.
        let mut map = HashMap::new();
        map.insert(k, v);
        self.by_key.push_back((now, map));
    }

    /// `sum(V over last window) / window_secs` — per-second
    /// rate for `k`. Returns `0.0` if `k` has no samples in
    /// the window.
    pub fn rate(&self, k: &K, now: Timestamp) -> f64 {
        let cutoff = now.saturating_sub(self.window);
        let mut sum: f64 = 0.0;
        for (bucket_ts, map) in &self.by_key {
            if *bucket_ts < cutoff {
                continue;
            }
            if let Some(v) = map.get(k) {
                sum += (*v).into();
            }
        }
        sum / self.window.as_secs_f64()
    }

    /// Snapshot every key with a non-zero rate. Yields
    /// `(K, rate_per_sec)` pairs in arbitrary order.
    pub fn snapshot(&self, now: Timestamp) -> impl Iterator<Item = (&K, f64)> + '_ {
        let cutoff = now.saturating_sub(self.window);
        let window_secs = self.window.as_secs_f64();
        // Accumulate per-key totals across in-window buckets.
        let mut totals: HashMap<&K, f64> = HashMap::new();
        for (bucket_ts, map) in &self.by_key {
            if *bucket_ts < cutoff {
                continue;
            }
            for (k, v) in map {
                *totals.entry(k).or_default() += (*v).into();
            }
        }
        totals.into_iter().map(move |(k, sum)| (k, sum / window_secs))
    }

    /// Drop buckets outside the window. Mirrors
    /// `TimeBucketedCounter::evict_expired`. Idempotent.
    pub fn evict_expired(&mut self, now: Timestamp) {
        let cutoff = now.saturating_sub(self.window);
        while let Some((bucket_ts, _)) = self.by_key.front() {
            if *bucket_ts < cutoff {
                self.by_key.pop_front();
            } else {
                break;
            }
        }
    }

    /// True if no buckets are tracked.
    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }

    /// Number of active buckets (approximate; capacity-bounded
    /// to `ceil(window / bucket_width)`).
    pub fn bucket_count(&self) -> usize {
        self.by_key.len()
    }

    fn same_bucket(prev: Timestamp, now: Timestamp, width: Duration) -> bool {
        // Same bucket iff the elapsed-since-prev is shorter
        // than the bucket width.
        now.saturating_sub(prev) < width
    }
}
```

(Adjust the exact `Timestamp` API methods to whatever the
shipped surface is; survey indicates `saturating_sub` exists.)

## Implementation steps

1. Write `RollingRate<K, V>` per the API above.
2. Wire `correlate::RollingRate` re-export in
   `src/correlate/mod.rs`.
3. Tests covering:
   - Single-key single-bucket rate.
   - Cross-bucket rate aggregation.
   - Snapshot iteration.
   - `evict_expired` idempotency.
   - Zero-rate for empty / past-window keys.
   - Bucket-reuse zero-alloc contract (assert no per-bump
     `HashMap` allocation when the bucket is reused — via
     dhat-style profiler if available, or by accessor count).
4. Add a usage example in `docs/recipes.md` under "0.14
   patterns" — bandwidth-by-app via `app_label` + `RollingRate`.

## Tests

- `new_unbounded_with_invalid_args_panics` (bucket_width = 0,
  window < bucket_width).
- `single_record_then_rate_returns_v_over_window_secs`.
- `multiple_records_same_bucket_sum`.
- `records_across_buckets_aggregate_in_window`.
- `rate_zero_when_window_elapsed`.
- `rate_zero_for_unknown_key`.
- `snapshot_yields_every_in_window_key`.
- `evict_expired_drops_old_buckets_idempotent`.
- `record_in_same_bucket_does_not_allocate_new_hashmap`
  (bucket-reuse contract).

## Acceptance criteria

- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- netring 0.22's `bandwidth_by_app()` primitive uses
  `RollingRate<&'static str, u64>` internally.
- Bench: `record` in a stable-bucket hot loop allocates 0
  bytes per call after warm-up.

## Risks

**R1: Bucket boundary edge cases.** `now == bucket_ts +
bucket_width` exactly: same bucket or new bucket? Mitigation:
documented contract (`same_bucket` uses strictly `<`). Adversarial
tests pin the boundary.

**R2: `Into<f64>` precision loss for `V = u64`.** A `u64` byte
count above `2^53` loses precision when cast to `f64`. In
practice this means ~9 PB of bytes per window, which is
implausible. Mitigation: documented in rustdoc.

**R3: Bucket-reuse zero-alloc assertion.** The bucket-reuse
contract is the perf-sensitive case. The test must actually
verify allocation count, not just correctness. Mitigation:
use `dhat::Profiler` or the existing flowscope bench
infrastructure.

## Effort

- LOC delta: +400 (primitive + tests + docs + example).
- Time estimate: **1.5 days**.

## Provenance

Wishlist plan 164. The bound simplification (drop `From<u64>`)
is my counter-proposal — see umbrella 169 §3.5.

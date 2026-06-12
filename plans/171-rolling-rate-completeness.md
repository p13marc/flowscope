# Plan 171 — `RollingRate` completeness sweep

**Cycle:** 0.14.0 pre-release polish
**Priority:** P0 (production-readiness gates)
**Effort:** ~half day
**Status:** drafted (consolidation review trimmed `with_capacity`)

## Motivation

Plan 164 shipped `RollingRate<K, V>` with the minimum-viable
shape: `new_unbounded` / `record` / `rate` / `snapshot` /
`for_each_bucket` / `evict_expired` / `is_empty` /
`bucket_count`.

Four gaps reviewers will hit immediately:

1. **No raw sum accessor.** `rate(k, now)` returns
   `sum/window_secs`. Many reports want the raw sum
   ("bytes-in-the-last-minute", "requests-in-the-last-5") without
   the per-second divide. Doing `rate * window_secs` at the call
   site is correct but reads as a bug to most reviewers.
2. **No top-N helper.** Every dashboard wants top-N talkers;
   today users `snapshot().collect().sort()` at every call site.
3. **No `clear()`.** Tests + periodic-reset semantics. Trivial.
4. **No `len()`.** Sibling to `is_empty()` — idiomatic and
   useful for "how many unique keys did we see this window".

## Proposed shape

```rust
impl<K, V> RollingRate<K, V>
where
    K: Hash + Eq + Clone,
    V: RateValue,
{
    /// Raw sum of `V` over the active window for `k`. No
    /// per-second divide. Returns `V::default()` (zero) if `k`
    /// is absent or has no samples in the window. Useful for
    /// "bytes-in-last-minute" style reports.
    pub fn sum(&self, k: &K, now: Timestamp) -> V;

    /// Sorted top-N entries by rate (descending). Ties broken
    /// by insertion order in `self.buckets`. Returns at most
    /// `n` entries; fewer if fewer non-zero keys exist.
    ///
    /// Pairs with [`Self::snapshot`] for unsorted access.
    pub fn top_k(&self, n: usize, now: Timestamp) -> Vec<(K, f64)>;

    /// Drop every recorded bucket. After this call,
    /// `is_empty()` returns `true`, `bucket_count()` returns
    /// `0`, every `rate(k, …)` returns `0.0`, every
    /// `sum(k, …)` returns `V::default()`.
    pub fn clear(&mut self);

    /// Number of unique keys observed in the current window.
    /// Sibling to [`Self::is_empty`]. Idempotent with
    /// `evict_expired` — outside-window keys are not counted.
    pub fn len(&self, now: Timestamp) -> usize;
}
```

## Files touched

- `src/correlate/rolling_rate.rs` — four new methods

## Implementation notes

- **`sum`** — iterate buckets `[cutoff, now]`, accumulate `V`
  via `AddAssign`. No allocation.
- **`top_k`** — call `snapshot(now)`, collect into `Vec`, sort
  by `b.1.partial_cmp(&a.1).unwrap_or(Equal)`, truncate to `n`.
  For typical `n ≤ 100`, full sort is faster than partial-heap
  variants. `top_k(0)` returns empty Vec without panic.
- **`clear`** — `self.buckets.clear()`. O(buckets).
- **`len`** — fold buckets `[cutoff, now]` into a `HashSet<&K>`
  via the existing snapshot pipeline; return set size. Allocates
  one `HashSet`. If the caller wants zero-alloc, they can build
  their own via `for_each_bucket`.

## Tests

Extend `tests/correlate_rolling_rate.rs` (or create one if
absent):
- `sum` returns raw `V`, no rate division (compare `rate(k, now)
  * window_secs ≈ sum(k, now).into()`).
- `top_k(3)` from 5 keys returns 3, descending.
- `top_k(0)` returns empty.
- `top_k(100)` from 5 keys returns 5.
- `clear` empties; `is_empty` true; `len` zero; `bucket_count`
  zero.
- `len` agrees with manual key-set count.

## Acceptance criteria

- All 4 methods compile + pass tests.
- `top_k(0)` returns empty Vec without panic.
- `sum` and `rate` agree: `rate(k, now) ≈ sum(k, now).as_f64() / window_secs`.
- Zero clippy warnings, zero rustdoc warnings.

## Explicitly deferred (out of scope for 0.14)

- **`with_capacity(window, bucket, lru_n)` LRU-bounded
  variant.** `RollingRate`'s storage is per-time-bucket
  (`VecDeque<(Timestamp, HashMap<K, V>)>`), not per-key
  (`HashMap<K, RateBuckets<V>>` as the wishlist sketched).
  An LRU bound requires a separate global `LruCache<K, ()>`
  for membership + reaching into every live bucket to remove
  evicted keys. ~50-80 LoC and complicates the
  bucket-rotation logic. Defer until a profile demonstrates
  the unbounded-K case actually hits memory. The current
  `evict_expired` already bounds memory to "K cardinality
  per window".
- **`RollingRate::merge(other)` for sharded aggregation.**
  Wait for `ShardedRunner::merge_state` to settle in netring
  0.22 — the merge contract should match.
- **Heap-based partial top-N.** Premature; full sort is fine
  for typical n.

## Non-goals

- Streaming top-N — defer until a profile shows it matters.
- A reusable `Vec<(K, f64)>` buffer variant on `top_k` —
  premature optimisation.

# Plan 102 — `correlate` module extensions

## Summary

Add four primitives to `flowscope::correlate` that detector
examples reinvented in the 0.9 cycle:

- **`TimeBucketedSet<K, V>`** — TTL'd set keyed by `K` with
  value set `V`; cardinality + entries-above-threshold
  queries. (`port_scan_detector`, `dns_tunnel_detector`.)
- **`BurstDetector<K, E>`** — "N events of kind X within
  window followed by event of kind Y" — direct sequence
  matcher. (`failed_auth_burst`.)
- **`TopK<K>`** — bounded "top K by rate" tracker with
  exact counts when under capacity, frequency-estimation
  when over. (Multiple "find the noisiest source" patterns.)
- **`Ewma<K>`** — per-key exponentially weighted moving
  average for latency / rate tracking. (Observability
  use cases.)

Theme 5 from
[`plans/100-examples-postmortem.md`](./100-examples-postmortem.md)
— `correlate` shipped too thin in 0.9.

## Status

**Ready to implement.** Targets 0.10.0. Independent of other
0.10 plans.

## Prerequisites

- Plan 81 — `flowscope::correlate` module (shipped 0.9.0).
  This plan extends it.

## Out of scope

- **Bloom-filter or Count-Min sketch primitives.** Useful for
  approximate cardinality at scale; defer until a consumer
  asks. The hash-based `TopK` here is a small step in that
  direction (exact under capacity, can grow to a sketch
  later if needed without breaking the API).
- **Streaming quantile estimators** (DDSketch, t-digest).
  Plan 103 (`aggregate` module) covers histograms; quantile
  estimators are a follow-up if observability use cases push
  for it.
- **Anomaly detection on streams.** Too broad; defer to a
  separate plan once specific consumer patterns surface.
- **Persistent correlate state.** Currently in-memory only;
  on-disk persistence is a separate concern.

---

## API

### `TimeBucketedSet<K, V>`

```rust
// src/correlate/set.rs
pub struct TimeBucketedSet<K, V>
where K: Hash + Eq + Clone, V: Hash + Eq + Clone,
{ /* … */ }

impl<K, V> TimeBucketedSet<K, V>
where K: Hash + Eq + Clone, V: Hash + Eq + Clone,
{
    /// `window`: total observation window.
    /// `bucket_width`: bucket resolution.
    /// `capacity`: max distinct K held at once.
    pub fn new(window: Duration, bucket_width: Duration, capacity: usize) -> Self;

    /// Add `value` to the set keyed by `key`.
    pub fn insert(&mut self, key: K, value: V, ts: Timestamp);

    /// Count of distinct values for `key` within the active
    /// window.
    pub fn cardinality(&self, key: &K, now: Timestamp) -> usize;

    /// Iterate `(key, cardinality)` pairs whose cardinality
    /// equals or exceeds `threshold`.
    pub fn entries_above(
        &self,
        threshold: usize,
        now: Timestamp,
    ) -> impl Iterator<Item = (&K, usize)>;

    /// Drop buckets older than `now - window`.
    pub fn evict_expired(&mut self, now: Timestamp);

    pub fn len(&self) -> usize;
}
```

Backed by `VecDeque<(Timestamp, HashMap<K, HashSet<V>>)>` —
same bucket layout as `TimeBucketedCounter`. Exact under
the `capacity` cap; LRU-evicts the oldest bucket's smallest
sets when over.

### `BurstDetector<K, E>`

```rust
// src/correlate/burst.rs
pub struct BurstDetector<K, E>
where K: Hash + Eq + Clone, E: Eq + Clone,
{ /* … */ }

#[derive(Debug, Clone)]
pub struct BurstHit<K> {
    pub key: K,
    pub burst_count: u32,
    pub trigger_ts: Timestamp,
}

impl<K, E> BurstDetector<K, E>
where K: Hash + Eq + Clone, E: Eq + Clone,
{
    /// Detect a burst pattern:
    /// `N` occurrences of `burst_kind` within `window`,
    /// optionally followed by `trigger_kind`.
    ///
    /// If `trigger_kind` is `Some`, emit on the trigger event
    /// only (post-burst trigger pattern — e.g. auth-failure
    /// burst then success).
    /// If `trigger_kind` is `None`, emit on the Nth burst
    /// event (pure burst pattern — e.g. SYN flood).
    pub fn new(
        burst_kind: E,
        threshold: u32,
        window: Duration,
        trigger_kind: Option<E>,
    ) -> Self;

    /// Observe an event for `key`. Returns `Some(BurstHit)` on
    /// the firing event; `None` otherwise.
    pub fn observe(&mut self, key: &K, event: &E, now: Timestamp) -> Option<BurstHit<K>>;

    /// Drop stale per-key state.
    pub fn evict_expired(&mut self, now: Timestamp);
}
```

The `failed_auth_burst.rs` example becomes:

```rust
let mut detector = BurstDetector::<IpAddr, AuthEvent>::new(
    AuthEvent::Fail,
    5,
    Duration::from_secs(60),
    Some(AuthEvent::Success),
);

for (src, evt, ts) in event_stream {
    if let Some(hit) = detector.observe(&src, &evt, ts) {
        println!("burst hit on {}: {}", hit.key, hit.burst_count);
    }
}
```

### `TopK<K>`

```rust
// src/correlate/topk.rs
pub struct TopK<K: Hash + Eq + Clone> { /* … */ }

impl<K: Hash + Eq + Clone> TopK<K> {
    /// Track up to `k` keys exactly. Beyond `k`, the smallest
    /// count gets bumped down to make room — same shape as
    /// Misra-Gries / Space-Saving algorithm.
    pub fn new(k: usize) -> Self;

    pub fn observe(&mut self, key: K);
    pub fn observe_n(&mut self, key: K, count: u64);

    /// Return the top-N entries (max `k`) sorted by count
    /// descending.
    pub fn top(&self) -> Vec<(&K, u64)>;

    /// Read estimated count for `key`. Off-by-up-to-N for
    /// keys that were ever evicted, where N is the lowest
    /// retained count.
    pub fn estimate(&self, key: &K) -> u64;

    pub fn clear(&mut self);
}
```

Exact for `≤ k` distinct keys; bounded-error for more (the
worst-case overestimate for any evicted key equals the
minimum count among retained keys).

### `Ewma<K>`

```rust
// src/correlate/ewma.rs
pub struct Ewma<K: Hash + Eq> { /* … */ }

impl<K: Hash + Eq> Ewma<K> {
    /// `alpha` in (0, 1] — weight of new sample. Smaller
    /// alpha = smoother / slower-reacting.
    pub fn new(alpha: f64) -> Self;

    /// Record a sample for `key`. Returns the updated EWMA.
    pub fn record(&mut self, key: K, sample: f64) -> f64;

    /// Current EWMA for `key`, or `None` if no samples.
    pub fn get(&self, key: &K) -> Option<f64>;

    /// Iterate `(key, ewma)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&K, f64)>;

    /// Drop entries that haven't been touched in `ttl`.
    pub fn evict_stale(&mut self, now: Timestamp, ttl: Duration);
}
```

Common use: per-flow latency tracking, where each `record`
adds an observation and the running EWMA is the dashboard
metric.

---

## Files

```
src/correlate/mod.rs         # re-exports for the four new types
src/correlate/set.rs         # TimeBucketedSet (NEW)
src/correlate/burst.rs       # BurstDetector (NEW)
src/correlate/topk.rs        # TopK (NEW)
src/correlate/ewma.rs        # Ewma (NEW)
tests/correlate_extensions.rs # integration tests
examples/port_scan_detector.rs    # MIGRATED to TimeBucketedSet
examples/failed_auth_burst.rs     # MIGRATED to BurstDetector
docs/recipes.md              # add "Cross-flow detector primitives" section
CHANGELOG.md                 # 0.10 entry
```

## Implementation steps

1. **`src/correlate/set.rs`** — `TimeBucketedSet`
   implementation. Reuses `TimeBucketedCounter`'s
   `VecDeque<bucket>` skeleton; bucket holds `HashMap<K,
   HashSet<V>>` instead of `HashMap<K, u64>`.
2. **`src/correlate/burst.rs`** — `BurstDetector`. Per-key
   state: ring buffer of recent burst event timestamps + a
   "primed" flag waiting for the trigger.
3. **`src/correlate/topk.rs`** — `TopK` via Misra-Gries.
4. **`src/correlate/ewma.rs`** — `Ewma`. Simple `HashMap<K,
   (f64, Timestamp)>`.
5. **Re-export** all four in `src/correlate/mod.rs`.
6. **Migrate examples**:
   - `port_scan_detector.rs`: collapse the parallel
     `HashMap<ScanKey, BTreeSet<u16>>` into a
     `TimeBucketedSet`.
   - `failed_auth_burst.rs`: collapse the hand-rolled
     `(fail_count, last_ts)` state into a `BurstDetector`.
7. **Update `docs/recipes.md`** with a section showing each
   primitive's intended use.
8. **CHANGELOG entry** under 0.10.0 "Added".

## Tests

`tests/correlate_extensions.rs` (single file, multiple
sections):

```rust
// TimeBucketedSet
- cardinality counts distinct values, not insertions.
- cardinality respects the window.
- entries_above filters correctly.
- evict_expired drops old buckets.

// BurstDetector
- N fails within window without trigger → no hit.
- N fails + trigger within window → hit.
- N fails + trigger past window → no hit.
- pure-burst mode (trigger_kind = None) fires on the Nth
  burst event.
- per-key isolation: source A's fails don't trigger source B.

// TopK
- ≤ k distinct keys: exact counts.
- 2k distinct keys: top is still correct (Misra-Gries
  guarantee).
- observe_n bulk-inserts work.
- clear resets state.

// Ewma
- alpha=1.0 → output equals last sample.
- alpha=0.5 → output = average of last two.
- per-key isolation.
- evict_stale drops untouched entries.
```

12+ scenarios across the four types.

## Acceptance criteria

- Four new types ship behind the existing `tracker` feature
  (where `correlate` lives).
- Two example migrations — LoC down ~30 % in each.
- `docs/recipes.md` "Cross-flow detector primitives"
  section ships.
- All 12+ tests pass.
- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- CHANGELOG entry.

## Risks

- **Misra-Gries TopK approximation surprises.** Users
  expecting exact counts get surprised when more than `k`
  distinct keys are observed. Mitigation: clear rustdoc on
  the trade-off; provide `estimate()` separately from
  `top()` so the approximation is explicit.
- **`Ewma` floating-point precision.** Decision: use `f64`
  throughout; document the precision floor for very small
  alphas in rustdoc.
- **Memory growth without `evict_*` calls.** All four types
  need periodic eviction; without it they grow unboundedly.
  Mitigation: document the eviction contract; add a
  rustdoc note "call `evict_*` from your `on_tick` / sweep
  loop."

## Effort

| Type | LoC | Hours |
|------|-----|-------|
| `TimeBucketedSet` | ~220 | 4 |
| `BurstDetector` | ~180 | 4 |
| `TopK` (Misra-Gries) | ~150 | 3 |
| `Ewma` | ~80 | 1.5 |
| Tests (12+ scenarios) | ~340 | 5 |
| Example migrations (2 files) | ~−40 net | 1.5 |
| Docs + CHANGELOG | ~80 | 1 |
| **Total** | **~1,010 LoC** | **~20 hours** |

## Provenance

Postmortem theme 5:

> `correlate` is missing common shapes. Set-with-TTL,
> top-K-by-rate, percentile bucketers — every detector
> example reinvented one.

Specific gaps observed:

- `port_scan_detector` needed "distinct destination ports
  per (src, dst) within window" — wrote a parallel
  `HashMap<K, BTreeSet<u16>>`. → `TimeBucketedSet`.
- `failed_auth_burst` needed "burst-then-trigger pattern" —
  wrote a hand-rolled state machine. → `BurstDetector`.
- "Top N source IPs by SYN rate" (not yet shipped as an
  example, but the obvious next detector) → `TopK`.
- "Per-flow EWMA of inter-packet delay" (a latency
  observability pattern) → `Ewma`.

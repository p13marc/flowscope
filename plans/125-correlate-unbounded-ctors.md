# Plan 125 — `correlate::*::new_unbounded` constructors

## Summary

Add a `new_unbounded` constructor to the three correlate
primitives that take an explicit capacity parameter today:
`TimeBucketedCounter`, `KeyIndexed`, `TimeBucketedSet`. Each
new constructor matches the existing 2-arg shape downstream
crates (notably netring's `correlate.rs`) use, internally
delegating to `new(…, usize::MAX)`.

Trivial additive change — no breaks, no API churn. Lets
netring 0.21 Phase G drop its duplicate correlate module and
re-export flowscope's directly.

## Status

Not started.

## Prerequisites

None.

## Out of scope

- **Removing the existing 3-arg `new(window, bucket, capacity)`
  constructors.** Pre-1.0 we *could*, but capacity-bounded
  callers exist and the redundant ctor isn't a cost.
- **`BurstDetector::new_unbounded`** — `BurstDetector::new`
  takes `(burst_kind, threshold, window, trigger_kind)`, not
  a capacity. No `new_unbounded` analogue exists.
- **`TopK::new_unbounded`** — `TopK::new(k)` is already
  inherently bounded by `k`. Not applicable.
- **`Ewma::new_unbounded`** — `Ewma::new(alpha)` is already
  the only constructor. Not applicable.

## Files

| Action | Path | Purpose |
|---|---|---|
| Modify | `src/correlate/bucketed.rs` | `TimeBucketedCounter::new_unbounded(w, b)` |
| Modify | `src/correlate/indexed.rs` | `KeyIndexed::new_unbounded(ttl)` |
| Modify | `src/correlate/set.rs` | `TimeBucketedSet::new_unbounded(w, b)` |

## API

```rust
// src/correlate/bucketed.rs
impl<K> TimeBucketedCounter<K>
where K: Hash + Eq + Clone
{
    /// Unbounded LRU capacity (`usize::MAX`). See [`Self::new`]
    /// for the bounded constructor — prefer it when memory
    /// pressure is a concern.
    ///
    /// Equivalent to `Self::new(window, bucket_width, usize::MAX)`.
    pub fn new_unbounded(window: Duration, bucket_width: Duration) -> Self {
        Self::new(window, bucket_width, usize::MAX)
    }
}

// src/correlate/indexed.rs
impl<K, V> KeyIndexed<K, V>
where K: Hash + Eq + Clone
{
    /// Unbounded capacity.
    pub fn new_unbounded(ttl: Duration) -> Self {
        Self::new(ttl, usize::MAX)
    }
}

// src/correlate/set.rs
impl<K, V> TimeBucketedSet<K, V>
where K: Hash + Eq + Clone, V: Hash + Eq + Clone
{
    /// Unbounded LRU capacity.
    pub fn new_unbounded(window: Duration, bucket_width: Duration) -> Self {
        Self::new(window, bucket_width, usize::MAX)
    }
}
```

## Implementation steps

1. Add the three constructors as 3-line delegates.
2. Add a doc cross-reference between `new` and `new_unbounded`:
   `"see [`Self::new_unbounded`] to skip the capacity cap"`.
3. Add a single regression test per primitive showing
   equivalence (`new_unbounded(w, b)` and `new(w, b, usize::MAX)`
   produce structurally-equivalent results after the same
   operations).
4. CHANGELOG entry — "Added `TimeBucketedCounter::new_unbounded`,
   `KeyIndexed::new_unbounded`, `TimeBucketedSet::new_unbounded` —
   convenience constructors matching the pre-0.10 2-arg shape.
   Downstream crates (netring) can drop duplicate primitives
   and re-export flowscope's directly."

## Tests

In `src/correlate/bucketed.rs`, `indexed.rs`, `set.rs`:

- `new_unbounded_equivalent_to_new_with_usize_max` per
  primitive. Asserts the two constructors produce
  `PartialEq`-equivalent state after the same insert sequence
  (or — if `PartialEq` isn't ergonomic — equivalent visible
  behaviour through public accessors).

## Acceptance criteria

- `cargo test --features tracker` (the gate for `correlate`)
  passes the new tests.
- Existing tests unchanged.
- `cargo doc --all-features --no-deps` zero warnings.
- netring 0.21 Phase G — verified by writing a one-line
  prototype that confirms the downstream re-export shape
  works: `pub use flowscope::correlate::TimeBucketedCounter as Counter;`
  + `Counter::new_unbounded(window, bucket)` compiles.

## Risks

None.

## Effort

| Step | LoC | Hours |
|---|---|---|
| Three constructors (5 LoC each) | 15 | 0.5 |
| Three regression tests | 30 | 0.5 |
| Docs + CHANGELOG | 10 | 0.5 |
| **Total** | **~55** | **~1.5 hours (¼ day)** |

Wishlist's "½ day" estimate is on track or shorter.

## Provenance

Triggered by netring 0.21 §5.4 / Phase G. The 3-arg
flowscope-side vs 2-arg netring-side signature mismatch
blocks the netring cleanup. Adding the 2-arg shape upstream is
zero-cost for flowscope and removes the duplicate code
downstream.

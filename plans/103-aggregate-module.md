# Plan 103 — `flowscope::aggregate` — SRE/observability primitives

## Summary

Ship a small `aggregate` module with the data structures
every observability example reinvented:

- **`Histogram`** — explicit-bucket counter with `record` /
  `quantile` / `samples` / `merge`. For "distribution of X"
  reports (flow durations, packet sizes, response times).
- **`Percentile`** — t-digest-style streaming quantile
  estimator for unbounded streams.

This is theme 5 follow-up. Keep the module deliberately
small — only ship what example writers actually reached for.

## Status

**Ready to implement.** Targets 0.10.0.

## Prerequisites

- Plan 81 — `flowscope::correlate` shipped 0.9.0; `aggregate`
  is the sibling module.

## Out of scope

- **HDR Histogram-compatible binary format.** If a consumer
  wants serdes-roundtrippable histograms, defer to the
  `hdrhistogram` crate or add it as a follow-up.
- **Counter / Gauge primitives.** Metrics-feature integration
  already covers these. Out of scope for `aggregate`.
- **Multi-dimensional aggregations.** Two-axis histograms
  (e.g. "latency by status code") are out of scope; the
  consumer maintains a `HashMap<K, Histogram>` themselves.

---

## API

### `Histogram`

```rust
// src/aggregate/histogram.rs
pub struct Histogram {
    bucket_boundaries: Vec<f64>,
    bucket_counts: Vec<u64>,
    samples: u64,
    min: f64,
    max: f64,
    sum: f64,
}

impl Histogram {
    /// Construct with explicit bucket boundaries (sorted ascending).
    /// `Histogram::with_buckets(&[0.1, 1.0, 10.0])` creates 4
    /// buckets: `<0.1`, `[0.1, 1.0)`, `[1.0, 10.0)`, `>=10.0`.
    pub fn with_buckets(boundaries: &[f64]) -> Self;

    /// Log-spaced buckets between `low` and `high` (geometric).
    pub fn log_spaced(low: f64, high: f64, count: usize) -> Self;

    pub fn record(&mut self, value: f64);

    /// Approximate quantile (linear interpolation within bucket).
    /// `q ∈ [0.0, 1.0]`.
    pub fn quantile(&self, q: f64) -> f64;

    pub fn samples(&self) -> u64;
    pub fn mean(&self) -> f64;
    pub fn min(&self) -> f64;
    pub fn max(&self) -> f64;

    /// Merge two histograms with identical bucket boundaries.
    pub fn merge(&mut self, other: &Histogram) -> Result<(), HistogramError>;

    /// Iterate `(boundary, count)` pairs for rendering.
    pub fn buckets(&self) -> impl Iterator<Item = (f64, u64)> + '_;
}
```

### `Percentile`

```rust
// src/aggregate/percentile.rs
/// Streaming quantile estimator.
///
/// Approximate via t-digest (compresses online; constant
/// memory). Error tightest near the tails (p99, p999).
pub struct Percentile {
    /* internal t-digest state */
}

impl Percentile {
    /// `compression`: higher = more accurate, more memory.
    /// 100-200 is typical.
    pub fn new(compression: u32) -> Self;

    pub fn record(&mut self, value: f64);

    pub fn quantile(&self, q: f64) -> f64;

    pub fn samples(&self) -> u64;
}
```

For the implementation, pull in the `tdigest` crate (small,
maintained, ~500 LoC). Adds one Cargo dep behind the
`aggregate` feature.

---

## Files

```
src/aggregate/mod.rs           # module entry + re-exports
src/aggregate/histogram.rs     # Histogram (NEW)
src/aggregate/percentile.rs    # Percentile (NEW; pulls `tdigest`)
Cargo.toml                     # new `aggregate` feature
tests/aggregate.rs             # coverage
examples/flow_duration_histogram.rs  # MIGRATED to Histogram
docs/recipes.md                # add "Aggregation primitives" section
CHANGELOG.md                   # 0.10 entry
```

## Implementation steps

1. Add Cargo feature `aggregate = ["dep:tdigest"]`.
2. Implement `Histogram` (no deps).
3. Implement `Percentile` (wraps `tdigest::TDigest`).
4. Add `src/aggregate/mod.rs` re-exports.
5. Migrate `examples/flow_duration_histogram.rs` to use
   `Histogram` — drops manual bucketing + percentile.
6. `tests/aggregate.rs`:
   - `Histogram::record` + `quantile` reasonable values.
   - `Histogram::merge` correctness.
   - `Percentile`: 1000 samples in [0,1], quantile(0.5) ≈ 0.5
     ± 0.01.
7. `docs/recipes.md` "Aggregation primitives" section.
8. CHANGELOG entry.

## Acceptance criteria

- Both types ship behind the new `aggregate` feature.
- Example migrated.
- 4+ tests pass.
- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- CHANGELOG entry.

## Risks

- **`tdigest` crate dependency.** Adds one transitive dep
  (small and maintained). Mitigation: gate behind the
  `aggregate` feature so users who don't want it pay zero
  cost.

## Effort

| Surface | LoC | Hours |
|---------|-----|-------|
| `Histogram` | ~180 | 4 |
| `Percentile` (wrapper) | ~80 | 2 |
| Tests | ~140 | 3 |
| Example migration | ~−20 net | 0.5 |
| Docs + CHANGELOG | ~60 | 1 |
| **Total** | **~440 LoC** | **~10.5 hours** |

## Provenance

Postmortem theme 5:

> Manual histogram bucketing. Manual p50 / p99 / max via
> sort+index. Same `Timestamp` → f64 boilerplate.

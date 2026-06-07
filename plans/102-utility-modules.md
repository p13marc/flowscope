# Plan 102 — utility modules (correlate ext + aggregate + detect + well-known)

## Summary

Ship four small primitive modules surfaced by the 0.9
examples-writing pass, as a single plan with four
independent sub-PRs. Each sub-PR is a small additive
module; none breaks anything; none depends on another.

| Sub-plan | Module | Adds | LoC | Hours |
|----------|--------|------|-----|-------|
| **A** | `flowscope::correlate` (extends) | `TimeBucketedSet` + `BurstDetector` + `TopK` + `Ewma` | ~1,010 | ~20 |
| **B** | `flowscope::aggregate` (new) | `Histogram` + `Percentile` (t-digest) | ~440 | ~11 |
| **C** | `flowscope::detect` (new) | `shannon_entropy` + 5 light primitives + `NgramDist` | ~295 | ~6 |
| **D** | `flowscope::well_known` (new) | `protocol_label()` + curated ~80-entry table | ~335 | ~6 |
| Total | | | **~2,080** | **~43** |

Theme 5 from
[`plans/100-examples-postmortem.md`](./100-examples-postmortem.md)
— "0.10 wants a thin layer of stateless / near-stateless
analysis primitives." Plan 113 (`signatures` submodule)
lives alongside sub-plan C in the same `detect` module.

## Status

**Ready to implement.** Targets 0.10.0. Four sub-PRs land
independently — no internal ordering. Recommended landing
order (lightest first): D → C → B → A.

## Prerequisites

- Plan 81 — `flowscope::correlate` module (shipped 0.9).
  Sub-plan A extends it; sub-plans B/C/D are new sibling
  modules.

## Out of scope (whole plan)

- **Bloom-filter / Count-Min sketch primitives.** The
  hash-based `TopK` is a small step in that direction.
- **HDR Histogram binary format.** Defer to the
  `hdrhistogram` crate.
- **ML-shaped detection.** Out for the `detect` module.
- **Dynamic protocol detection from payload** in `well_known`
  — that's plan 113 (signatures) + plan 114 (heuristic
  routing).
- **Persistent state.** All four modules are in-memory only.

---

## Sub-plan A — `correlate` extensions

### API additions

```rust
// src/correlate/set.rs
pub struct TimeBucketedSet<K, V>
where K: Hash + Eq + Clone, V: Hash + Eq + Clone,
{ /* … */ }

impl<K, V> TimeBucketedSet<K, V> {
    pub fn new(window: Duration, bucket_width: Duration, capacity: usize) -> Self;
    pub fn insert(&mut self, key: K, value: V, ts: Timestamp);
    pub fn cardinality(&self, key: &K, now: Timestamp) -> usize;
    pub fn entries_above(&self, threshold: usize, now: Timestamp)
        -> impl Iterator<Item = (&K, usize)>;
    pub fn evict_expired(&mut self, now: Timestamp);
    pub fn len(&self) -> usize;
}

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

impl<K, E> BurstDetector<K, E> {
    pub fn new(burst_kind: E, threshold: u32, window: Duration,
               trigger_kind: Option<E>) -> Self;
    pub fn observe(&mut self, key: &K, event: &E, now: Timestamp) -> Option<BurstHit<K>>;
    pub fn evict_expired(&mut self, now: Timestamp);
}

// src/correlate/topk.rs — Misra-Gries / Space-Saving
pub struct TopK<K: Hash + Eq + Clone> { /* … */ }

impl<K: Hash + Eq + Clone> TopK<K> {
    pub fn new(k: usize) -> Self;
    pub fn observe(&mut self, key: K);
    pub fn observe_n(&mut self, key: K, count: u64);
    pub fn top(&self) -> Vec<(&K, u64)>;
    pub fn estimate(&self, key: &K) -> u64;
    pub fn clear(&mut self);
}

// src/correlate/ewma.rs
pub struct Ewma<K: Hash + Eq> { /* … */ }

impl<K: Hash + Eq> Ewma<K> {
    pub fn new(alpha: f64) -> Self;
    pub fn record(&mut self, key: K, sample: f64) -> f64;
    pub fn get(&self, key: &K) -> Option<f64>;
    pub fn iter(&self) -> impl Iterator<Item = (&K, f64)>;
    pub fn evict_stale(&mut self, now: Timestamp, ttl: Duration);
}
```

### Files

```
src/correlate/set.rs         # NEW
src/correlate/burst.rs       # NEW
src/correlate/topk.rs        # NEW
src/correlate/ewma.rs        # NEW
src/correlate/mod.rs         # add 4 re-exports
tests/correlate_extensions.rs       # NEW — 12+ scenarios
examples/port_scan_detector.rs      # MIGRATED → TimeBucketedSet
examples/failed_auth_burst.rs       # MIGRATED → BurstDetector
docs/recipes.md              # add "Cross-flow detector primitives"
```

### Implementation steps (sub-A)

1. `set.rs` — `TimeBucketedSet`. Reuses
   `TimeBucketedCounter`'s `VecDeque<bucket>` skeleton.
2. `burst.rs` — `BurstDetector`. Per-key ring-buffer of recent
   burst events + "primed" flag.
3. `topk.rs` — Misra-Gries. Exact ≤ k; bounded error after.
4. `ewma.rs` — `HashMap<K, (ewma, last_touch)>`.
5. Migrate `port_scan_detector.rs` + `failed_auth_burst.rs`.
6. `docs/recipes.md` section + CHANGELOG entry.

### Tests (sub-A)

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
- pure-burst mode fires on the Nth burst event.
- per-key isolation.

// TopK
- ≤ k distinct keys: exact counts.
- 2k distinct keys: top is still correct (Misra-Gries).
- observe_n bulk-inserts work.
- clear resets state.

// Ewma
- alpha=1.0 → output equals last sample.
- alpha=0.5 → output = average of last two.
- per-key isolation.
- evict_stale drops untouched entries.
```

---

## Sub-plan B — `flowscope::aggregate`

### API additions

```rust
// src/aggregate/histogram.rs
pub struct Histogram { /* explicit-bucket counter */ }

impl Histogram {
    pub fn with_buckets(boundaries: &[f64]) -> Self;
    pub fn log_spaced(low: f64, high: f64, count: usize) -> Self;
    pub fn record(&mut self, value: f64);
    pub fn quantile(&self, q: f64) -> f64;
    pub fn samples(&self) -> u64;
    pub fn mean(&self) -> f64;
    pub fn min(&self) -> f64;
    pub fn max(&self) -> f64;
    pub fn merge(&mut self, other: &Histogram) -> Result<(), HistogramError>;
    pub fn buckets(&self) -> impl Iterator<Item = (f64, u64)> + '_;
}

// src/aggregate/percentile.rs — t-digest wrapper
pub struct Percentile { /* … */ }

impl Percentile {
    pub fn new(compression: u32) -> Self;
    pub fn record(&mut self, value: f64);
    pub fn quantile(&self, q: f64) -> f64;
    pub fn samples(&self) -> u64;
}
```

### Files

```
src/aggregate/mod.rs           # NEW — module entry + re-exports
src/aggregate/histogram.rs     # NEW
src/aggregate/percentile.rs    # NEW — wraps tdigest crate
Cargo.toml                     # new `aggregate` feature (dep: tdigest)
tests/aggregate.rs             # 4+ scenarios
examples/flow_duration_histogram.rs  # MIGRATED
docs/recipes.md                # add "Aggregation primitives"
```

### Implementation steps (sub-B)

1. Add Cargo feature `aggregate = ["dep:tdigest"]`.
2. `Histogram` (no deps).
3. `Percentile` (wraps `tdigest::TDigest`).
4. Migrate `examples/flow_duration_histogram.rs`.
5. `docs/recipes.md` + CHANGELOG.

### Tests (sub-B)

```rust
- Histogram::record + quantile reasonable values.
- Histogram::merge correctness.
- Percentile: 1000 samples in [0,1], quantile(0.5) ≈ 0.5 ± 0.01.
- log_spaced bucket boundaries geometric.
```

---

## Sub-plan C — `flowscope::detect`

### API additions

```rust
// src/detect/mod.rs

/// Shannon entropy in bits per byte. `0.0` for empty.
/// Range: `[0.0, 8.0]`.
pub fn shannon_entropy(bytes: &[u8]) -> f64;

/// `true` iff `shannon_entropy(bytes) >= threshold`.
pub fn is_high_entropy(bytes: &[u8], threshold: f64) -> bool;

pub fn is_base64ish(s: &str) -> bool;
pub fn is_hex_string(s: &str) -> bool;

/// Hamming distance — `None` if lengths differ.
pub fn hamming_distance(a: &[u8], b: &[u8]) -> Option<usize>;

pub fn ngram_distribution(bytes: &[u8], n: usize) -> NgramDist;

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct NgramDist {
    pub n: usize,
    pub samples: u64,
    pub counts: HashMap<Vec<u8>, u64>,
}

impl NgramDist {
    pub fn mode(&self) -> Option<(&Vec<u8>, u64)>;
    pub fn entropy(&self) -> f64;
    pub fn distinct(&self) -> usize;
}
```

### Files

```
src/detect/mod.rs            # NEW — six functions + NgramDist
tests/detect.rs              # 6+ scenarios
examples/dns_tunnel_detector.rs   # MIGRATED → shannon_entropy
docs/recipes.md              # extend detect recipe section
```

### Implementation steps (sub-C)

1. `src/detect/mod.rs` with the six functions + `NgramDist`.
2. Wire `pub mod detect` in `src/lib.rs`.
3. Migrate `examples/dns_tunnel_detector.rs`.
4. CHANGELOG entry.

### Tests (sub-C)

```rust
- shannon_entropy(b"AAAA") == 0.0.
- shannon_entropy(b"abcd") > 1.99.
- is_base64ish("AAAA====") == true.
- is_hex_string("deadbeef") == true.
- hamming_distance(b"foo", b"fob") == Some(1).
- ngram_distribution(b"aaab", 2) → {"aa": 2, "ab": 1}.
```

### Out of scope (sub-C)

- Regex-based detection.
- Known-bad signature lists (Suricata rules).
- YARA-style rule engine.
- Statistical anomaly detection (variance, z-score).

---

## Sub-plan D — `flowscope::well_known`

### API additions

```rust
// src/well_known/mod.rs

/// Canonical short label for the given (proto, port).
/// Always uses the lower-numbered port to disambiguate
/// client / server pairs.
pub fn protocol_label(proto: L4Proto, src_port: u16, dst_port: u16)
    -> Option<&'static str>;

pub fn entries() -> impl Iterator<Item = (L4Proto, u16, &'static str)>;

impl FiveTupleKey {
    pub fn well_known_port(&self) -> u16;
    pub fn protocol_label(&self) -> Option<&'static str>;
}
```

### Table content (~80 entries)

```
TCP:
  20-21 ftp, 22 ssh, 23 telnet, 25/587 smtp, 53 dns,
  80/8000/8080 http, 110 pop3, 143 imap, 443/8443 tls/https,
  465 smtps, 993 imaps, 995 pop3s,
  1433 mssql, 1521 oracle, 2049 nfs, 3306 mysql, 3389 rdp,
  5432 postgres, 5672 amqp, 5984 couchdb, 6379 redis,
  6443 kubernetes-api, 6667 irc, 7000-7001 cassandra,
  8088 hbase, 8500 consul, 9000-9001 minio, 9042 cassandra-cql,
  9092-9093 kafka, 9200/9300 elasticsearch, 10000 webmin,
  11211 memcached, 15672 rabbitmq-mgmt, 27017 mongodb, 50070 hdfs

UDP:
  53 dns, 67-68 dhcp, 69 tftp, 88 kerberos, 123 ntp,
  137-139 netbios, 161-162 snmp, 389 ldap,
  443 quic/http3, 500/4500 ipsec, 514 syslog, 636 ldaps,
  1812-1813 radius, 2049 nfs, 2152 gtp-u, 3478 stun,
  4789 vxlan, 5060-5061 sip
```

Initial: `&'static [(L4Proto, u16, &'static str)]` constant
+ small binary-search function. Switch to `phf::Map` if
benchmarks show the linear/binary path matters.

### Files

```
src/well_known/mod.rs              # NEW — public API + curated table
src/extract/five_tuple.rs          # add FiveTupleKey accessors
tests/well_known.rs                # 4+ scenarios
examples/bandwidth_by_protocol.rs  # MIGRATED → protocol_label
docs/recipes.md                    # one-paragraph note
```

### Implementation steps (sub-D)

1. `src/well_known/mod.rs` with the curated table and
   `protocol_label()`.
2. Add `FiveTupleKey::well_known_port()` +
   `protocol_label()` accessors.
3. Migrate `examples/bandwidth_by_protocol.rs`.
4. CHANGELOG entry.

### Tests (sub-D)

```rust
- 80 → http, 443 → tls/https, 53 → dns, 6379 → redis.
- Unknown port → None.
- Lower-port disambiguation: 80 + 33000 → "http".
- entries() iteration count matches the table size.
```

---

## Acceptance criteria (whole plan)

- Four sub-PRs land — A (correlate ext) / B (aggregate) /
  C (detect) / D (well-known).
- 4 example migrations (`port_scan_detector`,
  `failed_auth_burst`, `flow_duration_histogram`,
  `dns_tunnel_detector`, `bandwidth_by_protocol`) — LoC
  down meaningfully in each.
- `cargo test --all-features` clean across each PR.
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- `cargo doc --all-features --no-deps` zero warnings.
- One CHANGELOG entry per sub-PR under 0.10.0 "Added".

## Risks (whole plan)

- **Misra-Gries TopK approximation surprises** (A) —
  document the trade-off; expose `estimate()` separately
  from `top()`.
- **Ewma floating-point precision** (A) — `f64` throughout;
  document precision floor for very small alphas.
- **Memory growth without `evict_*` calls** (A) — document
  the eviction contract.
- **`tdigest` crate dependency** (B) — gate behind the
  `aggregate` feature; zero-cost when off.
- **`detect` module sprawl** (C) — hard "consumer must ask"
  rule for additions beyond the initial six. Document the
  rule in `docs/recipes.md`.
- **`well_known` table drift over time** (D) — curate
  against the IANA registry once per minor release.

## Effort

| Sub-PR | LoC | Hours |
|--------|-----|-------|
| A — correlate extensions | ~1,010 | ~20 |
| B — aggregate module | ~440 | ~11 |
| C — detect module | ~295 | ~6 |
| D — well-known module | ~335 | ~6 |
| **Total** | **~2,080** | **~43** |

## Provenance

Postmortem theme 5 (consolidated):

> `correlate` is missing common shapes. Set-with-TTL,
> top-K-by-rate, percentile bucketers — every detector
> example reinvented one.
>
> Manual histogram bucketing. Manual p50 / p99 / max via
> sort+index. Same `Timestamp` → f64 boilerplate.
>
> Wrote Shannon entropy in 13 lines. Common enough it
> should ship.
>
> `bandwidth_by_protocol` example hard-coded a 24-entry
> port table.

Consolidated from prior individual plans 102, 103, 104,
and 105 (all four shared theme 5 and shipped as
independent small additions).

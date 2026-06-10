# Plan 143 — `flowscope::detect::patterns` — named detectors

## Summary

Package the existing `correlate` + `detect` primitives as
named, parameter-tuned detectors so the FAQ "how do I detect
X" stops requiring users to compose Misra-Gries + EWMA +
Shannon entropy from scratch.

Three shipped detectors (the canonical security FAQ):

- **`BeaconDetector<K>`** — periodic outbound traffic (C2
  heartbeat). Coefficient-of-variation on inter-arrival times,
  RITA-style composite score on bytes consistency.
- **`PortScanDetector<K>`** — Threshold Random Walk (Jung et
  al., IEEE S&P 2004). Per-source sequential hypothesis test
  on success/failure connection outcomes.
- **`DgaScorer`** — bigram log-likelihood scoring on a domain
  name. Bundled Tranco-derived bigram table (~6 KB embedded
  via `include_bytes!`).

Always-on (no feature gate). No new runtime deps. Pure
algorithm + tuned thresholds + a small embedded dataset. Each
detector returns a typed *score* — not a verdict — so consumers
keep policy.

## Status

Not started.

## Prerequisites

None. (Builds on existing `correlate::TopK` / `Ewma` /
`TimeBucketedSet` / `BurstDetector` and `detect::shannon_entropy`.)

## Out of scope

- **No rule engine.** Detectors emit scores, not actions.
- **No ML / neural-net scoring.** Pure statistics + bigram
  table. ML belongs in a downstream consumer crate.
- **No live tuning / threshold adaptation.** Static parameters
  per detector; consumer overrides at construction.
- **No GeoIP, ASN, OUI lookup.** Defer; bring-your-own data.
- **DNS tunnel detection is NOT in this plan.** Already shipped
  via `examples/03-detection/dns_tunnel_detector.rs`; the
  `DgaScorer` here is the building block.

## Pre-1.0 breaks

None. Additive.

## Files

| Action | Path | Purpose |
|---|---|---|
| New | `src/detect/patterns/mod.rs` | Re-exports + module doc |
| New | `src/detect/patterns/beacon.rs` | `BeaconDetector<K>` |
| New | `src/detect/patterns/portscan.rs` | `PortScanDetector<K>` |
| New | `src/detect/patterns/dga.rs` | `DgaScorer` + embedded bigram table |
| New | `src/detect/patterns/bigrams.bin` | Bigram table binary (`include_bytes!`) — Tranco-derived |
| Modify | `src/detect/mod.rs` | `pub mod patterns;` |
| Modify | `src/lib.rs` | `pub use detect::patterns::*` in prelude |
| New | `tests/detect_beacon.rs` | Synthetic-traffic beacon tests |
| New | `tests/detect_portscan.rs` | Known-scanner / known-benign tests |
| New | `tests/detect_dga.rs` | DGArchive / Tranco labeled tests |
| New | `examples/03-detection/c2_beacon_finder.rs` | Pcap → flagged beacons |
| New | `examples/03-detection/dga_finder.rs` | Pcap → scored DNS qnames |
| Modify | `examples/03-detection/port_scan_detector.rs` | Replace inline TRW math with `PortScanDetector` |
| New | `docs/detect-patterns.md` | Algorithm references + threshold rationale |
| Modify | `CHANGELOG.md` | 0.12 entry |

## API

### `BeaconDetector<K>`

```rust
// src/detect/patterns/beacon.rs

use std::collections::HashMap;
use std::collections::VecDeque;
use std::hash::Hash;
use std::time::Duration;

use crate::Timestamp;

/// Per-key beacon detector.
///
/// State: rolling window of N inter-arrival times + byte counts.
/// Score range: 0.0 (no beacon) to 1.0 (perfect beacon). Composite
/// RITA-style:
///   `score = 0.5*(1−CV_dt) + 0.3*(1−CV_bytes) + 0.2*duration_bonus`
///
/// Suppresses chatty short-lived flows: requires N≥10 observations
/// and μ_dt ∈ [10s, 24h] before scoring.
pub struct BeaconDetector<K>
where K: Hash + Eq + Clone
{
    window: usize,
    min_interval: Duration,
    max_interval: Duration,
    keys: HashMap<K, BeaconState>,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BeaconScore<K> {
    pub key: K,
    /// 0.0–1.0; higher = more beacon-like.
    pub score: f64,
    /// Mean inter-arrival time over the window.
    pub mean_interval: Duration,
    /// CV of inter-arrival times.
    pub cv_dt: f64,
    /// CV of byte counts.
    pub cv_bytes: f64,
    /// Observations in the window.
    pub n: usize,
}

impl<K> BeaconDetector<K>
where K: Hash + Eq + Clone
{
    /// Default tuning: window=20, interval ∈ [10s, 24h].
    /// Matches RITA's standard thresholds.
    pub fn new() -> Self { … }

    pub fn with_window(window: usize) -> Self { … }
    pub fn with_interval_range(min: Duration, max: Duration) -> Self { … }

    /// Record an observation. Returns `Some(BeaconScore)` if
    /// the window is full and the mean interval is in range,
    /// otherwise `None`.
    pub fn observe(&mut self, key: K, ts: Timestamp, bytes: u64)
        -> Option<BeaconScore<K>> { … }

    /// Drop per-key state (call on flow end).
    pub fn forget(&mut self, key: &K) { … }
}
```

### `PortScanDetector<K>` (Threshold Random Walk)

```rust
// src/detect/patterns/portscan.rs

use std::collections::HashMap;
use std::hash::Hash;

/// Per-source scanner-likelihood detector.
///
/// Implements Threshold Random Walk (Jung et al., "Fast
/// Portscan Detection Using Sequential Hypothesis Testing",
/// IEEE S&P 2004).
///
/// Updates a log-likelihood ratio per source IP:
///   on success connection: λ += log(θ1/θ0) ≈ −1.386
///   on failed  connection: λ += log((1−θ1)/(1−θ0)) ≈ +1.386
/// where θ0 = P(success | benign) = 0.8 and θ1 = P(success |
/// scanner) = 0.2.
///
/// Verdict thresholds: scanner if λ ≥ +4.595 (α = β = 0.01);
/// benign if λ ≤ −4.595.
pub struct PortScanDetector<K>
where K: Hash + Eq + Clone
{
    sources: HashMap<K, ScannerState>,
    success_step: f64,  // log(θ1/θ0)
    failure_step: f64,  // log((1−θ1)/(1−θ0))
    threshold_scanner: f64,  // η1 = log((1−β)/α)
    threshold_benign: f64,   // η0 = log(β/(1−α))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScanVerdict {
    Scanner,
    Benign,
    Inconclusive,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ScanScore<K> {
    pub key: K,
    pub verdict: ScanVerdict,
    pub log_likelihood: f64,
    pub n_observed: u32,
}

impl<K> PortScanDetector<K>
where K: Hash + Eq + Clone
{
    /// Default: θ0=0.8, θ1=0.2, α=β=0.01.
    pub fn new() -> Self { … }

    pub fn with_priors(theta0: f64, theta1: f64) -> Self { … }
    pub fn with_error_rates(alpha: f64, beta: f64) -> Self { … }

    /// Record a connection outcome. `success = true` for
    /// completed 3WHS; `false` for SYN-only or RST response.
    /// Returns the updated score with verdict.
    pub fn observe(&mut self, key: K, success: bool) -> ScanScore<K> { … }

    pub fn forget(&mut self, key: &K) { … }
}
```

### `DgaScorer`

```rust
// src/detect/patterns/dga.rs

/// DGA likelihood scorer using bigram log-likelihood over a
/// bundled Tranco-derived bigram table.
///
/// Higher (less negative) → more "natural" English-like
/// domain; lower → more DGA-like.
///
/// Typical threshold: -2.8 (natural log) flags DGA with ~5%
/// FPR on Tranco-100k vs DGArchive labeled traffic.
///
/// Auxiliary features (returned alongside the score) for
/// composite scoring: length, vowel ratio, digit ratio,
/// max consonant run, character entropy.
pub struct DgaScorer {
    bigram: &'static [[f32; 38]; 38],
}

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct DgaScore {
    /// Mean log-likelihood per bigram (natural log).
    /// More negative = more DGA-like.
    pub log_likelihood: f32,
    pub length: u32,
    pub vowel_ratio: f32,
    pub digit_ratio: f32,
    pub max_consonant_run: u32,
    /// Shannon entropy bits/char over [a-z0-9-].
    pub char_entropy: f32,
}

impl DgaScorer {
    /// Construct with the bundled Tranco-derived bigram table.
    pub fn new() -> Self { … }

    /// Score the SLD (consumer must already have stripped TLD
    /// and lowercased). Returns a `DgaScore` snapshot.
    pub fn score(&self, sld: &str) -> DgaScore { … }

    /// Convenience verdict against the default threshold
    /// (`log_likelihood < -2.8`). Use raw `DgaScore` fields
    /// for custom thresholds / ensembles.
    pub fn is_dga(&self, sld: &str) -> bool {
        self.score(sld).log_likelihood < -2.8
    }
}
```

### Bigram table

`src/detect/patterns/bigrams.bin` — `[[f32; 38]; 38] = 5776`
bytes. Alphabet: `a..z` (26) + `0..9` (10) + `-` (1) + `.`
(1) = 38 classes. Computed from Tranco-1M (pinned snapshot,
date documented in `docs/detect-patterns.md`). Embedded via
`include_bytes!`. Pre-generated by a small script in
`tools/generate-bigrams.rs`; the script is documented but not
shipped to consumers.

## Implementation steps

### Phase 1: Module skeleton

1. `src/detect/patterns/mod.rs` (new) with re-exports.
2. `src/detect/mod.rs`: `pub mod patterns;`.

### Phase 2: PortScanDetector

3. Implement Sequential Hypothesis Test math.
4. Default thresholds from the 2004 paper.
5. Test against a known-scanner (TRW reference) trace and a
   known-benign trace.

### Phase 3: BeaconDetector

6. Rolling window of (timestamp, bytes) tuples.
7. CV computation; RITA composite score.
8. Threshold tests against synthetic-beacon and chatty-short-
   flow traces.

### Phase 4: DgaScorer

9. Generate the bigram table from a Tranco snapshot. Script
   under `tools/generate-bigrams.rs`. Output:
   `src/detect/patterns/bigrams.bin`. Document the snapshot
   date in `docs/detect-patterns.md`.
10. `DgaScorer` implementation. Embed via `include_bytes!`;
    runtime parse to `&'static [[f32; 38]; 38]` via
    `bytemuck::cast_slice`.
11. Test against DGArchive samples (Conficker, Tinba, Gameover
    Zeus) → expected `is_dga() == true`.
12. Test against Tranco top-100 → expected
    `is_dga() == false`.

### Phase 5: Examples + docs

13. `examples/03-detection/c2_beacon_finder.rs` — pcap → list
    of flagged (src, dst, dport) tuples with their scores.
14. `examples/03-detection/dga_finder.rs` — pcap → scored DNS
    qnames, top-K most-DGA-like.
15. `examples/03-detection/port_scan_detector.rs` — refactor
    existing example to use `PortScanDetector` directly.
16. `docs/detect-patterns.md` — algorithm references, threshold
    rationale, dataset provenance, citation list.

## Tests

### Unit

- `beacon::tests::synthetic_perfect_beacon_scores_above_0_9`
- `beacon::tests::chatty_short_flow_scores_none`
- `beacon::tests::jittered_beacon_within_15_percent_cv`
- `portscan::tests::all_success_eventually_benign_verdict`
- `portscan::tests::all_failure_eventually_scanner_verdict`
- `portscan::tests::mixed_outcomes_stays_inconclusive`
- `portscan::tests::custom_priors_override_thresholds`
- `dga::tests::tranco_top_10_score_below_threshold` (benign)
- `dga::tests::conficker_dga_samples_score_above_threshold`
- `dga::tests::short_domain_handled_gracefully`
- `dga::tests::digit_heavy_dga_scores_dga_via_aux_features`

### Integration

- `tests/detect_beacon.rs::scanner_traffic_pattern_finds_beacons`
- `tests/detect_portscan.rs::nmap_syn_scan_trace_classifies_scanner`
- `tests/detect_dga.rs::dga_archive_recall_above_90_percent`
- `tests/detect_dga.rs::tranco_top_1000_fpr_below_5_percent`

## Acceptance criteria

- `cargo build` (default features) clean.
- `cargo test` clean — all detector tests including the
  recall / FPR thresholds.
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- DGA recall ≥ 90% on labelled DGArchive families.
- DGA false-positive rate < 5% on Tranco top-1000.
- Port-scan TRW reproduces the verdict timing from the
  2004 paper's example traces (decision within 4-6 observations
  for clear-cut cases).
- `examples/03-detection/c2_beacon_finder.rs` and
  `dga_finder.rs` run end-to-end on the shipped pcap fixtures.
- `docs/detect-patterns.md` complete with algorithm citations
  and dataset provenance.
- The bundled bigram table is reproducible — running
  `tools/generate-bigrams.rs` against the documented Tranco
  snapshot produces byte-identical output.

## Risks

- **R1: Tranco snapshot expiry.** Tranco regenerates daily.
  Pin a specific date in the documentation; consumers can
  regenerate with their own snapshot if desired.
- **R2: Bigram table license.** Tranco is CC-BY-4.0. Our
  computed bigram table is a derived statistical aggregate;
  document attribution per the license terms.
- **R3: DGA classifier overfitting.** Bigram-only scoring
  catches algorithmic / random-looking domains but misses
  dictionary-based DGAs (Gozi, Suppobox). Document the
  limitation; suggest composite scoring with the auxiliary
  features for those families.
- **R4: PortScan FPs on legitimate scanners (Shodan,
  Censys, internal asset scanners).** Document; suggest a
  consumer-side allowlist of source IPs / ASNs.
- **R5: Beacon false positives on NTP, DNS background queries,
  metrics scrapes.** The 10s minimum interval helps; document
  the residual cases.

## Effort

| Step | LoC | Hours |
|---|---|---|
| Module skeleton + module doc | 30 | 0.5 |
| BeaconDetector + score composition | 200 | 4 |
| PortScanDetector (TRW) | 150 | 3 |
| DgaScorer + auxiliary features | 250 | 5 |
| Bigram table generation script (tools/) | 80 | 2 |
| Tests (11 unit + 4 integration) | 350 | 6 |
| 3 examples + refactor 1 example | 250 | 5 |
| docs/detect-patterns.md | 120 | 3 |
| CHANGELOG | 30 | 0.5 |
| **Total** | **~1460** | **~29 hours (~4 days)** |

## Provenance

netring 0.21 wishlist (Phase G §"Named detectors") + 0.12
audit Tier-2. flowscope already has the building blocks (TopK,
BurstDetector, Ewma, shannon_entropy, TimeBucketedSet); the
gap is that every consumer rebuilds the same three FAQ
detectors. Packaging them as named, threshold-tuned APIs:

- saves consumers ~200 LoC per pipeline,
- pins canonical algorithm references (Jung 2004 for TRW;
  RITA for the beacon composite; Tranco for the DGA baseline),
- keeps verdict policy in the consumer's hands.

References:
- Jung, Paxson, Berger, Balakrishnan, "Fast Portscan Detection
  Using Sequential Hypothesis Testing", IEEE S&P 2004.
- ActiveCM RITA: `github.com/activecm/rita` (beacon CV
  thresholds + composite score formula).
- Tranco list: `tranco-list.eu`.
- DGArchive: `github.com/baderj/domain_generation_algorithms`
  (DGA samples for testing).

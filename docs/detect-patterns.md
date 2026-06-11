# `flowscope::detect::patterns` — named detectors

Three canonical security FAQ detectors, packaged as parameter-
tuned named types so consumers stop reinventing them. Each
returns a typed **score** (not a verdict) so policy stays in
the consumer's hands.

Always-on. No new runtime deps. No feature gate. New in 0.12
(plan 143).

## `PortScanDetector<K>` — Threshold Random Walk

Per-source scanner-likelihood detector implementing the
sequential hypothesis test from Jung, Paxson, Berger, and
Balakrishnan, "Fast Portscan Detection Using Sequential
Hypothesis Testing" (IEEE S&P 2004).

Per source `K` (typically `IpAddr`), maintain a log-likelihood
ratio λ. On each observed connection outcome:

```text
  success → λ += log(θ1 / θ0)        ≈ −1.386
  failure → λ += log((1−θ1)/(1−θ0))  ≈ +1.386
```

with the paper's defaults θ0 = P(success | benign) = 0.8 and
θ1 = P(success | scanner) = 0.2.

Verdict thresholds (α = β = 0.01 false-positive / false-
negative rates):

```text
  η1 = log((1−β) / α) ≈ +4.595  → Scanner
  η0 = log(β / (1−α)) ≈ −4.595  → Benign
```

State **resets** the moment a verdict crosses a threshold — the
next `observe(k, …)` starts fresh at λ = 0. Consumers wanting
persistent classification keep their own map keyed by
`ScanScore::key`.

```rust,ignore
use flowscope::detect::patterns::{PortScanDetector, ScanVerdict};

let mut d: PortScanDetector<std::net::IpAddr> = PortScanDetector::new();
let s = d.observe(client_ip, three_way_handshake_completed);
match s.verdict {
    ScanVerdict::Scanner => alert(s.key),
    ScanVerdict::Benign  => whitelist(s.key),
    ScanVerdict::Inconclusive => {}
}
```

### Tuning

`with_params(theta0, theta1, alpha, beta)` for stricter or
laxer priors. Smaller α tightens the Scanner threshold;
smaller β tightens the Benign threshold.

### Limitations

- Misses **distributed** scans (many sources, few connections
  each). Pair with a separate cross-source aggregator if
  you care about that.
- Legitimate **fan-out** sources (CDN edges, asset scanners
  like Shodan / Censys) need an allowlist on the consumer
  side — the detector classifies them as Scanner.

## `BeaconDetector<K>` — coefficient-of-variation periodicity

Per-key rolling window of (timestamp, bytes) tuples. Score
range 0.0 (no beacon) → 1.0 (perfect beacon). Composite
RITA-style:

```text
  score = 0.5 · (1 − CV_dt)
        + 0.3 · (1 − CV_bytes)
        + 0.2 · duration_bonus
```

Where:

- `CV_dt`    = stddev / mean of inter-arrival intervals.
- `CV_bytes` = stddev / mean of payload byte counts.
- `duration_bonus` = `min(1, window_span / 30 min)` —
  rewards beacons that sustain over time.

**Suppresses chatty short-lived flows**: requires `n ≥ 10`
observations AND mean interval ∈ `[10 s, 24 h]` before
returning `Some(…)`.

```rust,ignore
use flowscope::detect::patterns::BeaconDetector;
use flowscope::extract::FiveTupleKey;

let mut d: BeaconDetector<FiveTupleKey> = BeaconDetector::new();
if let Some(score) = d.observe(key, packet_ts, packet_bytes) {
    if score.score > 0.85 {
        eprintln!("beacon: {:?} every {:?}", score.key, score.mean_interval);
    }
}
```

### Tuning

- `with_window(n)` — rolling window size; default 20.
- `with_interval_range(min, max)` — gate; default 10 s – 24 h.

### Reference

ActiveCM RITA: <https://github.com/activecm/rita> — the
composite-score weights and threshold methodology this
implementation follows.

## `DgaScorer` — bigram log-likelihood

Mean per-bigram log-likelihood over a 37-class alphabet
(a-z + 0-9 + `-`). The bigram probability table is compiled
once at first use from an embedded ~80-domain English baseline
(google / facebook / amazon / etc.), Laplace-smoothed
(pseudo-count 1).

```text
  S(domain) = (1 / (L − 1)) · Σ_{i=1..L−1} log P(c_{i+1} | c_i)
```

Higher (less negative) → more "natural" English-like. Lower →
more DGA-like. Default verdict threshold:
`log_likelihood < -3.5`.

```rust,ignore
use flowscope::detect::patterns::DgaScorer;

let scorer = DgaScorer::new();
for qname in dns_queries {
    let sld = strip_tld(&qname);
    let score = scorer.score(&sld);
    if score.log_likelihood < -3.5 {
        flag(qname, score);
    }
}
```

`DgaScore` also surfaces auxiliary features useful for
composite scoring:

| Field | Meaning |
|---|---|
| `length` | SLD length post-classification |
| `vowel_ratio` | vowels / alphabetic chars |
| `digit_ratio` | digits / total |
| `max_consonant_run` | longest run of consonants |
| `char_entropy` | Shannon entropy bits/char |

### Tuning

- `is_dga_with_threshold(sld, threshold)` overrides the −3.5
  default.

### Limitations

- **Misses dictionary-based DGAs** (Gozi, Suppobox) — these
  use real-word concatenation and score in the same band as
  legitimate domains. Pair with the auxiliary features
  (length > 12 + 0 digits + low entropy is a signal) or use
  a labelled-supervised classifier downstream.
- Embedded baseline is small (~80 SLDs). Consumers wanting
  tight FPR control compute their own bigram table from a
  representative SLD list (Tranco, internal allowlist) and
  ship a custom scorer.
- TLD stripping is the **caller's** job. The shipped
  `dga_finder` example uses a naive "last-2-labels minus the
  rightmost" heuristic; for strict eTLD+1 handling pair with
  the `publicsuffix` crate.

## Examples

- `examples/03-detection/c2_beacon_finder.rs` — replay a pcap,
  flag top beacon candidates.
- `examples/03-detection/dga_finder.rs` — replay a pcap,
  score DNS query names, rank suspicious SLDs.
- `examples/03-detection/port_scan_detector.rs` (pre-existing
  in 0.10 cycle) — refactor target if you want a
  `PortScanDetector` migration recipe.

## Why these three

The 0.12 strategic review identified these as the canonical
"how do I detect X" FAQ recipes consumers keep rebuilding from
the existing `correlate::TopK` / `Ewma` / `BurstDetector` and
`detect::shannon_entropy` primitives.

Packaging them as named, threshold-tuned APIs:

- saves consumers ~200 LoC per pipeline,
- pins canonical algorithm references (so a future spec drift
  surfaces as a documented change, not a silent regression),
- keeps verdict policy in the consumer's hands (we emit
  scores, not actions).

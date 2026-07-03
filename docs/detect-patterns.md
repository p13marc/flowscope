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

## Emitting detector output via `OwnedAnomaly` (0.13)

Every shipped detector's score implements
[`flowscope::DetectorScore`] and has an inherent
`into_anomaly(ts: Timestamp) -> OwnedAnomaly` method that
converts it to the canonical [`flowscope::OwnedAnomaly`] shape:

- **`ScanScore<K>`** → `DetectorKind::PortScanTrw`
  (slug `"PortScanTRW"`); verdict
  observation + `log_likelihood` + `n_observed` metrics;
  severity follows verdict (`Scanner` → `Warning`,
  `Benign`/`Inconclusive` → `Info`).
- **`BeaconScore<K>`** → `DetectorKind::BeaconCv`
  (slug `"BeaconCv"`); `score` + `cv_dt`
  + `cv_bytes` + `mean_interval_secs` + `n` metrics; severity
  `Warning` (beacon only emits when it has a hit).
- **`DgaScore`** → `DetectorKind::Dga` (slug
  `"DgaScorer"`); six feature metrics
  (`log_likelihood`, `length`, `vowel_ratio`, `digit_ratio`,
  `max_consonant_run`, `char_entropy`); severity `Info`
  (consumer thresholds on `log_likelihood` to escalate).

DGA is keyless on the detector side but consumers usually have
the DNS-query flow context — the inherent method takes
`Option<&dyn KeyFields>` for the flow key. The `DetectorScore`
trait impl is the keyless convenience (`into_anomaly(ts)`
delegates to `into_anomaly(ts, None)`).

End-to-end emit example:

```rust,ignore
use flowscope::detect::patterns::PortScanDetector;
use flowscope::emit::EveJsonWriter;
use flowscope::extract::FiveTupleKey;

let mut port_scan: PortScanDetector<FiveTupleKey> =
    PortScanDetector::new();
let mut eve = EveJsonWriter::new(std::io::stdout());

for (key, success) in connection_outcomes {
    let score = port_scan.observe(key, success);
    eve.write_owned_anomaly(&score.into_anomaly(ts))?;
}
```

For generic-over-detector routing, write the function bound
on `DetectorScore`:

```rust,ignore
use flowscope::{DetectorScore, Timestamp};
use flowscope::emit::EveJsonWriter;
use std::io::Write;

fn emit<S: DetectorScore, W: Write>(
    eve: &mut EveJsonWriter<W>,
    score: S,
    ts: Timestamp,
) -> std::io::Result<()> {
    eve.write_owned_anomaly(&score.into_anomaly(ts))
}
```

For custom detectors, implement `DetectorScore` on your score
type and you get the same uniform emit path:

```rust,ignore
use flowscope::{DetectorKind, DetectorScore, OwnedAnomaly, Timestamp};
use flowscope::event::Severity;

struct MyScore { hits: u32, max_burst: u32 }

impl DetectorScore for MyScore {
    fn kind(&self) -> DetectorKind { DetectorKind::Other("MyCustomDetector") }
    fn into_anomaly(self, ts: Timestamp) -> OwnedAnomaly {
        OwnedAnomaly::new(DetectorKind::Other("MyCustomDetector"), Severity::Warning, ts)
            .with_metric("hits", self.hits as f64)
            .with_metric("max_burst", self.max_burst as f64)
    }
}
```

See [`docs/eve-format.md`](eve-format.md) §"Custom anomaly
emission via `OwnedAnomaly` (0.13)" for the EVE schema mapping
and [`docs/recipes.md`](recipes.md) §"0.13 patterns" for the
end-to-end recipe.

## Unified `Detector` trait + `DetectorRegistry` (0.21, #131)

Registering detectors on a [`DetectorRegistry`] drives a
heterogeneous set from **one** call per event, instead of
hand-wiring each detector's feed/drain loop. The registry keeps
the genuinely-different observe inputs but unifies dispatch:

```rust,ignore
use flowscope::detect::{DetectorRegistry, DgaDetector, HostPair, SrcHost};
use flowscope::detect::patterns::{BeaconDetector, PortScanDetector};
use flowscope::extract::FiveTupleKey;

let mut registry: DetectorRegistry<FiveTupleKey> = DetectorRegistry::new();
registry
    .register(BeaconDetector::<HostPair>::new())   // aggregates per (src, dst, port)
    .register(PortScanDetector::<SrcHost>::new())  // aggregates per source IP
    .register(DgaDetector::new());                 // feeds off DNS query names

// per flow event (from FlowTracker or the typed Driver):
registry.observe(&flow_event, &mut anomalies);      // or observe_event(&driver_event, …)
// per DNS query name (from a DNS slot drain):
registry.observe_dns(&key, qname, ts, &mut anomalies);
// periodically:
registry.evict_expired(now);
```

Each detector implements the [`Detector`] trait — a set of
defaulted, no-op **lifecycle hooks** (`on_flow_start`,
`on_flow_end`, `on_dns_query`, …), so a detector implements only
the feeds it consumes. Anomalies append to a caller-owned
`Vec<OwnedAnomaly>` (the `track_into` idiom — zero per-event
allocation, no unbounded internal queues).

**Derived aggregation keys.** Registry detectors see the *flow*
key `K`, but beaconing and scanning aggregate *across* flows
(every beacon ping is its own ephemeral 5-tuple). The shipped
[`SrcHost`] (source IP) and [`HostPair`] (`src`, `dst`,
`dst_port`) keys implement `KeyFields + Hash + Eq`, derive from
any flow key via `from_key`, and replace the `SrcIpKey` newtype
consumers used to re-declare.

**Actionable-only emission.** The shipped impls gate on
per-detector thresholds + cooldowns
(`BeaconDetector::with_anomaly_threshold` / `with_cooldown`;
port-scan emits only on a `Scanner` verdict;
`DgaDetector::with_threshold` + per-`(src, domain)` suppression),
so a registry drain is alert-shaped, not score-shaped. Call the
detectors' raw `observe` methods directly when you want every
score.

**Port-scan success signal** is derived statelessly at flow end:
for TCP, the responder answered the handshake (`'s'` in the
Zeek-style [`HistoryString`]); for UDP, any responder packet.
An unanswered SYN or a RST refusal both read as failure.

Every emitted [`OwnedAnomaly`] carries its typed
[`DetectorKind`] (0.21, #133) — so `kind.attack_technique()`
gives the MITRE ATT&CK technique ID and `EveJsonWriter` emits
`anomaly.attack_technique` automatically.

## NDR detectors (0.21, #132)

Four network-detection-and-response detectors built on the
[`correlate`](crate::correlate) streaming primitives, each a
[`Detector`] you can drop into a [`DetectorRegistry`] or drive
standalone via its `observe` method. All take **pre-extracted**
values (an `IpAddr`, a `&str` qname, a byte count), so `detect`
stays independent of the `dns` Cargo feature, and all bound their
state + gate emission behind thresholds and cooldowns (a drain is
alert-shaped, not score-shaped).

| Detector | Feed hook | State | Fires when (defaults) | ATT&CK |
|---|---|---|---|---|
| [`DnsTunnelDetector`] | `on_dns_query` | `TimeBucketedSet<(IpAddr, domain), u64>` — distinct hashed subdomains | ≥ 50 distinct ≥ 50-byte qnames under one registered domain in 300 s | T1071.004 |
| [`NewlyObservedDomainDetector`] | `on_dns_query` | `FirstSeen<String>` (cap 100 k, 7-day TTL) | first sight of a registered domain, after a 600 s warmup | T1568 |
| [`ConnectionFloodDetector`] | `on_flow_start` | `TimeBucketedCounter<IpAddr>` | ≥ 100 new flows per source per 10 s | T1498 |
| [`DataExfilDetector`] | `on_flow_end` | `EwmaVar<IpAddr>` over `bytes_initiator` | flow > mean + 3σ of the source's own baseline, ≥ 10 samples, ≥ 1 MiB floor | T1048 |

Notes and gotchas:

- **Registered-domain rollup** uses a PSL-free last-two-labels
  rule (`a.b.evil.com` → `evil.com`), the same caveat as
  [`detect::risk`](crate::detect::risk) — imperfect for
  `co.uk`-style public suffixes; pre-extract or allowlist when
  it matters.
- **`DataExfilDetector` needs a non-degenerate baseline.** A
  source that sends *exactly* the same byte count every flow has
  zero variance, so no z-score exists and it never alarms
  (`EwmaVar::zscore` returns 0.0 during zero-variance warmup — by
  design, so a cold/flat baseline can't false-positive). Real
  traffic jitters; a perfectly constant baseline is a test
  artifact. The absolute `min_bytes` floor is the backstop.
- **`DataExfilDetector` observes at flow end, not per tick** —
  tick stats are cumulative, so naive per-tick recording would
  double-count a flow's bytes. Delta-tracking is a follow-up.
- **`ConnectionFloodDetector` is rate-shaped (DoS, T1498)**;
  scan-shaped fan-out across many destinations is
  [`PortScanDetector`]'s job (T1046). Both can fire on the same
  aggressive source — that's fine, they answer different
  questions.
- **NOD is a context signal, not a verdict** (`Info` severity) —
  every legitimate first visit is "newly observed". Pair it with
  beaconing / reputation / volume.

## Examples

- `examples/03-detection/c2_beacon_finder.rs` — replay a pcap,
  flag top beacon candidates.
- `examples/03-detection/dga_finder.rs` — replay a pcap,
  score DNS query names, rank suspicious SLDs.
- `examples/03-detection/port_scan_detector.rs` (pre-existing
  in 0.10 cycle) — refactor target if you want a
  `PortScanDetector` migration recipe.
- `examples/03-detection/detector_registry.rs` (0.21, #131) —
  the unified `DetectorRegistry` over a real typed `Driver`:
  register beacon / RITA-beacon / port-scan / DGA once, drive
  them all from one event stream, emit each anomaly (with its
  ATT&CK technique) as EVE.
- `examples/03-detection/dns_tunnel_detector.rs` (0.21, #132) —
  the `DnsTunnelDetector` distinct-subdomain heuristic driven
  through a registry over a DNS pcap, emitting T1071.004 EVE
  anomalies.

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

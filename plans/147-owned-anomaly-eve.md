# Plan 147 — `OwnedAnomaly` + emit-writer + score conversion

> **Absorbs:** wishlist Plan 151 (`OwnedAnomaly`) + wishlist Plan
> 148 (`Detector` trait). The 148 trait dissolves into a
> narrower `DetectorScore` output-side conversion, since the
> three detectors' inputs are genuinely heterogeneous and the
> unified-routing benefit happens through `OwnedAnomaly`, not
> through a feed/verdict split. See umbrella 157 §3.2 for the
> design rationale.

## Summary

Three additions, one cohesive shape:

1. **`flowscope::OwnedAnomaly`** — owned, serialisable, canonical
   detector-output value. SmallVec-backed for the no-alloc
   typical case (≤4 observations, ≤4 metrics).
2. **`DetectorScore` trait** — `name()` + `into_anomaly(ts)`,
   implemented on the three shipped score types
   (`ScanScore<K>`, `BeaconScore<K>`, `DgaScore`). Single output-
   side abstraction; lets consumers route any score through a
   uniform emit path without a heterogeneous input trait.
3. **`EveJsonWriter::write_owned_anomaly`** + 
   **`FlowEventNdjsonWriter::write_owned_anomaly`** — direct
   emission of detector-shaped anomalies through the canonical
   schemas (Suricata EVE JSON, NDJSON).

Together these close: custom detector slugs through EVE (was
wishlist 147), canonical retention type (was 151), and uniform
detector→sink routing (was 148).

## Status

Not started. P0 for 0.13.

## Prerequisites

None.

## Out of scope

- **Replacing `FlowEvent::FlowAnomaly` / `TrackerAnomaly`.** Those
  remain the tracker's typed-kind events. `OwnedAnomaly` is the
  detector-output / retention shape downstream of an emit.
- **Forcing `OwnedAnomaly` use upstream.** Detector frameworks
  can still hand-roll their own retention shapes; this is opt-in.
- **Zeek conn.log integration.** Zeek's conn.log is flow-shape,
  not anomaly-shape. Future PR can emit `notice.log` rows from
  `OwnedAnomaly` if a consumer asks.
- **A heterogeneous-input `Detector` trait.** Wishlist Plan 148's
  `Input<'a>` GAT + feed/verdict shape is dropped. Per-detector
  dispatch is per-detector by necessity. See umbrella §3.2.
- **Typed metric values.** `f64` only. A `MetricValue` sum-type
  would tighten typing but complicate JSON emit. Reconsider if a
  consumer reports precision loss.

## Files

| Action | Path | Purpose |
|---|---|---|
| New | `src/anomaly.rs` | `OwnedAnomaly` struct + builders + `DetectorScore` trait |
| Modify | `src/lib.rs` | `pub use anomaly::{OwnedAnomaly, DetectorScore};` |
| Modify | `src/prelude.rs` | re-exports |
| Modify | `src/detect/patterns/portscan.rs` | `impl DetectorScore for ScanScore<K>` + `into_anomaly` inherent |
| Modify | `src/detect/patterns/beacon.rs` | `impl DetectorScore for BeaconScore<K>` |
| Modify | `src/detect/patterns/dga.rs` | `impl DetectorScore for DgaScore` (takes `Option<&dyn KeyFields>` since DGA is keyless) |
| Modify | `src/emit/eve.rs` | `write_owned_anomaly` + `EveOptions::custom_anomaly_type` |
| Modify | `src/emit/ndjson.rs` | `write_owned_anomaly` |
| New | `tests/owned_anomaly.rs` | Unit + golden-fixture tests |
| New | `benches/owned_anomaly.rs` | Construction + emit benches |
| Modify | `docs/eve-format.md` | New §"Custom anomaly emit via `OwnedAnomaly`" |
| Modify | `docs/recipes.md` | "Emitting detector-shaped anomalies" |

## API

### `OwnedAnomaly`

```rust
// src/anomaly.rs
use std::borrow::Cow;
use std::net::IpAddr;
use smallvec::SmallVec;
use crate::{AnomalyKind, KeyFields, Timestamp};
use crate::event::Severity;

/// Canonical owned anomaly value for detector-shaped emission
/// and retention.
///
/// Backed by `SmallVec<[..; 4]>` for observations and metrics —
/// typical detectors produce 2-5 labels per dimension, well
/// under the inline threshold. Allocates only on overflow.
///
/// Wire-stable from 0.13 forward under `#[non_exhaustive]`.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct OwnedAnomaly {
    /// Detector / classification slug. `&'static str` for
    /// zero-alloc compile-time labels; `Cow` for runtime-built
    /// slugs (rare).
    pub kind: Cow<'static, str>,

    /// Severity tier.
    pub severity: Severity,

    /// Event timestamp.
    pub ts: Timestamp,

    /// 5-tuple-derived top-level fields. Filled by `with_key`
    /// from any `KeyFields` impl; each field independent.
    pub src_ip: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dest_ip: Option<IpAddr>,
    pub dest_port: Option<u16>,
    pub proto: Option<&'static str>,

    /// Free-form `(label, value)` observations. Labels are
    /// `&'static str` (compile-time constants); values can be
    /// runtime-built.
    pub observations: SmallVec<[(&'static str, Cow<'static, str>); 4]>,

    /// `(label, value)` numeric metrics. f64 covers integers,
    /// rates, ratios, durations-in-seconds uniformly.
    pub metrics: SmallVec<[(&'static str, f64); 4]>,

    /// Set when this anomaly bridges a flowscope-internal typed
    /// event into the owned shape (via `from_flow_anomaly`).
    /// Retained for typed-bridge consumers.
    pub flowscope_kind: Option<AnomalyKind>,
}

impl OwnedAnomaly {
    /// Construct with slug, severity, and timestamp. All other
    /// fields default to empty.
    pub fn new(
        kind: impl Into<Cow<'static, str>>,
        severity: Severity,
        ts: Timestamp,
    ) -> Self { … }

    /// Attach a key, flattening 5-tuple accessors. Each
    /// field independently `None` if the key returns `None`.
    pub fn with_key<K: KeyFields + ?Sized>(mut self, key: &K) -> Self { … }

    /// Append a `(label, value)` observation. Label is a
    /// `&'static str`; value can be a `&'static str` literal
    /// or a runtime `String` via `into()`.
    pub fn with_observation(
        mut self,
        label: &'static str,
        value: impl Into<Cow<'static, str>>,
    ) -> Self { … }

    /// Append a `(label, value)` numeric metric.
    pub fn with_metric(mut self, label: &'static str, value: f64) -> Self { … }

    /// Bridge a flowscope-internal `FlowAnomaly`/`TrackerAnomaly`
    /// event into the owned shape. Retains the typed
    /// `AnomalyKind` in `flowscope_kind` for downstream typed-
    /// bridge consumers.
    pub fn from_flow_anomaly<K: KeyFields>(
        key: &K,
        kind: AnomalyKind,
        ts: Timestamp,
    ) -> Self { … }
}
```

### `DetectorScore` trait

```rust
/// Conversion to canonical owned-anomaly form for detector
/// scores.
///
/// Each shipped detector's score type implements this:
/// - `ScanScore<K>`   → `"PortScanTRW"`
/// - `BeaconScore<K>` → `"BeaconCv"`
/// - `DgaScore`       → `"DgaScorer"`
///
/// Custom detectors implement on their own score types. The
/// trait gives consumers a uniform "score → anomaly → sink"
/// emit path without unifying the heterogeneous detector input
/// surface.
pub trait DetectorScore {
    /// Stable detector name. Used as `OwnedAnomaly::kind`
    /// (mapped to EVE `anomaly.event` slug; serves as a metric
    /// label).
    fn name(&self) -> &'static str;

    /// Convert into the canonical owned anomaly with the given
    /// timestamp.
    fn into_anomaly(self, ts: Timestamp) -> OwnedAnomaly;
}
```

### Per-score impls + inherent methods

```rust
// src/detect/patterns/portscan.rs (extension)
impl<K: KeyFields + Clone> ScanScore<K> {
    /// Convert into an `OwnedAnomaly`. Severity derives from
    /// `verdict`; `log_likelihood` and `n_observed` become
    /// metrics; the verdict slug becomes an observation.
    pub fn into_anomaly(self, ts: Timestamp) -> OwnedAnomaly {
        let severity = match self.verdict {
            ScanVerdict::Scanner => Severity::Warning,
            ScanVerdict::Benign | ScanVerdict::Inconclusive => Severity::Info,
        };
        OwnedAnomaly::new("PortScanTRW", severity, ts)
            .with_key(&self.key)
            .with_observation("verdict", scan_verdict_slug(self.verdict))
            .with_metric("log_likelihood", self.log_likelihood)
            .with_metric("n_observed", self.n_observed as f64)
    }
}

impl<K: KeyFields + Clone> DetectorScore for ScanScore<K> {
    fn name(&self) -> &'static str { "PortScanTRW" }
    fn into_anomaly(self, ts: Timestamp) -> OwnedAnomaly { self.into_anomaly(ts) }
}

// Analogous for BeaconScore<K> and DgaScore.
// DgaScore is keyless — its `into_anomaly` takes
// `Option<&dyn KeyFields>` for the caller's flow context:
impl DgaScore {
    pub fn into_anomaly(
        self,
        ts: Timestamp,
        flow_key: Option<&dyn KeyFields>,
    ) -> OwnedAnomaly { … }
}

// DetectorScore for DgaScore can't fit the (ts) signature
// alone without a flow key. Two options:
//   (a) DgaScore's DetectorScore::into_anomaly produces a
//       keyless anomaly (no src_ip/dest_ip fields).
//   (b) Don't impl DetectorScore for DgaScore — consumers call
//       the inherent `into_anomaly(ts, Some(&key))` explicitly.
// Decision: (a). Consumers wanting the key fields call the
// inherent method. The DetectorScore impl produces a keyless
// anomaly with the SLD as an observation.
impl DetectorScore for DgaScore {
    fn name(&self) -> &'static str { "DgaScorer" }
    fn into_anomaly(self, ts: Timestamp) -> OwnedAnomaly {
        self.into_anomaly(ts, None)
    }
}
```

### EVE / NDJSON writer methods

```rust
// src/emit/eve.rs (extension)
#[non_exhaustive]
pub struct EveOptions {
    // … existing fields …

    /// EVE `anomaly.type` field value for `OwnedAnomaly`-shaped
    /// emissions. Default `"applayer"`; Suricata-compatible
    /// values are `"stream"`, `"applayer"`, `"decode"`.
    /// Schema-permissive: downstream tooling tolerates new
    /// values.
    pub custom_anomaly_type: &'static str,
}

impl<W: Write> EveJsonWriter<W> {
    /// Emit `event_type: "anomaly"` from an `OwnedAnomaly`.
    ///
    /// Schema mapping:
    /// - `kind` → `anomaly.event`
    /// - `severity` → `severity` (via `EveOptions::severity_numeric`)
    /// - `(src_ip, src_port, dest_ip, dest_port, proto)` →
    ///   top-level fields (each omitted if `None`)
    /// - `observations` → `anomaly.labels.<label>: <value>`
    /// - `metrics` → `anomaly.metrics.<label>: <number>`
    /// - `anomaly.type` ← `EveOptions::custom_anomaly_type`
    ///   UNLESS `flowscope_kind.is_some()`, in which case the
    ///   typed `AnomalyKind::anomaly_type()` overrides (for
    ///   bridged events).
    pub fn write_owned_anomaly(&mut self, a: &OwnedAnomaly) -> io::Result<()>;
}

impl<W: Write> FlowEventNdjsonWriter<W> {
    /// NDJSON shape, one line:
    /// `{kind, severity, timestamp, src_ip?, src_port?, …,
    ///   observations: {…}, metrics: {…}, flowscope_kind?}`
    pub fn write_owned_anomaly(&mut self, a: &OwnedAnomaly) -> io::Result<()>;
}
```

### Idiomatic consumer flow

End-to-end shape that consumers will write:

```rust
let mut port_scan = PortScanDetector::<FiveTupleKey>::new();
let score = port_scan.observe(key, success);
eve.write_owned_anomaly(&score.into_anomaly(ts))?;

// Generic-over-detector routing through DetectorScore:
fn emit<S: DetectorScore>(eve: &mut EveJsonWriter<W>, s: S, ts: Timestamp) -> io::Result<()> {
    eve.write_owned_anomaly(&s.into_anomaly(ts))
}
emit(&mut eve, score, ts)?;
```

netring's `detector!` macro becomes per-detector (which is honest
— the per-detector feed logic differs anyway) but the emit half
is uniform via `DetectorScore`.

## Implementation steps

1. Create `src/anomaly.rs` with `OwnedAnomaly` + the four builder
   methods + `from_flow_anomaly`.
2. Define `DetectorScore` trait in the same module.
3. Wire `lib.rs` + `prelude.rs` re-exports.
4. Add `EveOptions::custom_anomaly_type` field (default
   `"applayer"`).
5. Refactor `src/emit/eve.rs::write_anomaly` so JSON-object
   construction lives in a private helper:
   `build_anomaly_obj(kind: &str, anomaly_type: &str, severity,
   ts, key_fields, observations, metrics) -> serde_json::Map`.
   Both `write_anomaly` (existing typed-kind path) and
   `write_owned_anomaly` call it.
6. Implement `write_owned_anomaly` on `EveJsonWriter` +
   `FlowEventNdjsonWriter`.
7. Add per-score `into_anomaly` inherent + `DetectorScore` impls:
   - `ScanScore<K>` (Plan 147 §portscan)
   - `BeaconScore<K>` (Plan 147 §beacon)
   - `DgaScore` (Plan 147 §dga; keyless via DetectorScore;
     keyed via inherent method)
8. Add `serde` feature gating on derives.
9. Tests + benches + docs.

## Tests

### `OwnedAnomaly` core
- `owned_anomaly_new_default_fields_are_empty`
- `owned_anomaly_with_key_flattens_5tuple`
- `owned_anomaly_with_key_none_when_key_returns_none`
- `owned_anomaly_observations_smallvec_inline_under_4`
- `owned_anomaly_observations_spill_to_heap_above_4`
- `owned_anomaly_from_flow_anomaly_retains_typed_kind`
- `owned_anomaly_serde_round_trip` (gated on `serde`)

### Score → anomaly
- `scan_score_into_anomaly_carries_5tuple_and_metrics`
- `beacon_score_into_anomaly_carries_window_metrics`
- `dga_score_into_anomaly_inherent_with_key_populates_5tuple`
- `dga_score_into_anomaly_via_detectorscore_no_key`
- `detector_score_trait_returns_stable_slug`

### EVE writer
- `eve_writer_writes_owned_anomaly_default_anomaly_type_is_applayer`
- `eve_writer_writes_owned_anomaly_uses_flowscope_kind_when_bridged`
- `eve_writer_writes_owned_anomaly_observations_nested_under_anomaly_labels`
- `eve_writer_writes_owned_anomaly_metrics_nested_under_anomaly_metrics`
- `eve_writer_options_overrides_custom_anomaly_type`

### NDJSON writer
- `ndjson_writer_writes_owned_anomaly_round_trips_through_serde_json`

### Golden fixture
- `tests/fixtures/owned_anomaly.json` — netring-shaped anomaly
  (kind = `"PortScanTRW"`, severity = `Warning`, FiveTupleKey,
  two observations, two metrics) — schema-validate against the
  shape committed in the fixture.

## Acceptance criteria

- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings` clean.
- Bench `bench_owned_anomaly_construction` shows **0 allocations
  per construction** for ≤4 observations + ≤4 metrics (SmallVec
  inline path).
- Bench `bench_owned_anomaly_emit_eve` shows the EVE write path
  is within 5% of the existing `write_event` path.
- netring 0.21 imports `OwnedAnomaly` + `DetectorScore` from
  flowscope; removes its own `OwnedAnomaly` definition.
- netring 0.21 `EveSink` adapter becomes a 3-line wrapper over
  `EveJsonWriter::write_owned_anomaly` — no schema knowledge in
  netring.
- With `serde` feature, `OwnedAnomaly` round-trips through
  `serde_json` byte-exactly.

## Risks

**R1: Wire-stability pre-1.0.** Users will store these in
databases. Mitigation: `#[non_exhaustive]` keeps field additions
non-breaking; `#[cfg_attr(feature = "serde", derive(...))]` makes
the JSON schema explicit. Document as "wire-stable from 0.13" in
CHANGELOG.

**R2: SmallVec inline-threshold tuning.** Default `[..; 4]` based
on existing detector outputs. If a downstream detector regularly
exceeds, set inline higher OR accept heap-allocation cost.
Mitigation: documented; benched.

**R3: DgaScore's keyless DetectorScore impl loses 5-tuple
context.** Trade-off: uniform trait surface vs key-aware
emission. Mitigation: shipped inherent `into_anomaly(ts,
key: Option<&dyn KeyFields>)` for consumers wanting the key
fields; the trait impl is the keyless convenience.

**R4: Two emit paths confuse consumers** (`write_event` for
`FlowEvent`, `write_owned_anomaly` for `OwnedAnomaly`).
Mitigation: docs/recipes.md decision tree: flowscope-internal
anomalies → `FlowEvent` path; detector outputs → `OwnedAnomaly`
path; bridge between them via `OwnedAnomaly::from_flow_anomaly`.

## Effort

- LOC delta: +500 (OwnedAnomaly + DetectorScore + 3 score impls
  + writer methods + tests + benches + docs).
- Time estimate: **2 days**.

## Provenance

Combined from wishlist plans 147, 148, 151. Counter-proposals
(merge 147+151 collapsed surface; narrow 148 to output-side
trait) discussed in umbrella 157 §3.1–§3.2.

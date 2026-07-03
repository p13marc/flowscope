# Migrating from 0.20 to 0.21

The 0.21 cycle is the **detection-architecture** pass (roadmap
#140): typed detector identity, the unified `Detector` trait +
registry, four new NDR detectors, new `correlate` streaming
primitives, the pDNS `NameMap`, and the final tap-merge phase.

Breaking changes are compile-time-focused; **every emitted wire
byte (EVE / NDJSON slugs) is unchanged** unless called out below.

## Breaking change — `OwnedAnomaly::kind` is now `DetectorKind` (#133)

Detector identity graduated from a string slug
(`Cow<'static, str>`) to the typed
[`flowscope::DetectorKind`] enum, following the `ParserKind`
precedent from 0.20 (#109).

**Your EVE / NDJSON pipelines need no changes** — every built-in
variant serializes to the exact slug string 0.20 emitted
(`"BeaconCv"`, `"BeaconRita"`, `"PortScanTRW"`, `"DgaScorer"`),
and `serde` round-trips it as a plain JSON string.

Compile-time migration:

```diff
- let a = OwnedAnomaly::new("BeaconCv", Severity::Warning, ts);
+ let a = OwnedAnomaly::new(DetectorKind::BeaconCv, Severity::Warning, ts);

- let a = OwnedAnomaly::new("my-detector", Severity::Info, ts);
+ let a = OwnedAnomaly::new(DetectorKind::Other("my-detector"), Severity::Info, ts);
```

`DetectorScore::name()` became `kind()`:

```diff
  impl DetectorScore for MyScore {
-     fn name(&self) -> &'static str { "my-detector" }
+     fn kind(&self) -> DetectorKind { DetectorKind::Other("my-detector") }
      fn into_anomaly(self, ts: Timestamp) -> OwnedAnomaly { … }
  }
```

Need the old string? `kind().as_str()` returns it.

Notes and edge cases:

- **Runtime-built slugs are no longer supported** —
  `DetectorKind::Other` needs a `&'static str`. Detector identity
  is a compile-time constant (the same trade `ParserKind` made);
  put dynamic context in `observations`, not the kind.
- **Deserialization** of an unrecognized slug yields
  `DetectorKind::Unknown` (an `Other` can't be rebuilt from a
  runtime string). Built-in slugs round-trip to their variant.
- `OwnedAnomaly::from_flow_anomaly` now sets
  `kind = DetectorKind::Other(anomaly_kind.short_kind())` — the
  emitted string (`"ooo_segment"`, …) is unchanged; the typed
  tracker-anomaly axis stays in `flowscope_kind` exactly as
  before.

**Delete your slug → ATT&CK table.** `DetectorKind` carries the
MITRE ATT&CK technique mapping in-crate:

```rust
use flowscope::DetectorKind;

assert_eq!(DetectorKind::PortScanTrw.attack_technique(), Some("T1046"));
assert_eq!(DetectorKind::BeaconCv.attack_technique(),    Some("T1071"));
assert_eq!(DetectorKind::Dga.attack_technique(),         Some("T1568.002"));
```

**Additive EVE field.** `EveJsonWriter::write_owned_anomaly` now
emits `anomaly.attack_technique` when the kind has a mapping —
schema-permissive; omitted for `Other(…)` / `Unknown`. See
[`eve-format.md`](eve-format.md).

## Breaking change — per-packet capture leg on `Packet` events (#121)

`FlowEvent::Packet` and `driver::Event::Packet` gain an **opt-in**
`source_idx: Option<u32>` field carrying the physical capture leg
([`RxMetadata::source_idx`]) of each packet — the final phase of the
tap-merge epic (#123). Both variants are now also marked
**variant-level `#[non_exhaustive]`**, so future per-packet
enrichments will be additive (this is the last break of this shape).

**Default off, zero hot-path cost.** The field is `None` unless you
set `FlowTrackerConfig::emit_packet_source_idx = true` (or
`DriverBuilder::emit_packet_source_idx(true)` on the typed driver).
The `0` "unused" sentinel is never surfaced. For merged-tap
consumers the per-direction `FlowStats::source_idx_forward` /
`source_idx_reverse` binding (#120) remains the mainstream answer;
this field is the audit / forensic tier ("did this exact packet
arrive on the wrong leg?").

Migration:

- **Matching**: exhaustive `Packet { … }` patterns need a trailing
  `..` (most code already has one). Field-by-field destructuring
  without `..` no longer compiles.
- **Constructing**: struct-expression construction of the `Packet`
  variants outside flowscope no longer compiles (non-exhaustive
  variant). Use the synthetic-event constructors —
  `flowscope::test_helpers::events::{packet, packet_side}` and
  `events::driver::{flow_packet, flow_packet_full}` — which is the
  documented path since 0.20.
- **Serde**: the new field is additive JSON (`"source_idx": null` /
  a number). `FlowEvent` deserialization accepts documents without
  the field (`serde(default)`).

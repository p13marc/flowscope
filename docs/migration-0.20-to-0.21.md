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

*(lands with the #121 PR; section placeholder maintained in that
change)*

# Plan 83 — `serde` Cargo feature on every public type

## Summary

Ship `serde::Serialize` + `serde::Deserialize` opt-in derives on every
public event, message, accessor, and configuration type. The wire
vocabulary — JSON field / variant names — is locked from 0.8.0 forward
under `#[serde(rename_all = "snake_case")]` matching the existing
metric label convention.

This is the load-bearing piece of the 0.8 release. Production
consumers (Vector / Fluentd / Loki / Splunk HEC) need structured event
output and don't want to hand-roll JSON for `HttpMessage` / `DnsMessage`
/ `TlsClientHello` / `IcmpMessage`. `#[non_exhaustive]` enums silently
miss new variants if every downstream serializer doesn't keep up;
shipping derive-based serialization in flowscope locks the format
once.

**Locked wire vocabulary (from 0.8 forward).** Once shipped, JSON
field names + variant tags become a stability surface — dashboards
and downstream consumers will depend on them. Renames require a
CHANGELOG-documented breaking change.

## Status

Not started.

## Prerequisites

- Plan 79 (`Ended` carries `l4`) — shipped in 0.7.0.
- Plan 76 (`icmp` module) — shipped in 0.7.0. ICMP types covered
  in this plan's surface.
- Plan 80 (`is_done` / `ParserDone`) — shipped in 0.7.0.
- Plan 82 (`Severity` enum) — shipped in 0.7.0.
- Plan 87 (`Established { l4 }`) — *lands in this cycle before
  this plan*. Variant-field stable before serde sees it.
- Plan 89 (`EndReason::ParserDone` etc.) — *lands in this cycle
  before this plan*. Enum stable before serde sees it.

## Out of scope

- Custom format adapters (CBOR / MessagePack / Avro). Serde derives
  let consumers pick their format; we ship the derives, not the
  format-specific code.
- Schema versioning / migration tooling. The wire format is the
  schema; bumps are CHANGELOG-documented.
- Serialization of `FlowTracker` / driver internals. Only event /
  message / accessor / config types are covered.
- `bincode` / wire-compactness considerations. Snake-case strings
  are the format; consumers wanting compactness route through
  postcard or similar via the same serde derives.
- A `to_json_string()` convenience method on every type. Consumers
  call `serde_json::to_string` directly; one fewer surface to
  maintain.

## Files

- `Cargo.toml` — new `serde` feature; `serde` / `bytes/serde`
  optional deps; CI matrix entry.
- `src/timestamp.rs` — custom `Serialize` / `Deserialize` for
  `Timestamp` (struct `{ sec: u32, nsec: u32 }`).
- Add `#[cfg_attr(feature = "serde", derive(serde::Serialize,
  serde::Deserialize))]` + enum-tagging attrs on every public
  type in:
  - `src/event.rs` (`FlowEvent`, `FlowStats`, `AnomalyKind`,
    `EndReason`, `FlowSide`, `FlowState`, `OverflowPolicy`,
    `Severity`).
  - `src/extractor.rs` (`L4Proto`, `TcpInfo`, `Orientation`).
  - `src/extract/*` (`FiveTupleKey`, `IpPair`, `MacPair`, …).
  - `src/history.rs` (`HistoryString`).
  - `src/view.rs` (`PacketView` — `Deserialize` only on
    `OwnedPacketView`; `PacketView<'_>` is borrowed and not
    deserialized).
  - `src/session.rs` (`SessionEvent`).
  - `src/http/types.rs` (`HttpRequest`, `HttpResponse`,
    `HttpVersion`, `HttpMessage`, `HttpConfig`).
  - `src/tls/types.rs` (`TlsClientHello`, `TlsServerHello`,
    `TlsAlert`, `TlsAlertLevel`, `TlsVersion`).
  - `src/tls/session.rs` (`TlsHandshake` if public).
  - `src/dns/types.rs` (`DnsQuery`, `DnsResponse`, `DnsRdata`,
    `DnsClass`, `DnsRcode`, `DnsOpcode`, `DnsConfig`,
    `DnsMessage`).
  - `src/icmp/types.rs` (`IcmpMessage`, `IcmpType`, `Icmpv4Type`,
    `Icmpv6Type`, every code enum, `IcmpInner`, `IcmpFamily`).
- `tests/serde_round_trip.rs` — golden-file round-trip tests for
  every top-level event / message type.
- `tests/fixtures/serde/` — golden JSON files (small, hand-written,
  pretty-printed for diffability).
- `.github/workflows/rust.yml` — feature-matrix entries: `"serde"`
  and `"serde,l7,pcap"`.
- `docs/OBSERVABILITY.md` — new top-level section "Structured
  output via serde" with the canonical Vector/Fluentd integration
  pattern.
- `CHANGELOG.md` — `### Added` entry explicitly documenting the
  stability commitment.

## API

```toml
# Cargo.toml
[features]
serde = ["dep:serde", "bytes?/serde"]

[dependencies]
serde = { version = "1", features = ["derive"], optional = true }
```

Every public type gains:

```rust
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
```

Every public enum gains tagging:

```rust
#[cfg_attr(feature = "serde", serde(tag = "type", rename_all = "snake_case"))]
```

Producing JSON like:

```json
{
  "type": "started",
  "key": { ... },
  "ts": { "sec": 1717610000, "nsec": 123456789 },
  "l4": "tcp"
}
```

`L4Proto::Other(u8)` serializes as `{"type": "other", "value": 6}`.

`Timestamp` ships a manual impl emitting `{sec, nsec}`:

```rust
// src/timestamp.rs
#[cfg(feature = "serde")]
impl serde::Serialize for Timestamp {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("Timestamp", 2)?;
        st.serialize_field("sec", &self.sec())?;
        st.serialize_field("nsec", &self.nsec())?;
        st.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Timestamp {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        struct Raw { sec: u32, nsec: u32 }
        let r = Raw::deserialize(d)?;
        Ok(Timestamp::new(r.sec, r.nsec))
    }
}
```

## Wire format reference

Locked from 0.8 forward.

### Field naming

`snake_case` via `#[serde(rename_all = "snake_case")]`.

### Enum tagging

`#[serde(tag = "type")]` — internally tagged. Variant tags are
snake_case via the same `rename_all`.

### Special types

- `Timestamp` → `{sec: u32, nsec: u32}`.
- `bytes::Bytes` → JSON array of bytes (via `bytes/serde` feature) or
  base64 — **defaulting to byte array** for round-trip fidelity. If
  consumers want compact base64 output they wrap downstream.
- `HistoryString` → string (Display-equivalent — Zeek-style chars).
- `Ipv4Addr` / `Ipv6Addr` / `IpAddr` → standard serde-`ip`-feature
  formats: `"10.0.0.1"` / `"::1"` strings.
- `Duration` → struct `{secs: u64, nanos: u32}` (serde default).

### Top-level event examples

`FlowEvent::Started`:
```json
{
  "type": "started",
  "key": {"proto": "tcp", "a": {"ip": "10.0.0.1", "port": 12345}, "b": {"ip": "10.0.0.2", "port": 80}},
  "side": "initiator",
  "ts": {"sec": 1717610000, "nsec": 0},
  "l4": "tcp"
}
```

`SessionEvent::Application` (HTTP):
```json
{
  "type": "application",
  "key": {...},
  "side": "initiator",
  "message": {
    "type": "request",
    "method": "GET",
    "path": "/",
    "version": "http1_1",
    "headers": [["host", [101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109]]],
    "body": []
  },
  "ts": {"sec": 1717610000, "nsec": 1000000},
  "parser_kind": "http/1"
}
```

`AnomalyKind::ReassemblerHighWatermark`:
```json
{
  "type": "reassembler_high_watermark",
  "side": "initiator",
  "bytes": 800,
  "cap": 1000,
  "threshold_pct": 80
}
```

### Forward-compatibility

Adding new variants to `#[non_exhaustive]` enums is a Serialize-only
change: existing decoders that match on `type` will receive an
unknown tag and serde returns an error per default behaviour.
Documented as the expected upgrade story. Long-term we may add
`#[serde(other)]` fallback variants on specific enums where graceful
degradation is critical (out of scope for this plan).

## Implementation steps

1. **Cargo feature wiring**: add `serde` feature in `Cargo.toml`;
   add `serde = { version = "1", features = ["derive"], optional = true }`.
   For the `bytes` dep, switch the existing line to
   `bytes = { version = "1", features = ["serde"], optional = true }`
   *only when `serde` feature is on* — actually use
   `bytes/serde` via the feature graph: `serde = ["dep:serde",
   "bytes?/serde"]`.
2. **Custom `Timestamp` impl**: per the API section. Test via
   round-trip in `tests/serde_round_trip.rs`.
3. **`#[cfg_attr]` derive sweep**: walk every file listed in
   "Files" and add the attribute pair. Group by file; commit
   sequentially to keep blast radius per commit small. For enums,
   add the `#[serde(tag = "type")]` attribute on the enum itself.
4. **Bytes-array vs base64**: keep `bytes::Bytes` rendering as
   array of bytes (the `bytes/serde` default). Document the
   "wrap in base64 yourself" recipe for log-pipeline consumers.
5. **Per-feature gates**: derives gated on `feature = "serde"` only,
   but the parser-module types are also gated on their parser
   feature (`http` / `tls` / `dns` / `icmp`). Compound cfg uses the
   `cfg_attr(all(feature = "serde", feature = "http"), …)` form
   where the type's enclosing module is already feature-gated.
6. **Golden-file tests**: `tests/serde_round_trip.rs` covers:
   - Every top-level event variant (`FlowEvent::*`).
   - Every `SessionEvent::*` variant.
   - Every L7 message top-level (`HttpMessage`, `DnsMessage`,
     `TlsClientHello`, `IcmpMessage`).
   - `AnomalyKind` exhaustive.
   - `EndReason` exhaustive.
   - `Severity` exhaustive.
   - `Timestamp` extreme values (0, max).

   Each test serializes to JSON, compares against a golden file
   (with `expect-test`-style auto-update via `INSERT_FILE_CONTENTS`
   env-var), then deserializes back and asserts structural equality.
7. **CI matrix**: add `"serde"` and `"serde,l7,pcap"` to
   `.github/workflows/rust.yml`. The latter exercises every L7
   parser's serde impl in one build.
8. **OBSERVABILITY.md section**: "Structured output via serde" —
   integration patterns for Vector / Fluentd / Loki / Splunk HEC.
   Note the stability commitment.
9. **CHANGELOG entry**: prominent under `### Added` with a
   "STABILITY: locked wire vocabulary" callout.

## Tests

`tests/serde_round_trip.rs` (~30 tests):

- **Round-trip every top-level type**: serialize, deserialize,
  assert equality (via `Debug`-string compare, then
  `assert_eq!` on field-by-field where derivable).
- **Golden-file stability**: each top-level type has a `*.golden.json`
  fixture under `tests/fixtures/serde/`. Comparing serialized output
  byte-for-byte locks the wire format.
- **`#[non_exhaustive]` decoder behaviour**: feed a `{"type":
  "future_variant"}` to a current enum; assert deserialize fails
  cleanly (not silently produces a default).
- **L7 message edge cases**: empty body, multi-value header,
  multi-question DNS, ICMPv6 NS/NA.

Golden files chosen for diffability — pretty-printed, alphabetised
where possible (objects), comment-friendly via filename.

## Acceptance criteria

- `cargo test --all-features --test serde_round_trip` clean
  (~30 round-trip tests).
- Golden files under `tests/fixtures/serde/` lock the wire vocabulary;
  any future PR that changes serialization output fails the test.
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean (including the new serde cfg-attrs).
- Feature-matrix CI green with new `"serde"` and
  `"serde,l7,pcap"` entries.
- `cargo doc --all-features --no-deps` clean.
- `cargo publish --dry-run --all-features` packages successfully.
- `docs/OBSERVABILITY.md` "Structured output via serde" section
  documents the canonical Vector / Fluentd ingestion pattern.
- CHANGELOG explicitly calls out the stability commitment.

## Risks

- **Long-term stability lock-in.** Once shipped, dashboards depend on
  field names. Renames require breaking changes. Mitigation:
  golden-file tests catch accidental drift; the rename policy is
  documented in OBSERVABILITY.md.
- **`#[non_exhaustive]` enum + serde tagging interactions.** Variant
  additions are serialize-additive but deserialize-breaking for any
  consumer running a version older than the producer. Documented;
  consumers stay version-aligned via the lockstep policy.
- **`bytes::Bytes` payload size in logs.** JSON-array-of-bytes for
  HTTP / DNS bodies blows log line size. Documented; consumers
  who want compact output route through a base64 wrapper or trim
  bodies before serialization.
- **`Timestamp` custom impl maintenance.** Custom impls don't auto-
  evolve; if `Timestamp` gains fields (e.g. a timezone tag), the
  impl needs hand-updating. Caught by round-trip tests.
- **Serde-version coupling.** flowscope locks to serde 1.x. Serde 2
  would force a breaking change; that's out of scope until 2.x
  arrives (no current signal it will).

## Effort

~30 type-files touched (mostly one `#[cfg_attr]` pair per type) +
~150 LoC custom `Timestamp` impl + tests + ~500 LoC test
infrastructure + golden files. **3–4 days realistic** including
CI matrix + OBSERVABILITY documentation + double-checking every
variant's serialization. The biggest investment is golden-file
correctness — every variant must be deliberate.

## Provenance

Round-3 wishlist item A1 in
[`docs/feedback-2026-06-06-netring-wishlist.md`](../docs/feedback-2026-06-06-netring-wishlist.md).
Author's top-1 ask; unblocks production pipelines. Plan-of-record
§5 documents the locked-vocabulary commitment. Snake_case and
`{sec, nsec}` Timestamp shape match the existing metric label
convention and Unix-time encoding tradition.

# Plan 123 — `flowscope::emit::eve` — Suricata EVE JSON writer

## Summary

Add `EveJsonWriter<W>` to `flowscope::emit`, the fourth in the
[`csv.rs`, `ndjson.rs`, `zeek.rs`] series. Emits one JSON line
per event in [Suricata EVE
format](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html),
schema-compatible with Filebeat's Suricata module, Splunk's
Suricata TA, Tenzir's `read_suricata`, and Elastic Common
Schema downstream pipelines.

Behind `emit-eve` feature (parallel to existing `emit` /
`emit-ndjson` gating).

## Status

Not started.

## Prerequisites

- **Plan 126** (`AnomalyFields` trait) — for clean 5-tuple +
  classification field extraction. Lands first.
- **Plan 127** (`Timestamp::write_iso8601`) — for the
  `timestamp` and `flow.start` / `flow.end` ISO-8601 fields.
  Lands first.

## Out of scope

- **Suricata rule alerts.** EVE's `event_type: "alert"`
  carries Suricata SID/GID/rev rule metadata that flowscope
  doesn't have. We emit `event_type: "anomaly"` (for
  `AnomalyKind` events) and `event_type: "flow"` (for
  `FlowEnded`) only. `event_type: "stats"` (for `FlowTick`)
  is gated on an opt-in `include_stats: bool` (default off —
  high cardinality).
- **Per-message event types.** No `eve_http` / `eve_dns` /
  `eve_tls`. The 0.12 ships lifecycle + anomaly emit only;
  add per-protocol EVE event_types in a future cycle if a
  consumer asks.
- **HTTP Event Collector / Kafka / Loki push.** Output is
  `impl Write` only — `BufWriter<File>` is the standard path.
- **`preserve_order` field ordering**. Suricata's EVE output
  doesn't guarantee field ordering either; we use serde_json's
  default. Add `preserve_order` only if a real consumer demands.

## Files

| Action | Path | Purpose |
|---|---|---|
| New | `src/emit/eve.rs` | `EveJsonWriter`, `EveOptions`, EVE schema renderer |
| Modify | `src/emit/mod.rs` | `mod eve;` + re-export behind `emit-eve` feature |
| Modify | `Cargo.toml` | `emit-eve = ["emit", "serde", "dep:serde_json"]` |
| New | `tests/emit_eve.rs` | Schema fixtures vs golden JSON; severity mapping |
| New | `docs/eve-format.md` | Mapping table from flowscope events to EVE fields |
| New | `examples/05-export/eve_writer.rs` | End-to-end pcap → eve.json |

## API

```rust
// src/emit/eve.rs
use std::io::{self, Write};

use crate::AnomalyFields;
use crate::Timestamp;
use crate::event::{AnomalyKind, EndReason, FlowEvent, Severity};

/// Suricata EVE JSON writer. Emits one JSON object per line.
///
/// Schema-compatible with Suricata 7.x EVE format
/// (anomaly + flow event_types) — pipes directly into
/// Filebeat's Suricata module, Splunk Suricata TA, Tenzir's
/// `read_suricata`, etc.
///
/// One `serde_json::Map` scratch buffer reused across calls;
/// per-event allocations are limited to the rendered JSON
/// (which `serde_json::to_writer` writes directly into the
/// sink).
pub struct EveJsonWriter<W>
where
    W: Write,
{
    sink: W,
    options: EveOptions,
    flow_id_counter: u64,
    scratch: serde_json::Map<String, serde_json::Value>,
    ts_buf: String, // reused for ISO-8601 rendering
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct EveOptions {
    /// Interface name embedded as `in_iface`. Default `""` —
    /// the field is omitted when empty.
    pub in_iface: String,
    /// Include `event_type: "flow"` records for `FlowEnded`
    /// (default `true`).
    pub include_flow: bool,
    /// Include `event_type: "anomaly"` for `FlowAnomaly` +
    /// `TrackerAnomaly` (default `true`).
    pub include_anomalies: bool,
    /// Include `event_type: "stats"` for `FlowTick`. Default
    /// `false` — high cardinality; opt in for verbose pipelines.
    pub include_stats: bool,
    /// Map flowscope's `Severity` to the EVE `severity` field
    /// (numeric 1–4, lower = more severe). Default: identity
    /// mapping — `Severity::Critical=1, Error=2, Warning=3, Info=4`.
    /// Matches Suricata's convention (1=high, 4=low) and
    /// flowscope's `Severity` enum's discriminant order.
    pub severity_numeric: fn(Severity) -> u8,
}

impl Default for EveOptions {
    fn default() -> Self {
        Self {
            in_iface: String::new(),
            include_flow: true,
            include_anomalies: true,
            include_stats: false,
            severity_numeric: default_severity_numeric,
        }
    }
}

fn default_severity_numeric(s: Severity) -> u8 {
    match s {
        Severity::Critical => 1,
        Severity::Error    => 2,
        Severity::Warning  => 3,
        Severity::Info     => 4,
    }
}

impl<W> EveJsonWriter<W>
where
    W: Write,
{
    pub fn new(sink: W, options: EveOptions) -> Self { /* … */ }

    /// Emit one event. Returns `Ok(())` on every event (write
    /// errors propagate as `io::Error`); skipped variants per
    /// the options produce no output.
    pub fn write_event<K: AnomalyFields>(
        &mut self,
        ev: &FlowEvent<K>,
    ) -> io::Result<()> { /* … */ }

    pub fn flush(&mut self) -> io::Result<()> { self.sink.flush() }
}
```

### EVE schemas produced

`event_type: "anomaly"` (per-flow):

```json
{
  "timestamp": "2026-06-10T12:34:56.789012345Z",
  "flow_id": 17,
  "flow_hash": "9f3c0bb2…",
  "in_iface": "eth0",
  "event_type": "anomaly",
  "src_ip": "10.0.0.1", "src_port": 12345,
  "dest_ip": "10.0.0.2", "dest_port": 80,
  "proto": "TCP",
  "anomaly": {
    "type": "stream",
    "event": "ooo_segment",
    "code": 0
  },
  "severity": 3
}
```

`event_type: "flow"` (per-flow on `FlowEnded`):

```json
{
  "timestamp": "2026-06-10T12:34:56.789012345Z",
  "flow_id": 17,
  "event_type": "flow",
  "src_ip": "10.0.0.1", "src_port": 12345,
  "dest_ip": "10.0.0.2", "dest_port": 80,
  "proto": "TCP",
  "flow": {
    "pkts_toserver": 7,
    "pkts_toclient": 5,
    "bytes_toserver": 2400,
    "bytes_toclient": 14000,
    "start": "2026-06-10T12:34:50.000000000Z",
    "end":   "2026-06-10T12:34:56.789012345Z",
    "age": 6,
    "state": "established",
    "reason": "fin",
    "alerted": false
  }
}
```

### Field mapping

| flowscope | EVE | Source |
|---|---|---|
| `FlowEvent::Started.ts` etc. | `timestamp` | plan 127 `write_iso8601` |
| `key` (via `AnomalyFields`) | `src_ip`, `src_port`, `dest_ip`, `dest_port` | plan 126 |
| `key.proto_str()` | `proto` | plan 126 |
| `AnomalyKind` | `anomaly.type` + `anomaly.event` | plan 126 |
| `AnomalyKind::severity()` | `severity` | existing `event.rs::Severity` |
| `FlowEnded.reason` | `flow.reason` (string slug) | `EndReason::as_str()` |
| `FlowStats` | `flow.pkts_toserver`, `flow.bytes_toclient`, etc. | existing `FlowStats` |
| flow_id (monotonic) | `flow_id` | counter on `EveJsonWriter` |
| 5-tuple hash | `flow_hash` (hex `u64`) | deterministic FNV |

`EndReason` → `flow.reason` slug mapping (matches Suricata):
- `Fin` → `"fin"`
- `Rst` → `"rst"`
- `IdleTimeout` → `"timeout"`
- `Evicted` → `"eviction"`
- `BufferOverflow` → `"buffer_overflow"`
- `ParseError` → `"parse_error"`
- `ParserDone` → `"parser_done"`
- `ForceClosed` → `"force_closed"`

## Implementation steps

1. **Cargo.toml**: add `emit-eve` feature pulling
   `serde` + `serde_json`.
2. **`src/emit/eve.rs`**: `EveJsonWriter` skeleton + options +
   `default_severity_numeric` fn pointer.
3. **`write_event` dispatch**: match on `FlowEvent<K>` variant
   → call one of `write_anomaly`, `write_flow_ended`,
   `write_stats` based on `EveOptions`.
4. **`write_anomaly`**:
   - Clear `self.scratch`.
   - Insert `"timestamp"` via `self.ts_buf` + `ts.write_iso8601`.
   - Insert `flow_id` (monotonic counter), `flow_hash` (FNV
     hash of `(proto, sorted_a, sorted_b)`).
   - Insert 5-tuple fields from `key.src_ip()`, `key.src_port()`,
     etc. — skip when `None`.
   - Insert `"proto"` from `key.proto_str()`.
   - Insert `"anomaly"` sub-object: `{"type": kind.anomaly_type(),
     "event": kind.anomaly_event(), "code": 0}`.
   - Insert `"severity"` from `(opts.severity_numeric)(kind.severity())`.
   - `serde_json::to_writer(&mut self.sink, &self.scratch)?;`
   - `self.sink.write_all(b"\n")?;`
5. **`write_flow_ended`**: similar structure; the `"flow"`
   sub-object carries `FlowStats` fields.
6. **`flow_hash`**: 64-bit FNV-1a over
   `(proto, min(a,b), max(a,b))`. Deterministic across runs;
   two flowscope instances on the same pcap produce the same
   `flow_hash`. Document the algorithm in `docs/eve-format.md`.
7. **Tests + golden fixtures**.
8. **`docs/eve-format.md`**: field-by-field mapping table.
9. **Example** (`examples/05-export/eve_writer.rs`): pcap →
   `eve.json` end-to-end; runnable with
   `cat eve.json | jq 'select(.event_type=="anomaly")'`.
10. **CI matrix**: add `emit-eve` to the matrix.

## Tests

In `tests/emit_eve.rs`:

- `eve_anomaly_buffer_overflow_matches_golden_fixture`
- `eve_anomaly_session_parse_error_matches_golden_fixture`
- `eve_flow_event_includes_expected_pkts_bytes`
- `eve_severity_numeric_default_critical_is_1_info_is_4`
- `eve_severity_numeric_override_can_invert`
- `eve_flow_id_monotonically_increases_within_writer`
- `eve_flow_hash_deterministic_for_same_5tuple` — twice the
  same input produces the same hex.
- `eve_disabled_event_types_produce_no_output` — opts off
  → no lines written.
- `eve_each_line_is_valid_json` — every line
  `serde_json::from_str::<Value>` parses back.
- `eve_no_trailing_comma_after_last_field` — regression test
  for the field-emit loop.

## Acceptance criteria

- `cargo build --features emit-eve` clean.
- `cargo test --features emit-eve` clean.
- `cargo clippy --features emit-eve --all-targets -- -D warnings` clean.
- Golden fixtures match a hand-validated reference. If
  Suricata 7.x is available locally, cross-check against
  `suricata --runmode single -r tests/fixtures/sample.pcap`
  for a small overlap of anomaly events (not exhaustive — our
  parsers differ from Suricata's, but the schema shape should
  match).
- `docs/eve-format.md` complete.
- `examples/05-export/eve_writer.rs` builds + runs against the
  shipped `tests/data/mixed_short.pcap`.
- New `emit-eve` CI matrix entry clean.

## Risks

- **R1: `serde_json` Map ordering.** Default hash-map ordering
  may surprise human readers (machines don't care). Mitigation:
  document order isn't guaranteed; opt-in `preserve_order`
  not pursued (would pull a non-default serde_json feature).
- **R2: ECS field-name drift.** Elastic's ECS sometimes
  renames fields version-to-version. We ship v1 fixed to
  Suricata 7.x EVE; users wanting ECS-strict pipe through
  Logstash. Document the schema version explicitly in
  `docs/eve-format.md`.
- **R3: Severity mapping vs flowscope's `Severity` enum
  discriminant.** Suricata's convention is "lower = more
  severe" (1=critical, 4=info). flowscope's `Severity`
  discriminants happen to match. Default mapping is identity;
  document the convention so override authors don't invert it
  accidentally.
- **R4: `flow_hash` collision rate.** 64-bit FNV is fine at
  flowscope scales (1 M flows per pcap, collision prob ~5e-8).
  Document the hash; consumers needing zero-collision can
  override with a stronger algorithm in their own pipeline.

## Effort

| Step | LoC | Hours |
|---|---|---|
| `EveJsonWriter` + options | 80 | 3 |
| `write_anomaly` + tests | 130 | 4 |
| `write_flow_ended` + tests | 100 | 3 |
| `write_stats` (gated) | 60 | 1.5 |
| `flow_hash` + tests | 30 | 1 |
| Cargo.toml + feature gate | 10 | 0.5 |
| `docs/eve-format.md` | 80 | 2 |
| Example | 60 | 2 |
| CHANGELOG + migration | 40 | 1 |
| CI matrix | 10 | 0.5 |
| **Total** | **~600** | **~18.5 hours (~2.5 days)** |

Wishlist's "3 days" estimate is on track.

## Provenance

Triggered by netring 0.21 §3.2 (EveSink). Filebeat's Suricata
module, Splunk Suricata TA, Tenzir's `read_suricata` operator,
and Elastic Common Schema downstream all parse EVE natively
— shipping EVE makes flowscope-produced traffic data
immediately usable for SIEM operators without a translation
step. Offline pcap users benefit too (offline EVE → ingest
later).

The schema work belongs in flowscope (where `AnomalyKind` /
`FlowStats` / `EndReason` are owned), not netring; netring's
`EveSink` becomes a thin `AnomalySink → EveJsonWriter` adapter.

# EVE JSON output (`emit-eve` feature)

`flowscope::emit::EveJsonWriter` produces one JSON object per
line in [Suricata 7.x EVE format](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html).
Schema-compatible with:

- [Filebeat's Suricata module](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-module-suricata.html)
- Splunk Suricata TA
- [Tenzir's `read_suricata`](https://docs.tenzir.com/operators/read-suricata)
- ECS-converting downstream pipelines (Logstash, Vector)

Behind the `emit-eve` Cargo feature. Pulls `serde_json` only.

## Quickstart

```rust,no_run
use flowscope::emit::EveJsonWriter;
use std::fs::File;
use std::io::BufWriter;

let mut eve = EveJsonWriter::new(BufWriter::new(File::create("eve.json")?));
for ev in driver_events {
    eve.write_event(&ev)?;
}
eve.finish()?; // flush + recover the sink
# Ok::<(), Box<dyn std::error::Error>>(())
```

`EveJsonWriter::write_event` accepts any `FlowEvent<K>` whose
`K` implements `flowscope::KeyFields` (5-tuple accessors). The
shipped impls — `FiveTupleKey` and `L4Proto` (`KeyFields`),
`AnomalyKind` (`AnomalyFields`) — cover the canonical case;
custom keys opt in by implementing `KeyFields`. (The
`KeyFields` / `AnomalyFields` split happened in 0.12 plan 130
— pre-split, both kinds of accessors lived on a single
`AnomalyFields` trait.)

## Event types

Three come from the `FlowEvent` stream via `write_event`, each
toggled on `EveOptions`:

| `FlowEvent` variant      | `event_type` | Toggle                | Default |
|--------------------------|--------------|-----------------------|---------|
| `FlowEvent::Ended`       | `"flow"`     | `include_flow`        | on      |
| `FlowEvent::FlowAnomaly` / `TrackerAnomaly` | `"anomaly"` | `include_anomalies` | on      |
| `FlowEvent::Tick`        | `"stats"`    | `include_stats`       | off     |

`FlowEvent::Started` / `Established` / `Packet` /
`StateChange` produce no EVE output. Use the dedicated
`FlowEventCsvWriter` / `FlowEventNdjsonWriter` if you need
those.

A fourth, `event_type: "http"`, is written explicitly rather than
derived from a `FlowEvent` — see below.

## Common fields

Every emitted record carries:

| Field        | Type                  | Source                                                                |
|--------------|-----------------------|-----------------------------------------------------------------------|
| `timestamp`  | string (ISO 8601 UTC) | event's `ts` via `Timestamp::write_iso8601`                          |
| `flow_id`    | u64                   | monotonic counter on the writer (one writer = one stream)             |
| `event_type` | string                | `"flow"` / `"anomaly"` / `"stats"`                                    |
| `in_iface`   | string (optional)     | `EveOptions::in_iface`; field is omitted when the option is empty     |
| `src_ip` / `src_port` / `dest_ip` / `dest_port` | string / u16 | `KeyFields` accessors on the key (each field omitted if `None`) |
| `proto`      | string (optional)     | `KeyFields::proto_str` — uppercase EVE convention                 |
| `app_proto`  | string (optional)     | `KeyFields::app_proto_str` — well-known port label                |
| `community_id` | string (`"1:"`+base64) | Corelight Community ID v1 — the canonical cross-tool flow id |

`community_id` is the portable flow identifier the ecosystem
pivots on (Zeek, Suricata, Security Onion, Arkime all key on it).
It is `"1:"`-prefixed SHA-1 + base64 over the canonical 5-tuple,
direction-invariant (A→B and B→A produce the same value) and
deterministic across runs. It is emitted **only when flowscope is
built with the `community-id` feature**, and is omitted if the key
lacks a full 5-tuple.

> **Changed in 0.19 (issue #88):** the proprietary 64-bit FNV-1a
> `flow_hash` field was **removed** from default EVE output in favour
> of the standard `community_id`. If you have dashboards keying on
> `flow_hash`, pivot them to `community_id` (and enable the
> `community-id` feature). The FNV hash is still available
> in-process as `KeyFields::stable_hash()` for sharding / keying, but
> it is non-portable and no longer emitted.

## `event_type: "anomaly"`

```json
{
  "timestamp": "2026-06-10T12:34:56.789012345Z",
  "flow_id": 17,
  "event_type": "anomaly",
  "src_ip": "10.0.0.1", "src_port": 33000,
  "dest_ip": "10.0.0.2", "dest_port": 80,
  "proto": "TCP",
  "app_proto": "http",
  "community_id": "1:wCb3Oy8JZ7qWp0pXm1mUg6yQ7sE=",
  "anomaly": {
    "type": "stream",
    "event": "ooo_segment",
    "code": 0
  },
  "severity": 3
}
```

`anomaly.type` is `"stream"` for buffer / OOO / retransmit /
watermark / eviction; `"applayer"` for parse errors. The
classification table lives in
`AnomalyFields for AnomalyKind` (see plan 126).

`anomaly.event` is the stable `AnomalyKind::short_kind` slug
(`"buffer_overflow"`, `"ooo_segment"`, `"retransmit"`, etc.).

`severity` is numeric per Suricata convention (1 = high,
4 = low):

| flowscope `Severity` | EVE `severity` |
|----------------------|----------------|
| `Critical`           | 1              |
| `Error`              | 2              |
| `Warning`            | 3              |
| `Info`               | 4              |

Override via `EveOptions::severity_numeric: fn(Severity) -> u8`.

## `event_type: "flow"`

Emitted on `FlowEvent::Ended`:

```json
{
  "timestamp": "2026-06-10T12:34:56.789012345Z",
  "flow_id": 18,
  "event_type": "flow",
  "src_ip": "10.0.0.1", "src_port": 33000,
  "dest_ip": "10.0.0.2", "dest_port": 80,
  "proto": "TCP",
  "community_id": "1:wCb3Oy8JZ7qWp0pXm1mUg6yQ7sE=",
  "flow": {
    "pkts_toserver": 7,
    "pkts_toclient": 5,
    "bytes_toserver": 2400,
    "bytes_toclient": 14000,
    "start": "2026-06-10T12:34:50.000000000Z",
    "end":   "2026-06-10T12:34:56.789012345Z",
    "age": 6,
    "reason": "fin",
    "alerted": false
  }
}
```

`flow.reason` mapping (matches `EndReason::as_str`):

| `EndReason`        | `flow.reason`        |
|--------------------|----------------------|
| `Fin`              | `"fin"`              |
| `Rst`              | `"rst"`              |
| `IdleTimeout`      | `"idle"`             |
| `Evicted`          | `"evicted"`          |
| `BufferOverflow`   | `"buffer_overflow"`  |
| `ParseError`       | `"parse_error"`      |
| `ParserDone`       | `"parser_done"`      |
| `ForceClosed`      | `"force_closed"`     |

## `event_type: "stats"` (opt-in)

Off by default — `Tick` events are high cardinality. Enable
via `EveOptions::include_stats = true`:

```json
{
  "timestamp": "2026-06-10T12:34:56.789012345Z",
  "flow_id": 19,
  "event_type": "stats",
  "src_ip": "10.0.0.1", "src_port": 33000,
  "dest_ip": "10.0.0.2", "dest_port": 80,
  "proto": "TCP",
  "community_id": "1:wCb3Oy8JZ7qWp0pXm1mUg6yQ7sE=",
  "stats": {
    "pkts_toserver": 7,
    "pkts_toclient": 5,
    "bytes_toserver": 2400,
    "bytes_toclient": 14000
  }
}
```

## Custom anomaly emission via `OwnedAnomaly` (0.13)

The 0.12 path emits `event_type: "anomaly"` from a typed
[`FlowEvent::FlowAnomaly`] / `TrackerAnomaly` — the `anomaly.type`
and `anomaly.event` fields come from the typed `AnomalyKind`
variant's classification.

The 0.13 path emits the same `event_type: "anomaly"` shape from
a [`flowscope::OwnedAnomaly`] — a canonical owned detector-
output value that carries:

- `kind: DetectorKind` — typed detector identity (0.21, issue
  #133; was `Cow<'static, str>` through 0.20). Its `as_str()`
  slug becomes `anomaly.event` — byte-identical to the pre-0.21
  string values. When `kind.attack_technique()` is `Some`, the
  MITRE ATT&CK technique ID is emitted as
  **`anomaly.attack_technique`**.
- `severity: Severity` — same severity tier as the typed path.
- `ts: Timestamp` — event time, becomes `timestamp`.
- 5-tuple flattened fields (`src_ip` / `src_port` /
  `dest_ip` / `dest_port` / `proto`) — each omitted if `None`.
- `observations: SmallVec<[(label, value); 4]>` — labels are
  `&'static str` (compile-time constants); values are
  `Cow<'static, str>`. Becomes the **`anomaly.labels`**
  nested object.
- `metrics: SmallVec<[(label, f64); 4]>` — labels are
  `&'static str`; values are `f64`. Becomes the
  **`anomaly.metrics`** nested object.
- `flowscope_kind: Option<AnomalyKind>` — set when bridging a
  flowscope-internal event into the owned shape (via
  `OwnedAnomaly::from_flow_anomaly`); informs the
  `anomaly.type` value when present.

### When to use which path

| You want to emit … | Use … |
|---|---|
| A flowscope-internal tracker anomaly (`BufferOverflow`, `OutOfOrderSegment`, …) | `EveJsonWriter::write_event(&FlowEvent::FlowAnomaly { … })` — same as 0.12 |
| A detector output (`PortScanTRW`, `BeaconCv`, `DgaScorer`, custom) | `EveJsonWriter::write_owned_anomaly(&owned)` |
| Both, through one routing function | `write_owned_anomaly`, bridging tracker anomalies via `OwnedAnomaly::from_flow_anomaly` |

### Shape

```json
{
  "timestamp": "2026-06-11T12:34:56.789012345Z",
  "flow_id": 21,
  "event_type": "anomaly",
  "src_ip": "10.0.0.1", "src_port": 33000,
  "dest_ip": "10.0.0.2", "dest_port": 80,
  "proto": "TCP",
  "anomaly": {
    "type": "applayer",
    "event": "PortScanTRW",
    "code": 0,
    "attack_technique": "T1046",
    "labels":  { "verdict": "scanner" },
    "metrics": { "log_likelihood": 4.158, "n_observed": 4 }
  },
  "severity": 3
}
```

- `anomaly.type` ← `EveOptions::custom_anomaly_type`
  (default `"applayer"`; Suricata-compatible values:
  `"stream"`, `"applayer"`, `"decode"`; schema-permissive).
  When `flowscope_kind.is_some()`, the typed kind's
  classification takes precedence (so bridged tracker
  anomalies get `"stream"` etc. as before).
- `anomaly.event` ← `OwnedAnomaly::kind.as_str()` slug.
- `anomaly.attack_technique` ← `DetectorKind::attack_technique()`
  (0.21) — omitted when the kind has no ATT&CK mapping
  (`Other(…)` / `Unknown`).
- `anomaly.labels` / `anomaly.metrics` — both omitted when
  the corresponding SmallVec is empty.

### Wiring detector output

Every shipped detector's score implements `flowscope::DetectorScore`
+ has an inherent `into_anomaly(ts) -> OwnedAnomaly`. Typical
end-to-end shape:

```rust,ignore
use flowscope::{DetectorScore, OwnedAnomaly};
use flowscope::detect::patterns::PortScanDetector;
use flowscope::extract::FiveTupleKey;

let mut port_scan: PortScanDetector<FiveTupleKey> =
    PortScanDetector::new();
let score = port_scan.observe(key, success);
// score: ScanScore<FiveTupleKey>
eve.write_owned_anomaly(&score.into_anomaly(ts))?;
```

### Custom detectors

Implement `DetectorScore` on your score type to route through
the same EVE path uniformly:

```rust,ignore
use flowscope::{DetectorKind, DetectorScore, OwnedAnomaly, Timestamp};
use flowscope::event::Severity;

struct MyScore { hits: u32 }

impl DetectorScore for MyScore {
    fn kind(&self) -> DetectorKind { DetectorKind::Other("MyCustomDetector") }
    fn into_anomaly(self, ts: Timestamp) -> OwnedAnomaly {
        OwnedAnomaly::new(DetectorKind::Other("MyCustomDetector"), Severity::Warning, ts)
            .with_metric("hits", self.hits as f64)
    }
}
```

### `EveOptions::custom_anomaly_type`

New field on `EveOptions` (0.13). Sets the `anomaly.type` value
for `write_owned_anomaly` calls when the anomaly has no
`flowscope_kind`:

```rust,ignore
let mut options = EveOptions::default();
options.custom_anomaly_type = "applayer";  // default
let mut eve = EveJsonWriter::with_options(sink, options);
```

## `event_type: "http"` — access records (0.23)

`EveJsonWriter::write_http_access(&record, ts)` emits one line per
HTTP exchange, built from an
[`HttpAccessRecord`](https://docs.rs/flowscope/latest/flowscope/http/struct.HttpAccessRecord.html).
It is written explicitly, not from the `FlowEvent` stream, because
the streaming HTTP parser is driven by the caller rather than by the
tracker — see `HttpAccessLog`.

```json
{"timestamp":"2023-11-14T22:13:20.000000+0000","flow_id":1,
 "event_type":"http","app_proto":"http",
 "http":{"hostname":"api.example","http_method":"POST","url":"/orders",
         "status":201,"request_body_len":5,"response_body_len":2,
         "protocol":"HTTP/1.1"},
 "flowscope":{"outcome":"completed"}}
```

| Field | Meaning |
|---|---|
| `http.hostname` | Routing authority — the absolute-form target if the request had one, else `Host`. |
| `http.http_method` / `http.url` | Method and request-target as they appeared on the wire. |
| `http.status` | Final response status. **Omitted** when no response was framed — not zero. |
| `http.request_body_len` / `http.response_body_len` | Body bytes **as framed on the wire** (chunk framing included), counted as they passed. The parser never held them. |
| `flowscope.outcome` | `completed` / `no_response` / `switched` / `refused`. |
| `flowscope.refused_reason` | Present only on `refused`: the [`HttpPoison`] slug naming the framing violation. |

Two things to know before you build on this:

- **There is no 5-tuple on these records.** The streaming parser is
  handed bytes, not packets, so it has no addresses to report. Join
  on `flow_id`, or emit the `"flow"` record alongside.
- **A refused connection still produces a line.** That is the point:
  a proxy that declined to forward a smuggled request is exactly the
  event an operator needs, and a log that omitted it would report
  that nothing happened.

## What's NOT emitted

- Per-message `event_type: "dns"` / `"tls"` records. Out of scope —
  file an issue if needed. (`"http"` **is** emitted, since 0.23; see
  above.)
- Alerts (`event_type: "alert"`). flowscope does not run
  Suricata rules; rule alerts come from Suricata.
- Field ordering. `serde_json::Map` uses insertion-order
  semantics, but downstream EVE parsers are order-independent
  by design.

## Schema version

This document targets Suricata 7.x EVE. The exact mapping is
locked through the 0.23 cycle; field additions will be
additive. For ECS-strict pipelines, pipe through Logstash with
the ECS-Suricata conversion module.

## Custom keys

`FiveTupleKey` ships an impl. To use your own key type,
implement `flowscope::KeyFields`:

```rust
use std::net::IpAddr;
use flowscope::KeyFields;

struct MyKey { src: IpAddr, dst: IpAddr, sport: u16, dport: u16 }

impl KeyFields for MyKey {
    fn src_ip(&self) -> Option<IpAddr> { Some(self.src) }
    fn src_port(&self) -> Option<u16> { Some(self.sport) }
    fn dest_ip(&self) -> Option<IpAddr> { Some(self.dst) }
    fn dest_port(&self) -> Option<u16> { Some(self.dport) }
    fn proto_str(&self) -> Option<&'static str> { Some("TCP") }
}
```

`KeyFields` and `AnomalyFields` are both in scope through
`flowscope::prelude::*`.

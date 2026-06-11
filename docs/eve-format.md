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

Three EVE `event_type` values are produced. Each is toggled
on `EveOptions`:

| `FlowEvent` variant      | `event_type` | Toggle                | Default |
|--------------------------|--------------|-----------------------|---------|
| `FlowEvent::Ended`       | `"flow"`     | `include_flow`        | on      |
| `FlowEvent::FlowAnomaly` / `TrackerAnomaly` | `"anomaly"` | `include_anomalies` | on      |
| `FlowEvent::Tick`        | `"stats"`    | `include_stats`       | off     |

`FlowEvent::Started` / `Established` / `Packet` /
`StateChange` produce no EVE output. Use the dedicated
`FlowEventCsvWriter` / `FlowEventNdjsonWriter` if you need
those.

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
| `flow_hash`  | string (16-char hex)  | FNV-1a over `(proto, sorted endpoints)` — direction-invariant         |

`flow_hash` is omitted if `proto_str` or any of the four
endpoint accessors return `None`. Two flowscope runs over the
same pcap produce the same `flow_hash` for the same flow
(deterministic). A→B and B→A produce the same `flow_hash`.

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
  "flow_hash": "9f3c0bb2a17f5048",
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
  "flow_hash": "9f3c0bb2a17f5048",
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
  "flow_hash": "9f3c0bb2a17f5048",
  "stats": {
    "pkts_toserver": 7,
    "pkts_toclient": 5,
    "bytes_toserver": 2400,
    "bytes_toclient": 14000
  }
}
```

## What's NOT emitted

- Per-message records (`event_type: "http"` / `"dns"` /
  `"tls"`). Out of scope for 0.12 — file an issue if needed.
- Alerts (`event_type: "alert"`). flowscope does not run
  Suricata rules; rule alerts come from Suricata.
- Field ordering. `serde_json::Map` uses insertion-order
  semantics, but downstream EVE parsers are order-independent
  by design.

## Schema version

This document targets Suricata 7.x EVE. The exact mapping is
locked for the 0.12 cycle; field additions will be additive.
For ECS-strict pipelines, pipe through Logstash with the
ECS-Suricata conversion module.

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

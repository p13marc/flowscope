# Observability

flowscope ships two opt-in Cargo features that wire the tracker
and drivers into the standard Rust observability ecosystem:

- **`metrics`** — counters, gauges, and histograms via the
  [`metrics`](https://crates.io/crates/metrics) crate (Prometheus
  / OpenTelemetry / anything with a recorder).
- **`tracing`** — structured events at flow-lifecycle transitions
  and on every emitted anomaly via the
  [`tracing`](https://crates.io/crates/tracing) crate.

Both are **zero-cost when off**. Every entry point is an
`#[inline(always)]` no-op stub when the feature isn't enabled —
no runtime branches, no string formatting, no allocations.

```toml
flowscope = { version = "0.8", features = ["metrics", "tracing"] }
```

Pick one or both. Both depend on the `tracker` feature (already
on by default).

## Metric vocabulary

| Metric | Type | Labels | Source |
|--------|------|--------|--------|
| `flowscope_flows_created_total` | counter | `l4` (`tcp` / `udp` / `other`) | First sight of a flow |
| `flowscope_flows_ended_total` | counter | `reason` (`fin` / `rst` / `idle` / `evicted` / `buffer_overflow` / `parse_error` / `parser_done` / `force_closed`) | Every `FlowEvent::Ended` |
| `flowscope_flows_active` | gauge | — | Live entries in the tracker |
| `flowscope_packets_unmatched_total` | counter | — | Extractor returned `None` |
| `flowscope_bytes_total` | counter | `side` (`initiator` / `responder`) | Cumulative on `Ended`, summed across flows |
| `flowscope_flow_duration_seconds` | histogram | — | Per-flow duration on `Ended` |
| `flowscope_flow_packets` | histogram | — | Per-flow packet count on `Ended` |
| `flowscope_flow_bytes` | histogram | — | Per-flow byte total on `Ended` |
| `flowscope_anomalies_total` | counter | `kind` (`buffer_overflow` / `ooo_segment` / `flow_table_eviction` / `parse_error` / `retransmit` / `reassembler_high_watermark`) | Every per-flow / tracker-global anomaly |
| `flowscope_reassembly_dropped_ooo_total` | counter | `side` | Out-of-order TCP segment drops |
| `flowscope_reassembly_bytes_dropped_oversize_total` | counter | `side` | Bytes dropped due to per-side buffer cap |
| `flowscope_reassembler_high_watermark_bytes` | histogram | `side` | Peak per-side buffer occupancy at `Ended` |
| `flowscope_retransmits_total` | counter | `side` | Classified TCP retransmits at `Ended` |
| `flowscope_flow_ticks_total` | counter | — | Per-flow periodic `Tick` events emitted |

Metric names are exported as `pub const` from `flowscope::obs`
(`METRIC_FLOWS_CREATED`, …) so downstream config can reference
them without typos.

## Cardinality discipline

All label values are `&'static str` — no per-call allocations.

**Never extend the obs module with flow-key-derived labels** (5-
tuple, MAC, IP). That creates one time series per flow and blows
up your storage backend. Stick to the four coarse axes:

- `l4` — protocol family.
- `reason` — end-of-flow classification.
- `kind` — anomaly classification.
- `side` — `initiator` vs `responder`.

If you need per-flow telemetry, snapshot via
`tracker.iter_active()` or `driver.snapshot_flow_stats()` and
emit to a side channel (events, traces, debug logging).

## Wiring up a recorder

Use whatever recorder fits your deployment. Prometheus:

```rust,ignore
use metrics_exporter_prometheus::PrometheusBuilder;

let handle = PrometheusBuilder::new()
    .install_recorder()
    .expect("recorder installs");

// Run flowscope. Counters land in the recorder.

// Render the scrape page when Prometheus polls /metrics:
let body = handle.render();
```

For OpenTelemetry the
[`metrics-exporter-opentelemetry`](https://crates.io/crates/metrics-exporter-opentelemetry)
crate works the same way.

For testing,
[`metrics-util`](https://crates.io/crates/metrics-util)'s
`DebuggingRecorder` snapshots counters into memory; see
`tests/metrics_integration.rs` for the canonical pattern.

## Histogram bucket tuning

`metrics` 0.24 lets the recorder configure histogram buckets.
Sensible starting points for flowscope's three histograms:

```rust,ignore
PrometheusBuilder::new()
    .set_buckets_for_metric(
        Matcher::Full("flowscope_flow_duration_seconds".to_string()),
        &[0.1, 1.0, 10.0, 60.0, 300.0, 3600.0],
    )?
    .set_buckets_for_metric(
        Matcher::Full("flowscope_flow_packets".to_string()),
        &[1.0, 10.0, 100.0, 1_000.0, 10_000.0, 100_000.0],
    )?
    .set_buckets_for_metric(
        Matcher::Full("flowscope_flow_bytes".to_string()),
        &[1_500.0, 64_000.0, 1_000_000.0, 10_000_000.0, 100_000_000.0],
    )?
    .install_recorder()?;
```

## Sample Prometheus / Grafana queries

- **New-flow rate** by L4:
  `rate(flowscope_flows_created_total[1m])`
- **Flow-termination breakdown**:
  `sum by (reason) (rate(flowscope_flows_ended_total[1m]))`
- **Buffer-cap pressure**:
  `rate(flowscope_anomalies_total{kind="buffer_overflow"}[1m])`
  — persistent non-zero means stuck parsers or undersized cap.
- **Eviction pressure**:
  `increase(flowscope_anomalies_total{kind="flow_table_eviction"}[5m])`
  — non-zero means `max_flows` is bottlenecking; bump it or
  shorten idle timeouts.
- **OOO drop rate by side**:
  `rate(flowscope_reassembly_dropped_ooo_total[1m])` —
  sustained non-zero on one side suggests asymmetric routing or
  a lossy NIC.
- **Retransmit rate by side**:
  `rate(flowscope_retransmits_total[1m])` — operators read this
  as a proxy for link loss; one-side imbalance points at
  directional packet loss.
- **Tick volume**:
  `rate(flowscope_flow_ticks_total[1m])` — for sizing
  `flow_tick_interval`; expected rate is
  `flowscope_flows_active × (1 / interval)`.

## Tracing

When the `tracing` feature is on, flowscope emits two event
targets:

- `flowscope.flow` — INFO-level events on flow created and ended.
  Fields: `l4`, `reason`, `packets`, `bytes`.
- `flowscope.anomaly` — WARN-level events on every emitted
  anomaly. Fields: `severity`, `kind` (full `AnomalyKind` debug
  rendering).

Flow keys are intentionally **not** included in trace events —
the `FlowExtractor::Key` trait isn't bound to `Debug`, and
including keys would defeat the cardinality discipline that the
metrics side follows. Operators correlate by timestamp and the
structured fields.

### Wiring up a subscriber

```rust,ignore
use tracing_subscriber::EnvFilter;

tracing_subscriber::fmt()
    .with_env_filter(EnvFilter::from_default_env()
        .add_directive("flowscope.flow=info".parse().unwrap())
        .add_directive("flowscope.anomaly=warn".parse().unwrap()))
    .init();
```

Or configure via `RUST_LOG=flowscope.flow=info,flowscope.anomaly=warn`.

For JSON logs / OpenTelemetry collection, swap in your usual
`tracing-subscriber` layers — flowscope emits standard events;
no special integration required.

### Routing by severity

Every `flowscope.anomaly` event carries a `severity` structured
field — `info` / `warning` / `error` / `critical` — derived from
`AnomalyKind::severity()`.

Default mapping:

| Kind | Default severity |
|------|------------------|
| `OutOfOrderSegment` | `info` |
| `RetransmittedSegment` | `info` |
| `BufferOverflow` (any policy) | `warning` |
| `ReassemblerHighWatermark` | `warning` |
| `FlowTableEvictionPressure` | `warning` |
| `SessionParseError` | `error` |

`critical` is reserved for future use; no `AnomalyKind` variant
defaults to it today.

`Severity` derives `Ord`, so threshold filters compile directly:

```rust,ignore
if kind.severity() >= Severity::Warning {
    metrics::counter!("anomalies_high_severity_total").increment(1);
}
```

### Overhead

Tracing events are cheap when no subscriber is attached
(`tracing-core` short-circuits the call). With a subscriber, the
per-flow INFO event adds one allocation per flow lifecycle (~30–
50 ns per event measured locally). At INFO level the overhead is
negligible even at 100k flows/sec.

Per-packet tracing is **not** wired up. If you need it, attach a
custom subscriber that watches `flowscope.flow` and correlates
with packet-level data from your capture layer.

## Coordinating with `FlowEvent::FlowAnomaly` / `TrackerAnomaly`

The `flowscope_anomalies_total` counter and the
`flowscope.anomaly` tracing target share the same vocabulary as
the `AnomalyKind` enum. Adding a new variant requires a
corresponding label arm in `src/obs.rs::anomaly_label` —
`cargo test --features metrics` catches drift via the integration
test.

When you opt in to anomaly emission via
`FlowDriver::with_emit_anomalies(true)`, the metrics + tracing
hooks fire automatically on every emitted event.

When you stay opted out, the **cumulative** counters (driven by
`FlowStats` and tracker stats at flow end) still capture the
aggregate signal; you just lose the per-event live stream.

## Structured output via `serde`

Beyond the `metrics` and `tracing` hooks, flowscope ships a
`serde` Cargo feature for full event-level structured output to
Vector / Fluentd / Loki / Splunk HEC. See
[`recipes.md`](recipes.md) → "Structured event output via serde"
for the canonical pattern and a note on the locked wire format.

# Observability — `metrics` and `tracing`

flowscope ships two opt-in Cargo features that wire the tracker and
driver into the standard Rust observability ecosystem:

- **`metrics`** — Prometheus / OpenTelemetry-style counters,
  gauges, and histograms via the [`metrics`](https://crates.io/crates/metrics)
  crate.
- **`tracing`** — structured events at flow lifecycle transitions
  via the [`tracing`](https://crates.io/crates/tracing) crate.

Both are zero-cost when off — every entry point is `#[inline(always)]`
no-op stubbed at compile time, so you pay nothing if you don't enable
the feature.

## Enabling

```toml
flowscope = { version = "0.2", features = ["metrics", "tracing"] }
```

Or pick one. Both depend on the `tracker` feature (already enabled
by default).

## Metrics

### Vocabulary

| Metric | Type | Labels | Source |
|--------|------|--------|--------|
| `flowscope_flows_created_total` | counter | `l4` (`tcp` / `udp` / `other`) | First sight of a flow in `FlowTracker` |
| `flowscope_flows_ended_total` | counter | `reason` (`fin` / `rst` / `idle` / `evicted` / `buffer_overflow`) | Every `FlowEvent::Ended` |
| `flowscope_flows_active` | gauge | — | Live count of tracker entries |
| `flowscope_packets_unmatched_total` | counter | — | Extractor returned `None` |
| `flowscope_bytes_total` | counter | `side` (`initiator` / `responder`) | Cumulative on `Ended`, summed across all flows |
| `flowscope_flow_duration_seconds` | histogram | — | Per-flow duration on `Ended` |
| `flowscope_flow_packets` | histogram | — | Per-flow packet count on `Ended` |
| `flowscope_flow_bytes` | histogram | — | Per-flow byte total on `Ended` |
| `flowscope_anomalies_total` | counter | `kind` (`buffer_overflow` / `ooo_segment` / `flow_table_eviction` / `parse_error` / `retransmit` / `reassembler_high_watermark`) | Every `FlowEvent::FlowAnomaly` / `TrackerAnomaly` |
| `flowscope_reassembly_dropped_ooo_total` | counter | `side` | Out-of-order TCP segment drops |
| `flowscope_reassembly_bytes_dropped_oversize_total` | counter | `side` | Bytes dropped due to per-side buffer cap |
| `flowscope_reassembler_high_watermark_bytes` | histogram | `side` | Peak per-side reassembler buffer occupancy at `Ended` |
| `flowscope_retransmits_total` (0.5.0) | counter | `side` | Reassembler-classified TCP retransmits at `Ended` |
| `flowscope_flow_ticks_total` (0.5.0) | counter | — | Per-flow periodic `FlowEvent::Tick` emissions |

The metric names are also exported as constants from `flowscope::obs`
(`METRIC_FLOWS_CREATED`, …) so downstream config can reference them
without typos.

### Cardinality discipline

All label values are `&'static str` — no per-call allocations. **Never
extend the obs module with flow-key-derived labels** (5-tuple, MAC,
IP). That would create one time series per flow and blow up your
storage backend. Stick to coarse labels:

- `l4` — protocol family at the transport layer.
- `reason` — end-of-flow classification.
- `kind` — anomaly classification.
- `side` — `initiator` vs `responder`.

### Wiring up a recorder

Use whatever recorder fits your deployment:

```rust,ignore
use metrics_exporter_prometheus::PrometheusBuilder;

let handle = PrometheusBuilder::new()
    .install_recorder()
    .expect("recorder installs");

// Run flowscope. Counters land in the recorder.

// Render the scrape page when Prometheus polls /metrics:
let body = handle.render();
```

For OpenTelemetry, the [`metrics-exporter-opentelemetry`](https://crates.io/crates/metrics-exporter-opentelemetry)
crate works the same way.

For testing, the `metrics-util` crate's `DebuggingRecorder` snapshots
counters into memory (see `tests/metrics_integration.rs`).

### Histogram bucket tuning

`metrics` 0.24 lets the recorder configure histogram buckets. Sensible
starting points for flowscope's three histograms:

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

### Sample Prometheus / Grafana queries

- **New flow rate**: `rate(flowscope_flows_created_total[1m])`
  by `l4`.
- **Flow termination breakdown**: `sum by (reason) (rate(flowscope_flows_ended_total[1m]))`.
- **Buffer-cap pressure**: `rate(flowscope_anomalies_total{kind="buffer_overflow"}[1m])`.
  Persistent non-zero rate means consumers have stuck parsers or
  the cap is too small.
- **Eviction pressure**: `increase(flowscope_anomalies_total{kind="flow_table_eviction"}[5m])`.
  Non-zero means `max_flows` is the bottleneck — bump the limit or
  shorten idle timeouts.
- **OOO drop rate by side**: `rate(flowscope_reassembly_dropped_ooo_total[1m])`
  by `side`. Sustained non-zero on one side suggests asymmetric
  routing or a lossy NIC.
- **Retransmit rate** (0.5.0): `rate(flowscope_retransmits_total[1m])`
  by `side`. Operators read this as a proxy for link loss; a sustained
  imbalance between sides points at one-direction packet loss.
- **Tick volume** (0.5.0): `rate(flowscope_flow_ticks_total[1m])`.
  Helps size the `flow_tick_interval` against the live-flow count
  — `flowscope_flows_active × (1 / interval)` is the expected
  tick rate.

## Tracing

When `feature = "tracing"` is on, flowscope emits two event targets:

- `flowscope.flow` — INFO-level events on flow created and ended.
  Fields: `l4`, `reason`, `packets`, `bytes`.
- `flowscope.anomaly` — WARN-level events on every emitted anomaly.
  Fields: `kind` (the full `AnomalyKind` debug rendering).

Flow keys are intentionally **not** included in trace events — the
`FlowExtractor::Key` trait isn't bound to `Debug`, and including
keys would defeat the cardinality discipline that the metrics side
follows. Operators correlate by timestamp and the structured fields.

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
`tracing-subscriber` layers — flowscope emits standard `tracing`
events, no special integration required.

### Routing by severity (0.7.0+)

Every emitted `flowscope.anomaly` event carries a `severity`
structured field — `info` / `warning` / `error` / `critical` —
derived from `AnomalyKind::severity()`. Subscribers route on it:

```rust,ignore
// Pseudocode — wrap your subscriber to filter on the field.
tracing_subscriber::fmt()
    .with_env_filter("flowscope.anomaly=warn")
    .init();

// Or in a custom layer, inspect the event's severity field
// and route to alerts / metrics / logs accordingly.
```

The default mapping is conservative:

| Kind | Default severity |
|------|------------------|
| `OutOfOrderSegment` | `info` |
| `RetransmittedSegment` | `info` |
| `BufferOverflow` (any policy) | `warning` |
| `ReassemblerHighWatermark` | `warning` |
| `FlowTableEvictionPressure` | `warning` |
| `SessionParseError` | `error` |

`critical` is reserved for future use; no `AnomalyKind` variant
defaults to `Critical` today. Consumers can override the default
by classifying anomalies themselves in their event loop.

`Severity` implements `Ord`, so threshold filters work directly:

```rust,ignore
if kind.severity() >= Severity::Warning {
    metrics::counter!("anomalies_high_severity_total").increment(1);
}
```

### Overhead

Tracing events are cheap when no subscriber is attached (the call
short-circuits in `tracing-core`). With a subscriber, the per-flow
INFO event adds one allocation per flow lifecycle (~30–50 ns per
event measured locally). At INFO level the overhead is negligible
even at 100k flows/sec.

Per-packet tracing is **not** wired up. If you need it, you can
attach a custom subscriber that watches `flowscope.flow` and
correlates with packet-level data from your capture layer.

## Coordinating with `FlowEvent::FlowAnomaly` / `TrackerAnomaly`

The `flowscope_anomalies_total` counter and `flowscope.anomaly`
trace events share the same vocabulary as the
[`AnomalyKind`](../src/event.rs) enum. Adding a new variant to
`AnomalyKind` requires a corresponding match arm in
`src/obs.rs::anomaly_label` — `cargo test --features metrics`
catches drift via the integration test.

When you opt in to anomaly emission via
`FlowDriver::with_emit_anomalies(true)`, the metrics + tracing
hooks fire automatically. If you stay opted out, the counters
(based on `FlowStats` and tracker stats at flow end) still capture
the cumulative information; you just lose the per-event live
signal.

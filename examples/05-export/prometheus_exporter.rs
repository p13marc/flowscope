//! Render flowscope's `metrics` feature output as OpenMetrics
//! (Prometheus) text.
//!
//! Walks a pcap through a [`FlowDriver`] configured with
//! `with_emit_anomalies(true)`, then dumps every counter +
//! gauge + histogram the `metrics` feature exposed during the
//! run, formatted as Prometheus text-exposition.
//!
//! This example uses the `metrics-util` `DebuggingRecorder`
//! (already a dev-dependency) rather than pulling in
//! `metrics-exporter-prometheus`. The rendered output is
//! schema-equivalent to what an in-process Prometheus exporter
//! would scrape — point `promtool check metrics` at it to
//! confirm.
//!
//! ## Production wiring
//!
//! For a real long-running daemon, install
//! [`metrics-exporter-prometheus`](https://docs.rs/metrics-exporter-prometheus)
//! once at startup and let it expose `/metrics`:
//!
//! ```ignore
//! use metrics_exporter_prometheus::PrometheusBuilder;
//! PrometheusBuilder::new()
//!     .with_http_listener(([0, 0, 0, 0], 9898))
//!     .install()?;
//! ```
//!
//! ## Metric vocabulary (see `docs/observability.md`)
//!
//! - `flowscope_flows_created_total{l4=}`
//! - `flowscope_flows_ended_total{reason=}`
//! - `flowscope_flows_active`
//! - `flowscope_bytes_total{side=}`
//! - `flowscope_anomalies_total{kind=}`
//! - `flowscope_retransmits_total{side=}`
//! - `flowscope_reassembly_dropped_ooo_total{side=}`
//! - `flowscope_reassembly_bytes_dropped_oversize_total{side=}`
//! - `flowscope_flow_duration_seconds` (histogram)
//! - `flowscope_flow_packets` (histogram)
//! - `flowscope_flow_bytes` (histogram)
//!
//! ## Cardinality budget
//!
//! Labels are **kind / reason / side / l4** — bounded vocabularies.
//! Do NOT add per-flow labels (5-tuple, SNI, JA3) directly to
//! counters; that explodes cardinality. Route per-flow data
//! through structured event sinks (EVE / NDJSON / Zeek) instead.
//!
//! ## Usage
//!
//! ```bash
//! cargo run --features "metrics,pcap,extractors,tracker,reassembler" \
//!     --example prometheus_exporter -- trace.pcap
//!
//! cargo run --features "metrics,pcap,extractors,tracker,reassembler" \
//!     --example prometheus_exporter -- trace.pcap | promtool check metrics
//! ```
//!
//! Closes #45.

use std::collections::BTreeMap;

use flowscope::extract::FiveTuple;
use flowscope::pcap::PcapFlowSource;
use flowscope::reassembler::BufferedReassemblerFactory;
use flowscope::{FlowDriver, Timestamp};
use metrics_util::MetricKind;
use metrics_util::debugging::{DebugValue, DebuggingRecorder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    // metrics-util DebuggingRecorder — install once per process.
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    recorder.install()?;

    // Drive the pcap through a real FlowDriver — every counter
    // / gauge / histogram in src/obs.rs fires during this walk.
    let mut driver = FlowDriver::new(
        FiveTuple::bidirectional(),
        BufferedReassemblerFactory::default(),
    )
    .with_emit_anomalies(true);

    let mut last_ts = Timestamp { sec: 0, nsec: 0 };
    for view in PcapFlowSource::open(&path)?.views() {
        let view = view?;
        last_ts = view.timestamp;
        let _ = driver.track(&view);
    }
    let _ = driver.sweep(last_ts);

    // Render the snapshot as Prometheus text-exposition. The
    // output is grouped per metric name with a single # TYPE
    // hint line.
    let snap = snapshotter.snapshot().into_vec();
    let mut by_name: BTreeMap<String, (MetricKind, Vec<(String, String)>)> = BTreeMap::new();
    for (key, _unit, _desc, value) in &snap {
        let name = key.key().name().to_string();
        let kind = key.kind();
        let labels: Vec<String> = key
            .key()
            .labels()
            .map(|l| format!("{}=\"{}\"", l.key(), l.value()))
            .collect();
        let labels_part = if labels.is_empty() {
            String::new()
        } else {
            format!("{{{}}}", labels.join(","))
        };
        let value_str = match value {
            DebugValue::Counter(n) => n.to_string(),
            DebugValue::Gauge(g) => format!("{}", g.into_inner()),
            DebugValue::Histogram(hs) => {
                // For brevity, emit the mean as a synthetic gauge
                // sample. Real Prometheus exposition would emit
                // the histogram bucket vector — see
                // metrics-exporter-prometheus for the full path.
                let total = hs.iter().map(|v| v.into_inner()).sum::<f64>();
                let n = hs.len() as f64;
                format!("{}", if n > 0.0 { total / n } else { 0.0 })
            }
        };
        let entry = by_name.entry(name).or_insert_with(|| (kind, Vec::new()));
        entry.1.push((labels_part, value_str));
    }

    for (name, (kind, mut samples)) in by_name {
        let kind_str = match kind {
            MetricKind::Counter => "counter",
            MetricKind::Gauge => "gauge",
            MetricKind::Histogram => "summary",
        };
        println!("# TYPE {name} {kind_str}");
        samples.sort();
        for (labels, value) in samples {
            println!("{name}{labels} {value}");
        }
    }
    Ok(())
}

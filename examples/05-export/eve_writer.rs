//! Flagship Suricata EVE-JSON exporter.
//!
//! Pipes flowscope's full event vocabulary through
//! [`EveJsonWriter`] (plan 123, 0.12; plan 147, 0.13). Output is
//! one JSON object per line in Suricata 7.x EVE schema — drop-
//! in input for Filebeat's Suricata module, Splunk Suricata TA,
//! Tenzir's `read_suricata`, and ECS-converting pipelines.
//!
//! Demonstrates **all three** EVE event types emitted by the
//! stack:
//!
//! - `event_type: "flow"` — emitted on every
//!   [`FlowEvent::Ended`].
//! - `event_type: "anomaly"` — emitted on
//!   [`FlowEvent::FlowAnomaly`] (turned on by
//!   [`FlowDriver::with_emit_anomalies`]) and on any detector
//!   score routed via [`EveJsonWriter::write_owned_anomaly`].
//! - `event_type: "stats"` — emitted on
//!   [`FlowEvent::Tick`] (turned on via
//!   [`EveOptions::include_stats`]).
//!
//! Plus a [`BeaconDetector`] running side-by-side; its scores
//! ship through `write_owned_anomaly` so SIEM operators see the
//! detector verdict in the same EVE stream.
//!
//! ## Usage
//!
//! ```bash
//! cargo run --features "pcap,extractors,tracker,reassembler,emit-eve" \
//!     --example eve_writer -- trace.pcap > eve.json
//!
//! # Per event-type filtering:
//! jq 'select(.event_type=="flow")'    < eve.json | head
//! jq 'select(.event_type=="anomaly")' < eve.json | head
//! jq 'select(.event_type=="stats")'   < eve.json | head
//! ```

use std::collections::HashSet;
use std::io::{BufWriter, stdout};
use std::net::IpAddr;

use flowscope::detect::patterns::BeaconDetector;
use flowscope::emit::{EveJsonWriter, EveOptions};
use flowscope::extract::FiveTuple;
use flowscope::pcap::PcapFlowSource;
use flowscope::reassembler::BufferedReassemblerFactory;
use flowscope::{
    DetectorKind, FlowDriver, KeyFields, OwnedAnomaly, PacketView, Timestamp, event::Severity,
};

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct SrcIpKey(IpAddr);

impl KeyFields for SrcIpKey {
    fn src_ip(&self) -> Option<IpAddr> {
        Some(self.0)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    // FlowDriver gates anomaly emission; the EveJsonWriter
    // serializes whatever ends up on the event stream.
    let mut driver = FlowDriver::new(
        FiveTuple::bidirectional(),
        BufferedReassemblerFactory::default(),
    )
    .with_emit_anomalies(true);

    let mut opts = EveOptions::default();
    opts.in_iface = "pcap0".to_string();
    opts.include_stats = true; // Tick → stats event_type.
    let mut eve = EveJsonWriter::with_options(BufWriter::new(stdout().lock()), opts);

    // Plan 147 — a detector running side-by-side; its scores
    // ship through the same EVE writer as FlowAnomaly /
    // TrackerAnomaly events.
    let mut beacon: BeaconDetector<IpAddr> = BeaconDetector::new();
    let mut detector_emitted: HashSet<IpAddr> = HashSet::new();
    let mut last_ts = Timestamp { sec: 0, nsec: 0 };

    for view in PcapFlowSource::open(&path)?.views() {
        let view = view?;
        last_ts = view.timestamp;

        // Detector — observe every packet, route scores to EVE
        // via write_owned_anomaly (plan 147 pipeline).
        let pv = PacketView::new(&view.frame, view.timestamp);
        if let Ok(layers) = pv.layers() {
            let src: Option<IpAddr> = if let Some(v4) = layers.ipv4() {
                Some(IpAddr::V4(v4.source()))
            } else {
                layers.ipv6().map(|v6| IpAddr::V6(v6.source()))
            };
            if let Some(src) = src
                && let Some(score) = beacon.observe(src, view.timestamp, view.frame.len() as u64)
                && score.score >= 0.7
                && detector_emitted.insert(src)
            {
                let anomaly =
                    OwnedAnomaly::new(DetectorKind::BeaconCv, Severity::Warning, view.timestamp)
                        .with_key(&SrcIpKey(src))
                        .with_metric("score", score.score)
                        .with_metric("cv_dt", score.cv_dt)
                        .with_metric("cv_bytes", score.cv_bytes)
                        .with_metric("mean_interval_secs", score.mean_interval.as_secs_f64());
                eve.write_owned_anomaly(&anomaly)?;
            }
        }

        // Driver — Ended + FlowAnomaly + TrackerAnomaly + Tick
        // events all flow through the same writer.
        for ev in driver.track(&view) {
            eve.write_event(&ev)?;
        }
    }
    for ev in driver.sweep(last_ts) {
        eve.write_event(&ev)?;
    }

    eve.finish()?;
    Ok(())
}

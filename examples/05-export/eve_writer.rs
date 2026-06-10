//! Export flows + anomalies as Suricata EVE JSON.
//!
//! Pipes flowscope's `FlowEvent` stream through
//! [`flowscope::emit::EveJsonWriter`] (plan 123, 0.12) producing
//! one JSON object per line in Suricata 7.x EVE schema. Drop-in
//! input for Filebeat's Suricata module, Splunk Suricata TA,
//! Tenzir's `read_suricata`, and ECS-converting pipelines.
//!
//! ```bash
//! cargo run --features pcap,emit-eve \
//!     --example eve_writer -- trace.pcap > eve.json
//!
//! # Filter the output:
//! cat eve.json | jq 'select(.event_type=="anomaly")'
//! cat eve.json | jq 'select(.event_type=="flow") | .flow_hash'
//! ```

use std::io::{BufWriter, stdout};

use flowscope::FlowTracker;
use flowscope::emit::{EveJsonWriter, EveOptions};
use flowscope::extract::FiveTuple;
use flowscope::pcap::PcapFlowSource;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    let mut tracker = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());

    // `include_anomalies` and `include_flow` default to true; we
    // set in_iface so the records carry the capture point. Stats
    // (FlowTick) stays off — too noisy for offline replay.
    let mut opts = EveOptions::default();
    opts.in_iface = "pcap0".to_string();
    let mut eve = EveJsonWriter::with_options(BufWriter::new(stdout().lock()), opts);

    // For live FlowAnomaly emission, wrap the tracker in a
    // `FlowDriver` and call `.with_emit_anomalies(true)`. The
    // shape used here surfaces `FlowEvent::Ended` records;
    // cumulative reassembly diagnostics still ride along in
    // `FlowStats`.
    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        for ev in tracker.track(&owned) {
            eve.write_event(&ev)?;
        }
    }
    for ev in tracker.finish() {
        eve.write_event(&ev)?;
    }
    eve.finish()?;
    Ok(())
}

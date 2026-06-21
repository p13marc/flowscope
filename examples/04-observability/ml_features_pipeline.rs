//! ML feature-vector export — full CICFlowMeter pipeline.
//!
//! Drives a [`FlowTracker`] over a pcap, builds a
//! `FlowRecord` per ended flow (via the IPFIX `from_parts`
//! constructor), then folds in the per-direction IAT +
//! Active/Idle stats from the underlying `FlowStats`
//! through `CicFlowFeatures::with_iat`. Writes one
//! NDJSON line per flow — ready for pandas / DuckDB /
//! scikit-learn ingestion.
//!
//! Demonstrates the full 0.18-cycle ml-features pipeline:
//!
//!   pcap → FlowTracker → FlowEvent::Ended
//!        → FlowRecord::from_parts
//!        → CicFlowFeatures::from_flow_record(&rec).with_iat(&stats)
//!        → serde_json::to_string
//!
//! Usage:
//!     cargo run --features "pcap,ml-features,extractors,tracker,serde" \
//!         --example ml_features_pipeline -- trace.pcap > flows.jsonl

use std::env;

use flowscope::{
    CicFlowFeatures, EndReason, FlowEvent, FlowRecord, FlowTracker, extract::FiveTuple,
    pcap::PcapFlowSource,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args()
        .nth(1)
        .ok_or("usage: ml_features_pipeline <trace.pcap>")?;

    let mut tracker = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
    let mut flows_emitted = 0u64;

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        for ev in tracker.track(&owned) {
            if let FlowEvent::Ended {
                key, stats, reason, ..
            } = ev
            {
                let rec = FlowRecord::from_parts(&stats, &key, Some(reason));
                let feats = CicFlowFeatures::from_flow_record(&rec).with_iat(&stats);
                println!("{}", serde_json::to_string(&feats)?);
                flows_emitted += 1;
            }
        }
    }
    for ev in tracker.finish() {
        if let FlowEvent::Ended {
            key, stats, reason, ..
        } = ev
        {
            let rec = FlowRecord::from_parts(&stats, &key, Some(reason));
            let feats = CicFlowFeatures::from_flow_record(&rec).with_iat(&stats);
            println!("{}", serde_json::to_string(&feats)?);
            flows_emitted += 1;
        }
    }

    // Acknowledge the EndReason import even when no flows
    // emitted (silences -D unused_imports under
    // -D warnings).
    let _ = EndReason::Fin;

    eprintln!("emitted {flows_emitted} CIC-flow feature vectors");
    Ok(())
}

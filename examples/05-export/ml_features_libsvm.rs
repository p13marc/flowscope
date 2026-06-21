//! ML feature-vector export — libsvm sibling of
//! `ml_features_pipeline.rs`.
//!
//! Walks a pcap, builds a [`CicFlowFeatures`] per finalised
//! flow, then writes one libsvm-format row per flow to stdout
//! ready to redirect to `training.libsvm`.
//!
//! The libsvm format (a.k.a. svmlight) is the canonical
//! sklearn / xgboost / liblinear input:
//!
//! ```text
//! <label> <feature_idx>:<value> <feature_idx>:<value> ...
//! ```
//!
//! - One row per data point.
//! - `<label>` is the supervised target. Since flowscope is a
//!   feature-extraction tool, this example writes `0` as a
//!   placeholder; the user joins real labels separately.
//! - `<feature_idx>` is 1-based per the format spec.
//! - Zero-valued features may be omitted (sparse format); this
//!   example emits all features for compatibility with the
//!   stricter loaders.
//!
//! ## Reference
//!
//! - libsvm format spec:
//!   <https://www.csie.ntu.edu.tw/~cjlin/libsvmtools/datasets/>
//! - sklearn loader:
//!   <https://scikit-learn.org/stable/modules/generated/sklearn.datasets.load_svmlight_file.html>
//! - For NDJSON / pandas-shaped output instead, see
//!   `examples/04-observability/ml_features_pipeline.rs`.
//!
//! ## Usage
//!
//! ```bash
//! cargo run --features "pcap,ml-features,extractors,tracker" \
//!     --example ml_features_libsvm -- trace.pcap > training.libsvm
//! ```
//!
//! Closes #49.

use std::env;

use flowscope::extract::FiveTuple;
use flowscope::pcap::PcapFlowSource;
use flowscope::{CicFlowFeatures, FlowEvent, FlowRecord, FlowTracker};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args()
        .nth(1)
        .ok_or("usage: ml_features_libsvm <trace.pcap>")?;

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
                emit_libsvm(&feats);
                flows_emitted += 1;
            }
        }
    }

    eprintln!("{flows_emitted} flow(s) exported.");
    Ok(())
}

/// Write one libsvm-format row to stdout. Placeholder label
/// `0`; downstream supplies real labels via a join.
fn emit_libsvm(f: &CicFlowFeatures) {
    let pairs: [(u32, f64); 32] = [
        (1, f.flow_duration_us as f64),
        (2, f.total_fwd_packets as f64),
        (3, f.total_bwd_packets as f64),
        (4, f.total_fwd_bytes as f64),
        (5, f.total_bwd_bytes as f64),
        (6, f.fwd_packet_length_mean),
        (7, f.bwd_packet_length_mean),
        (8, f.mean_packet_length),
        (9, f.flow_bytes_per_sec),
        (10, f.flow_packets_per_sec),
        (11, f.down_up_ratio),
        (12, f.flow_iat_mean_us),
        (13, f.flow_iat_std_us),
        (14, f.flow_iat_min_us),
        (15, f.flow_iat_max_us),
        (16, f.fwd_iat_mean_us),
        (17, f.fwd_iat_std_us),
        (18, f.fwd_iat_min_us),
        (19, f.fwd_iat_max_us),
        (20, f.bwd_iat_mean_us),
        (21, f.bwd_iat_std_us),
        (22, f.bwd_iat_min_us),
        (23, f.bwd_iat_max_us),
        (24, f.active_mean_us),
        (25, f.active_std_us),
        (26, f.active_min_us),
        (27, f.active_max_us),
        (28, f.idle_mean_us),
        (29, f.idle_std_us),
        (30, f.idle_min_us),
        (31, f.idle_max_us),
        (
            32,
            (f.tcp_flag_counts.fwd_fin + f.tcp_flag_counts.bwd_fin) as f64,
        ),
    ];
    let mut line = String::from("0");
    for (idx, v) in pairs {
        line.push(' ');
        line.push_str(&idx.to_string());
        line.push(':');
        line.push_str(&format_value(v));
    }
    println!("{line}");
}

fn format_value(v: f64) -> String {
    if v == 0.0 || v.is_nan() {
        "0".to_string()
    } else if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{}", v as i64)
    } else {
        format!("{v:.6}")
    }
}

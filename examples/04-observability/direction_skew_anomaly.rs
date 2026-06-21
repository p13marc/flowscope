//! Direction-skew anomaly: flag flows whose end-of-life
//! bytes are >90% one-sided. Useful for finding scans
//! (initiator-only), DoS (responder-only), asymmetric
//! streaming (CDN downloads), or broken-handshake patterns.
//!
//! Demonstrates two 0.14 additions:
//!
//! - [`FlowStats::direction_skew`] (plan 168) — `(bytes_init -
//!   bytes_resp) / total_bytes`, clamped to [-1, 1].
//! - [`FlowStats::throughput_bps_for`] (plan 173) — per-side
//!   lifetime-average throughput with safe-divide (zero-duration
//!   flows return 0.0, not NaN).
//!
//! Plus uses [`FlowStats::bytes_for`] (plan 168) and
//! [`FlowStats::duration_secs`] (0.10).
//!
//! Recipe: `docs/recipes.md` § "0.14 patterns" /
//! "Direction skew" (forthcoming).
//! Migration doc: `docs/migration-0.13-to-0.14.md` §7, §14.
//!
//! ```bash
//! cargo run --features pcap,extractors,tracker --example direction_skew_anomaly
//! ```
//!
//! [`FlowStats::direction_skew`]: flowscope::FlowStats::direction_skew
//! [`FlowStats::throughput_bps_for`]: flowscope::FlowStats::throughput_bps_for
//! [`FlowStats::bytes_for`]: flowscope::FlowStats::bytes_for
//! [`FlowStats::duration_secs`]: flowscope::FlowStats::duration_secs

use flowscope::{FlowEvent, FlowSide, FlowTracker, extract::FiveTuple, pcap::PcapFlowSource};

/// Threshold for one-sided detection. |skew| > THRESH triggers
/// the anomaly. 0.9 means "responder contributes <5% or
/// initiator contributes <5%".
const THRESH: f64 = 0.9;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    let mut tracker = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
    let mut total_flows = 0usize;
    let mut flagged = 0usize;

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        for ev in tracker.track(&owned) {
            if let FlowEvent::Ended { key, stats, .. } = ev {
                total_flows += 1;
                let skew = stats.direction_skew();
                if skew.abs() > THRESH {
                    flagged += 1;
                    let direction = if skew > 0.0 {
                        "↑ upload-heavy"
                    } else {
                        "↓ download-heavy"
                    };
                    println!(
                        "{direction:<18} flow {key:?} \
                         skew={skew:+.2} \
                         {init_bytes}B↑ / {resp_bytes}B↓ \
                         ({init_bps:.0}↑/{resp_bps:.0}↓ B/s)",
                        init_bytes = stats.bytes_for(FlowSide::Initiator),
                        resp_bytes = stats.bytes_for(FlowSide::Responder),
                        init_bps = stats.throughput_bps_for(FlowSide::Initiator),
                        resp_bps = stats.throughput_bps_for(FlowSide::Responder),
                    );
                }
            }
        }
    }
    for ev in tracker.finish() {
        if let FlowEvent::Ended { key, stats, .. } = ev {
            total_flows += 1;
            let skew = stats.direction_skew();
            if skew.abs() > THRESH {
                flagged += 1;
                let direction = if skew > 0.0 {
                    "↑ upload-heavy"
                } else {
                    "↓ download-heavy"
                };
                println!(
                    "{direction:<18} flow {key:?} \
                     skew={skew:+.2} \
                     {init_bytes}B↑ / {resp_bytes}B↓ \
                     ({init_bps:.0}↑/{resp_bps:.0}↓ B/s)",
                    init_bytes = stats.bytes_for(FlowSide::Initiator),
                    resp_bytes = stats.bytes_for(FlowSide::Responder),
                    init_bps = stats.throughput_bps_for(FlowSide::Initiator),
                    resp_bps = stats.throughput_bps_for(FlowSide::Responder),
                );
            }
        }
    }

    println!();
    println!("=== summary ===");
    println!("Total ended flows:     {total_flows}");
    println!("Flagged |skew| > {THRESH}: {flagged}");
    if total_flows > 0 {
        let pct = flagged as f64 * 100.0 / total_flows as f64;
        println!("Rate:                  {pct:.1}%");
    }
    Ok(())
}

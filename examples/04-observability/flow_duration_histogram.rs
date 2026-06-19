//! Flow-duration histogram — distribution of how long flows last.
//! Useful for SLO baselining (e.g. "p99 flow lifetime"), tuning
//! idle-timeout config, and finding outlier long-running
//! sessions.
//!
//! Buckets: <100ms, 100ms-1s, 1-10s, 10s-1min, 1-10min, 10min-1h,
//! >1h.
//!
//! Uses [`flowscope::aggregate::Histogram`] (0.10 — plan 102
//! sub-B) for bucketing + quantile estimation.
//!
//! ```bash
//! cargo run --features pcap,aggregate --example flow_duration_histogram
//! ```

use flowscope::{
    FlowEvent, FlowTracker, aggregate::Histogram, extract::FiveTuple, pcap::PcapFlowSource,
};

const LABELS: &[&str] = &[
    "<100ms", "100ms-1s", "1s-10s", "10s-1min", "1-10min", "10-60min", ">1h",
];
const BOUNDARIES: &[f64] = &[0.1, 1.0, 10.0, 60.0, 600.0, 3600.0];

fn main() -> flowscope::Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    let mut tracker = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
    let mut hist = Histogram::with_buckets(BOUNDARIES);

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        for ev in tracker.track(&owned) {
            if let FlowEvent::Ended { stats, .. } = ev {
                hist.record(stats.duration_secs());
            }
        }
    }
    for ev in tracker.finish() {
        if let FlowEvent::Ended { stats, .. } = ev {
            hist.record(stats.duration_secs());
        }
    }

    let total = hist.samples();
    println!("=== Flow duration histogram ({total} flows) ===");
    let buckets: Vec<(f64, u64)> = hist.buckets().collect();
    let max = buckets.iter().map(|(_, c)| *c).max().unwrap_or(1);
    for (label, (_, count)) in LABELS.iter().zip(buckets.iter()) {
        let bar_width = count
            .checked_mul(40)
            .and_then(|n| n.checked_div(max))
            .unwrap_or(0);
        let bar: String = "█".repeat(bar_width as usize);
        let pct = if total == 0 {
            0.0
        } else {
            *count as f64 * 100.0 / total as f64
        };
        println!("  {label:<10} {count:>6} ({pct:>5.1}%) {bar}");
    }
    if total > 0 {
        println!();
        println!(
            "  p50: {:.3}s   p99: {:.3}s   max: {:.3}s",
            hist.quantile(0.50),
            hist.quantile(0.99),
            hist.max(),
        );
    }
    Ok(())
}

//! Flow-duration histogram — distribution of how long flows last.
//! Useful for SLO baselining (e.g. "p99 flow lifetime"), tuning
//! idle-timeout config, and finding outlier long-running
//! sessions.
//!
//! Buckets: <1s, 1-10s, 10s-1min, 1-10min, 10min-1h, >1h.
//!
//! ```bash
//! cargo run --features pcap,extractors,tracker --example flow_duration_histogram
//! ```

use flowscope::extract::FiveTuple;
use flowscope::pcap::PcapFlowSource;
use flowscope::{FlowEvent, FlowTracker};

const BUCKETS: &[(&str, f64)] = &[
    ("<100ms",    0.1),
    ("100ms-1s",  1.0),
    ("1s-10s",   10.0),
    ("10s-1min", 60.0),
    ("1-10min",  600.0),
    ("10-60min", 3600.0),
    (">1h",      f64::INFINITY),
];

fn main() -> flowscope::Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    let mut tracker = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
    let mut counts = vec![0u64; BUCKETS.len()];
    let mut durations: Vec<f64> = Vec::new();

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        for ev in tracker.track(&owned) {
            if let FlowEvent::Ended { stats, .. } = ev {
                let dur =
                    (stats.last_seen.sec as f64 + stats.last_seen.nsec as f64 / 1e9)
                  - (stats.started.sec as f64 + stats.started.nsec as f64 / 1e9);
                let dur = dur.max(0.0);
                durations.push(dur);
                for (i, (_, ceiling)) in BUCKETS.iter().enumerate() {
                    if dur < *ceiling {
                        counts[i] += 1;
                        break;
                    }
                }
            }
        }
    }
    for ev in tracker.finish() {
        if let FlowEvent::Ended { stats, .. } = ev {
            let dur =
                (stats.last_seen.sec as f64 + stats.last_seen.nsec as f64 / 1e9)
              - (stats.started.sec as f64 + stats.started.nsec as f64 / 1e9);
            let dur = dur.max(0.0);
            durations.push(dur);
            for (i, (_, ceiling)) in BUCKETS.iter().enumerate() {
                if dur < *ceiling {
                    counts[i] += 1;
                    break;
                }
            }
        }
    }

    let total: u64 = counts.iter().sum();
    println!("=== Flow duration histogram ({total} flows) ===");
    let max = *counts.iter().max().unwrap_or(&1);
    for ((label, _), &c) in BUCKETS.iter().zip(counts.iter()) {
        let bar_width = c.checked_mul(40).and_then(|n| n.checked_div(max)).unwrap_or(0);
        let bar: String = "█".repeat(bar_width as usize);
        let pct = if total == 0 {
            0.0
        } else {
            c as f64 * 100.0 / total as f64
        };
        println!("  {label:<10} {c:>6} ({pct:>5.1}%) {bar}");
    }
    if !durations.is_empty() {
        durations.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let p50 = durations[durations.len() / 2];
        let p99 = durations[(durations.len() * 99) / 100];
        let max = durations.last().copied().unwrap_or(0.0);
        println!();
        println!("  p50: {p50:.3}s   p99: {p99:.3}s   max: {max:.3}s");
    }
    Ok(())
}

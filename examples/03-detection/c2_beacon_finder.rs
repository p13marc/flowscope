//! C2 beacon finder — replay a pcap and flag flow keys that
//! score as periodic beacons via
//! [`flowscope::detect::patterns::BeaconDetector`].
//!
//! Run with:
//!
//! ```bash
//! cargo run --features pcap,extractors,tracker \
//!     --example c2_beacon_finder -- trace.pcap
//! ```
//!
//! The detector requires ≥ 10 observations per key and mean
//! inter-arrival in the [10 s, 24 h] band before scoring. Short
//! pcaps may produce no hits — that's the chatty-flow suppressor
//! working, not a bug.

use std::collections::HashMap;

use flowscope::FlowTracker;
use flowscope::detect::patterns::{BeaconDetector, BeaconScore};
use flowscope::extract::{FiveTuple, FiveTupleKey};
use flowscope::pcap::PcapFlowSource;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    let mut tracker = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
    let mut detector: BeaconDetector<FiveTupleKey> = BeaconDetector::new();

    // Track best score per flow key.
    let mut best: HashMap<FiveTupleKey, BeaconScore<FiveTupleKey>> = HashMap::new();
    let mut packet_count = 0u64;

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        packet_count += 1;
        for ev in tracker.track(&owned) {
            if let flowscope::FlowEvent::Packet { key, len, ts, .. } = ev
                && let Some(score) = detector.observe(key, ts, len as u64)
                && best
                    .get(&key)
                    .map(|s| score.score > s.score)
                    .unwrap_or(true)
            {
                best.insert(key, score);
            }
        }
    }

    let mut hits: Vec<_> = best.values().collect();
    hits.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    println!(
        "# c2_beacon_finder — {packet_count} packets, {} candidates",
        hits.len()
    );
    if hits.is_empty() {
        println!("# (no beacon-candidates — pcap probably too short for the 10-observation gate)");
        return Ok(());
    }
    println!("# fields: score, mean_interval_s, cv_dt, cv_bytes, n, key");
    for h in hits.iter().take(20) {
        println!(
            "{:.3}\t{:.2}\t{:.3}\t{:.3}\t{}\t{:?}",
            h.score,
            h.mean_interval.as_secs_f64(),
            h.cv_dt,
            h.cv_bytes,
            h.n,
            h.key,
        );
    }
    Ok(())
}

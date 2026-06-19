//! Top-K source IPs by byte count using
//! [`flowscope::correlate::TopK`] (Misra-Gries) — bounded-memory
//! variant of `top_talkers.rs`.
//!
//! Unlike the original which keeps a HashMap of every IP it sees
//! (memory ∝ distinct IPs), this version caps the tracked set at
//! a fixed `K`. Above that, low-frequency keys are squeezed out
//! by the Misra-Gries algorithm — exact counts for the top
//! talkers, bounded approximation for the long tail.
//!
//! Plan 102 sub-A.
//!
//! ```bash
//! cargo run --features pcap,extractors,tracker --example top_talkers_topk
//! ```

use std::net::IpAddr;

use flowscope::{
    FlowEvent, FlowTracker, correlate::TopK, extract::FiveTuple, pcap::PcapFlowSource,
};

const K: usize = 32;

fn main() -> flowscope::Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    let mut tracker = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
    let mut by_bytes: TopK<IpAddr> = TopK::new(K);
    let mut by_packets: TopK<IpAddr> = TopK::new(K);

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        for ev in tracker.track(&owned) {
            if let FlowEvent::Ended { key, stats, .. } = ev {
                let src = key.a.ip();
                by_bytes.observe_n(src, stats.total_bytes());
                by_packets.observe_n(src, stats.total_packets());
            }
        }
    }
    for ev in tracker.finish() {
        if let FlowEvent::Ended { key, stats, .. } = ev {
            let src = key.a.ip();
            by_bytes.observe_n(src, stats.total_bytes());
            by_packets.observe_n(src, stats.total_packets());
        }
    }

    println!("=== Top {K} by bytes (Misra-Gries TopK) ===");
    for (rank, (ip, bytes)) in by_bytes.top().iter().enumerate() {
        println!("  {:>2}. {:<40} {:>12} bytes", rank + 1, ip, bytes);
    }
    println!();
    println!("=== Top {K} by packets (Misra-Gries TopK) ===");
    for (rank, (ip, packets)) in by_packets.top().iter().enumerate() {
        println!("  {:>2}. {:<40} {:>12} packets", rank + 1, ip, packets);
    }
    Ok(())
}

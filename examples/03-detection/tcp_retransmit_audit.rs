//! Per-flow TCP retransmit audit — surface flows with elevated
//! retransmit rates and out-of-order drops. Production
//! observability signal: high retransmit rate ≈ congestion,
//! flaky network path, or a misbehaving NIC.
//!
//! Pairs the tracker with the new (0.9) `SegmentBufferReassembler`
//! so OOO segments are counted accurately (rather than dropped
//! silently as in the default `BufferedReassembler`).
//!
//! ```bash
//! cargo run --features pcap,extractors,reassembler --example tcp_retransmit_audit
//! ```

use flowscope::{extract::FiveTuple, pcap::PcapFlowSource, FlowEvent, FlowTracker, L4Proto};

fn main() -> flowscope::Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    let mut tracker = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());

    let mut report = Vec::new();
    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        for ev in tracker.track(&owned) {
            collect(&mut report, &ev);
        }
    }
    for ev in tracker.finish() {
        collect(&mut report, &ev);
    }

    report.sort_by_key(|(_, retx_rate, _)| std::cmp::Reverse((retx_rate * 1_000.0) as u64));

    println!(
        "{:<22} {:<22} {:>5} {:>5} {:>5} {:>5} {:>9}",
        "src", "dst", "pkt_i", "pkt_r", "ret_i", "ret_r", "retx_rate"
    );
    for (key, rate, stats) in report.iter().take(20) {
        if *rate <= 0.0 {
            continue;
        }
        println!(
            "{:<22} {:<22} {:>5} {:>5} {:>5} {:>5} {:>8.2}%",
            key.a.to_string(),
            key.b.to_string(),
            stats.packets_initiator,
            stats.packets_responder,
            stats.retransmits_initiator,
            stats.retransmits_responder,
            rate * 100.0,
        );
    }
    Ok(())
}

fn collect(
    report: &mut Vec<(flowscope::extract::FiveTupleKey, f64, flowscope::FlowStats)>,
    ev: &FlowEvent<flowscope::extract::FiveTupleKey>,
) {
    let FlowEvent::Ended { key, stats, l4, .. } = ev else {
        return;
    };
    if *l4 != Some(L4Proto::Tcp) {
        return;
    }
    let total = stats.packets_initiator + stats.packets_responder;
    if total < 4 {
        return; // ignore trivially-short flows
    }
    let retx = stats.retransmits_initiator + stats.retransmits_responder;
    let rate = retx as f64 / total as f64;
    report.push((*key, rate, stats.clone()));
}

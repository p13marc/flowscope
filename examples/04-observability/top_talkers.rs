//! Top-N source IPs by bytes and packets — classic SRE / capacity-
//! planning summary.
//!
//! Reads a pcap, runs flows through a tracker with `FiveTuple`, and
//! on each `FlowEvent::Ended` aggregates the flow's totals into a
//! per-source-IP rollup. At end of input, prints the top 10 by
//! bytes and the top 10 by packets.
//!
//! ```bash
//! cargo run --features pcap,extractors,tracker --example top_talkers
//! ```

use std::{collections::HashMap, net::IpAddr};

use flowscope::{FlowEvent, FlowTracker, extract::FiveTuple, pcap::PcapFlowSource};

#[derive(Default, Clone, Copy)]
struct Rollup {
    bytes_init: u64,
    bytes_resp: u64,
    packets_init: u64,
    packets_resp: u64,
    flows: u64,
}

impl Rollup {
    fn total_bytes(&self) -> u64 {
        self.bytes_init + self.bytes_resp
    }
    fn total_packets(&self) -> u64 {
        self.packets_init + self.packets_resp
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    let mut tracker = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
    let mut rollup: HashMap<IpAddr, Rollup> = HashMap::new();

    let mut last_ts = None;
    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        last_ts = Some(owned.timestamp);
        for ev in tracker.track(&owned) {
            account(&mut rollup, &ev);
        }
    }
    // Flush any flows that didn't close cleanly.
    if let Some(ts) = last_ts {
        for ev in tracker.finish() {
            account(&mut rollup, &ev);
        }
        let _ = ts;
    }

    print_topn(
        &rollup,
        "Top 10 talkers by bytes",
        |r| r.total_bytes(),
        |r| {
            format!(
                "{:>12} bytes ({:>5} flows, init→{} resp→{})",
                r.total_bytes(),
                r.flows,
                r.bytes_init,
                r.bytes_resp,
            )
        },
    );
    println!();
    print_topn(
        &rollup,
        "Top 10 talkers by packets",
        |r| r.total_packets(),
        |r| format!("{:>8} pkts ({:>5} flows)", r.total_packets(), r.flows,),
    );
    Ok(())
}

fn account(rollup: &mut HashMap<IpAddr, Rollup>, ev: &FlowEvent<flowscope::extract::FiveTupleKey>) {
    let FlowEvent::Ended { key, stats, .. } = ev else {
        return;
    };
    let entry = rollup.entry(key.a.ip()).or_default();
    entry.bytes_init += stats.bytes_initiator;
    entry.bytes_resp += stats.bytes_responder;
    entry.packets_init += stats.packets_initiator;
    entry.packets_resp += stats.packets_responder;
    entry.flows += 1;
}

fn print_topn<F, S>(rollup: &HashMap<IpAddr, Rollup>, title: &str, sort_key: F, fmt: S)
where
    F: Fn(&Rollup) -> u64,
    S: Fn(&Rollup) -> String,
{
    println!("{title}");
    let mut sorted: Vec<(&IpAddr, &Rollup)> = rollup.iter().collect();
    sorted.sort_by_key(|(_, r)| std::cmp::Reverse(sort_key(r)));
    for (rank, (ip, r)) in sorted.iter().take(10).enumerate() {
        println!("  #{:>2} {:<18} {}", rank + 1, ip.to_string(), fmt(r));
    }
}

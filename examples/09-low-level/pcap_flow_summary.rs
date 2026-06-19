//! Sync flow tracking over a pcap input.
//!
//! Reads a pcap file, runs every frame through a `FlowTracker` with
//! a `FiveTuple::bidirectional()` extractor, and prints a one-line
//! summary for each ended flow. Demonstrates that `netring-flow`
//! works without `netring` and without tokio.
//!
//! Usage:
//!     cargo run -p netring-flow --example pcap_flow_summary -- trace.pcap

use std::{env, fs::File, io::BufReader};

use flowscope::{extract::FiveTuple, FlowEvent, FlowTracker, PacketView, Timestamp};
use pcap_file::pcap::PcapReader;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args()
        .nth(1)
        .ok_or("usage: pcap_flow_summary <trace.pcap>")?;
    let file = File::open(&path)?;
    let mut reader = PcapReader::new(BufReader::new(file))?;
    let mut tracker = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());

    let mut packets = 0usize;
    let mut started = 0usize;
    let mut ended = 0usize;

    while let Some(pkt) = reader.next_packet() {
        let pkt = pkt?;
        packets += 1;
        let ts = Timestamp::new(pkt.timestamp.as_secs() as u32, pkt.timestamp.subsec_nanos());
        let view = PacketView::new(&pkt.data, ts);
        for evt in tracker.track(view) {
            match evt {
                FlowEvent::Started { key, l4, ts, .. } => {
                    started += 1;
                    println!("[{ts}] + {l4:?} {a} <-> {b}", l4 = l4, a = key.a, b = key.b);
                }
                FlowEvent::Ended {
                    key,
                    reason,
                    stats,
                    history,
                    ..
                } => {
                    ended += 1;
                    let total_pkts = stats.packets_initiator + stats.packets_responder;
                    let total_bytes = stats.bytes_initiator + stats.bytes_responder;
                    println!(
                        "      - {a} <-> {b}  reason={reason:?}  pkts={total_pkts}  bytes={total_bytes}  history={history}",
                        a = key.a,
                        b = key.b,
                    );
                }
                _ => {}
            }
        }
    }

    // Force the remaining flows to end with a max-timestamp sweep.
    for evt in tracker.sweep(Timestamp::MAX) {
        if let FlowEvent::Ended {
            key,
            stats,
            history,
            ..
        } = evt
        {
            ended += 1;
            let total_pkts = stats.packets_initiator + stats.packets_responder;
            let total_bytes = stats.bytes_initiator + stats.bytes_responder;
            println!(
                "      - {a} <-> {b}  reason=IdleTimeout  pkts={total_pkts}  bytes={total_bytes}  history={history}",
                a = key.a,
                b = key.b,
            );
        }
    }

    eprintln!("\n--- summary: {packets} packets, {started} flows started, {ended} flows ended");
    Ok(())
}

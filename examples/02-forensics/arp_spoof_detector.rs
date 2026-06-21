//! ARP spoof detector: monitors a network for IP→MAC binding
//! changes and flags the classic ARP-cache-poisoning patterns
//! (gratuitous replies asserting ownership of another host's IP).
//!
//! Demonstrates the issue #1 (0.17) surface:
//! - [`flowscope::arp::parse_frame`] (stateless wire parser).
//! - [`flowscope::ArpMessage`] + [`flowscope::ArpOp`].
//! - [`flowscope::ArpMessage::is_likely_spoof`] (classifier).
//! - [`flowscope::MacAddr`] (typed link-layer address).
//! - [`flowscope::correlate::NeighborTable`] (binding tracker
//!   with TTL + LRU bounds; emits
//!   [`flowscope::correlate::NeighborEvent::Changed`] on
//!   rebinds).
//!
//! ```bash
//! cargo run --features arp,pcap --example arp_spoof_detector -- trace.pcap
//! ```

use std::{net::Ipv4Addr, time::Duration};

use flowscope::{
    ArpMessage, MacAddr, Timestamp, arp,
    correlate::{NeighborEvent, NeighborTable},
    pcap::PcapFlowSource,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    // 5-minute binding TTL — standard for an ARP cache. The
    // table is generic; behind the `arp` feature `ArpTable` is
    // the IPv4 + MacAddr alias.
    let mut table: NeighborTable<Ipv4Addr, MacAddr> =
        NeighborTable::new_unbounded(Duration::from_secs(300));

    let mut arp_count = 0usize;
    let mut spoof_count = 0usize;
    let mut rebind_count = 0usize;

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        let frame = &owned.frame[..];
        let Some(msg) = arp::parse_frame(frame) else {
            continue;
        };
        arp_count += 1;
        let ts = Timestamp::new(owned.timestamp.sec, owned.timestamp.nsec);

        report_classifier(&msg);
        if msg.is_likely_spoof() {
            spoof_count += 1;
        }

        if let NeighborEvent::Changed { prior, new } = table.observe(msg.sender_ip, msg.sender, ts)
        {
            rebind_count += 1;
            println!(
                "rebind  {} : {prior} -> {new}  (sender_op = {})",
                msg.sender_ip,
                msg.oper.as_str(),
            );
        }
    }

    println!();
    println!("=== summary ===");
    println!("ARP messages parsed:     {arp_count}");
    println!("Likely-spoof flagged:    {spoof_count}");
    println!("Distinct IP→MAC rebinds: {rebind_count}");
    println!("Final neighbor cache:    {} bindings", table.len());
    Ok(())
}

fn report_classifier(msg: &ArpMessage) {
    if msg.is_likely_spoof() {
        println!(
            "SPOOF   {} <-> {} : sender={} target={}",
            msg.sender_ip, msg.target_ip, msg.sender, msg.target,
        );
    } else if msg.is_gratuitous() {
        // Legit announcement — useful operational signal but
        // not an alert.
        println!(
            "gratuit {} sender={} ({})",
            msg.sender_ip,
            msg.sender,
            msg.oper.as_str(),
        );
    }
}

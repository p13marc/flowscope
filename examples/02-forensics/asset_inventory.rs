//! Build a passive asset inventory from a pcap.
//!
//! Walks a pcap once, feeding ARP messages into the
//! `Asset::from_arp` adapter, accumulating into a MAC-keyed
//! [`flowscope::asset::Inventory`]. At end-of-file, prints one
//! row per discovered host with its IP, hostname (if known),
//! and the contributing-source bitflag.
//!
//! Why MAC-keyed: asset identity is link-layer. Across a DHCP
//! lease cycle a host's IP changes; its MAC doesn't. Across
//! mDNS responses, the same host advertises multiple services
//! with one MAC. The composition layer keeps them stitched.
//!
//! ## Usage
//!
//! ```bash
//! cargo run --features "asset,arp,pcap" \
//!     --example asset_inventory -- trace.pcap
//! ```
//!
//! ## Extension points
//!
//! For DHCP / LLDP / mDNS / NetBIOS-NS sources, the same
//! pattern applies — call `Asset::from_dhcp` /
//! `from_lldp` / `from_mdns` and `inventory.absorb(asset)`.
//! Real consumers walk all sources in one pass via a typed
//! `Driver` with multiple datagram/session parsers
//! registered.
//!
//! Closes #41.

use flowscope::Asset;
use flowscope::arp;
use flowscope::asset::Inventory;
use flowscope::pcap::PcapFlowSource;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: asset_inventory <trace.pcap>")?;

    let mut inventory = Inventory::new(4096);
    let mut arp_count = 0u64;

    for view in PcapFlowSource::open(&path)?.views() {
        let view = view?;
        let Ok(msg) = arp::parse_frame(&view.frame) else {
            continue;
        };
        arp_count += 1;
        inventory.absorb(Asset::from_arp(&msg));
    }

    println!(
        "--- Inventory ({} assets, cap={}, from {arp_count} ARP messages) ---",
        inventory.len(),
        inventory.capacity(),
    );
    println!("{:<19} {:<16} {:<24} sources", "MAC", "IPv4", "hostname");
    for (mac, asset) in inventory.iter() {
        let ip = asset
            .ipv4
            .first()
            .map(|i| i.to_string())
            .unwrap_or_else(|| "-".to_string());
        let hostname = asset.hostname.as_deref().unwrap_or("-");
        println!("{mac} {ip:<16} {hostname:<24} {:?}", asset.seen_via);
    }
    Ok(())
}

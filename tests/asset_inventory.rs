//! Issue #27 — asset-inventory composition module integration
//! tests. Builds parser inputs from wire bytes (parser message
//! types are `#[non_exhaustive]` and can't be struct-literal'd
//! from outside the crate), parses them, and feeds the
//! resulting messages through the adapter functions into an
//! [`Inventory`].

#![cfg(all(
    feature = "asset",
    feature = "arp",
    feature = "ndp",
    feature = "dhcp",
    feature = "cdp",
    feature = "ssdp",
))]

use std::net::Ipv4Addr;

use flowscope::MacAddr;
use flowscope::asset::{Asset, AssetCapabilities, AssetSourceSet, Inventory};

const TEST_MAC: MacAddr = MacAddr([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);

// ── ARP wire-format builders ──────────────────────────────

fn arp_request_bytes(sender: MacAddr, sender_ip: [u8; 4]) -> Vec<u8> {
    let mut p = Vec::with_capacity(28);
    p.extend_from_slice(&[0x00, 0x01]); // htype = Ethernet
    p.extend_from_slice(&[0x08, 0x00]); // ptype = IPv4
    p.push(6); // hlen
    p.push(4); // plen
    p.extend_from_slice(&[0x00, 0x01]); // op = request
    p.extend_from_slice(&sender.0);
    p.extend_from_slice(&sender_ip);
    p.extend_from_slice(&[0u8; 6]); // target hw
    p.extend_from_slice(&[10, 0, 0, 1]); // target ip
    p
}

// ── NDP wire-format builders ──────────────────────────────

fn ndp_advert_bytes(target: [u8; 16], lladdr: MacAddr) -> Vec<u8> {
    // ICMPv6 header: type=136 NA, code=0, checksum=0.
    let mut p = vec![136, 0, 0, 0];
    // NA body: flags(1) + reserved(3) + target(16).
    p.push(0x40); // S flag = solicited
    p.extend_from_slice(&[0, 0, 0]);
    p.extend_from_slice(&target);
    // Target Link-Layer Address option (type=2, len=1).
    p.push(2);
    p.push(1);
    p.extend_from_slice(&lladdr.0);
    p
}

// ── DHCP wire-format builders ─────────────────────────────

fn dhcp_request_bytes(mac: MacAddr, hostname: &str, vendor: &str, prl: &[u8]) -> Vec<u8> {
    // BOOTP fixed header (236 bytes).
    let mut p = vec![0u8; 236];
    p[0] = 1; // BootRequest
    p[1] = 1; // htype = Ethernet
    p[2] = 6; // hlen
    p[4..8].copy_from_slice(&0xdeadbeefu32.to_be_bytes()); // xid
    // yiaddr = 10.0.0.5
    p[16..20].copy_from_slice(&[10, 0, 0, 5]);
    p[28..34].copy_from_slice(&mac.0);
    // Magic cookie.
    p.extend_from_slice(&[99, 130, 83, 99]);
    // opt 53 = DHCPREQUEST (3).
    p.extend_from_slice(&[53, 1, 3]);
    // opt 12 hostname.
    p.push(12);
    p.push(hostname.len() as u8);
    p.extend_from_slice(hostname.as_bytes());
    // opt 60 vendor class.
    p.push(60);
    p.push(vendor.len() as u8);
    p.extend_from_slice(vendor.as_bytes());
    // opt 55 parameter request list.
    p.push(55);
    p.push(prl.len() as u8);
    p.extend_from_slice(prl);
    p.push(255); // END
    p
}

// ── SSDP wire-format builders ─────────────────────────────

fn ssdp_notify_payload(server: &str) -> Vec<u8> {
    format!(
        "NOTIFY * HTTP/1.1\r\n\
         HOST: 239.255.255.250:1900\r\n\
         CACHE-CONTROL: max-age=1800\r\n\
         LOCATION: http://10.0.0.50:80/desc.xml\r\n\
         NT: upnp:rootdevice\r\n\
         NTS: ssdp:alive\r\n\
         SERVER: {server}\r\n\
         USN: uuid:550e8400::upnp:rootdevice\r\n\
         \r\n"
    )
    .into_bytes()
}

// ── Tests ──────────────────────────────────────────────────

#[test]
fn arp_alone_records_mac_and_ipv4() {
    let arp = flowscope::arp::parse(&arp_request_bytes(TEST_MAC, [10, 0, 0, 5])).unwrap();
    let mut inv = Inventory::new(16);
    inv.absorb(Asset::from_arp(&arp));
    let a = inv.get(&TEST_MAC).unwrap();
    assert_eq!(a.mac, TEST_MAC);
    assert_eq!(a.ipv4, vec![Ipv4Addr::new(10, 0, 0, 5)]);
    assert!(a.ipv6.is_empty());
    assert_eq!(a.seen_via, AssetSourceSet::ARP);
}

#[test]
fn ndp_contributes_ipv6_binding() {
    let target = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x05,
    ];
    let frame = ndp_advert_bytes(target, TEST_MAC);
    let ndp = flowscope::ndp::parse_icmpv6(&frame).unwrap();
    let mut inv = Inventory::new(16);
    inv.absorb(Asset::from_ndp(&ndp).unwrap());
    let a = inv.get(&TEST_MAC).unwrap();
    assert_eq!(a.ipv6.len(), 1);
    assert!(a.seen_via.contains(AssetSourceSet::NDP));
}

#[test]
fn dhcp_contributes_hostname_vendor_and_fingerprint() {
    let frame = dhcp_request_bytes(
        TEST_MAC,
        "workstation-01",
        "MSFT 5.0",
        &[1, 3, 6, 15, 33, 253],
    );
    let dhcp = flowscope::dhcp::parse(&frame).unwrap();
    let mut inv = Inventory::new(16);
    inv.absorb(Asset::from_dhcp(&dhcp).unwrap());
    let a = inv.get(&TEST_MAC).unwrap();
    assert_eq!(a.hostname.as_deref(), Some("workstation-01"));
    assert_eq!(a.vendor_banner.as_deref(), Some("MSFT 5.0"));
    assert_eq!(
        a.fingerprints.dhcp.as_deref(),
        Some("1,3,6,15,33,253|MSFT 5.0")
    );
    assert!(a.seen_via.contains(AssetSourceSet::DHCP));
}

#[test]
fn arp_then_ndp_then_dhcp_merge_into_single_asset() {
    let mut inv = Inventory::new(16);

    let arp = flowscope::arp::parse(&arp_request_bytes(TEST_MAC, [10, 0, 0, 5])).unwrap();
    inv.absorb(Asset::from_arp(&arp));

    let target = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x05,
    ];
    let ndp = flowscope::ndp::parse_icmpv6(&ndp_advert_bytes(target, TEST_MAC)).unwrap();
    inv.absorb(Asset::from_ndp(&ndp).unwrap());

    let dhcp = flowscope::dhcp::parse(&dhcp_request_bytes(
        TEST_MAC,
        "workstation-01",
        "MSFT 5.0",
        &[1, 3, 6, 15, 33, 253],
    ))
    .unwrap();
    inv.absorb(Asset::from_dhcp(&dhcp).unwrap());

    assert_eq!(inv.len(), 1, "all three contribute to same MAC entry");
    let a = inv.get(&TEST_MAC).unwrap();
    assert!(a.ipv4.contains(&Ipv4Addr::new(10, 0, 0, 5)));
    assert_eq!(a.ipv6.len(), 1);
    assert_eq!(a.hostname.as_deref(), Some("workstation-01"));
    assert_eq!(a.vendor_banner.as_deref(), Some("MSFT 5.0"));
    let expected = AssetSourceSet::ARP | AssetSourceSet::NDP | AssetSourceSet::DHCP;
    assert_eq!(a.seen_via, expected);
    assert!(a.capabilities.contains(AssetCapabilities::HOST));
}

#[test]
fn ssdp_records_upnp_banner_and_capability() {
    let payload = ssdp_notify_payload("Linux/4.19 UPnP/1.0 IGD/1.1");
    let ssdp = flowscope::ssdp::parse(&payload).unwrap();
    let mut inv = Inventory::new(16);
    inv.absorb(Asset::from_ssdp(&ssdp, TEST_MAC));
    let a = inv.get(&TEST_MAC).unwrap();
    assert_eq!(
        a.vendor_banner.as_deref(),
        Some("Linux/4.19 UPnP/1.0 IGD/1.1")
    );
    assert!(a.capabilities.contains(AssetCapabilities::UPNP));
    assert!(a.seen_via.contains(AssetSourceSet::SSDP));
}

#[test]
fn many_macs_below_capacity_all_kept() {
    let mut inv = Inventory::new(8);
    for i in 1..=5 {
        let mac = MacAddr([i, i, i, i, i, i]);
        let arp = flowscope::arp::parse(&arp_request_bytes(mac, [10, 0, 0, i])).unwrap();
        inv.absorb(Asset::from_arp(&arp));
    }
    assert_eq!(inv.len(), 5);
}

#[test]
fn ndp_without_lladdr_returns_no_asset() {
    let target = [0u8; 16];
    // NA with no Target LL Address option.
    let mut frame = vec![136, 0, 0, 0, 0x40, 0, 0, 0];
    frame.extend_from_slice(&target);
    let ndp = flowscope::ndp::parse_icmpv6(&frame).unwrap();
    assert!(Asset::from_ndp(&ndp).is_none());
}

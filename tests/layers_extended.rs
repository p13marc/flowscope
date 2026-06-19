//! Plan 94 Tier 3 extensions — tunnels (VXLAN/GTP-U/GRE/IP-in-IP)
//! + ARP/MPLS/ICMP slices.

#![cfg(all(feature = "extractors", feature = "test-helpers"))]

use flowscope::{
    extract::parse::test_frames::{ipv4_tcp, ipv4_udp},
    layers::{Layer, LayerKind, Layers},
};

// ─── ARP ─────────────────────────────────────────────────────────

fn arp_request_frame() -> Vec<u8> {
    let mut f = vec![0u8; 14 + 28];
    f[0..6].copy_from_slice(&[0xff; 6]); // dst MAC = broadcast
    f[6..12].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    f[12..14].copy_from_slice(&0x0806u16.to_be_bytes()); // ARP ethertype
                                                         // ARP header
    f[14..16].copy_from_slice(&1u16.to_be_bytes()); // HTYPE = Ethernet
    f[16..18].copy_from_slice(&0x0800u16.to_be_bytes()); // PTYPE = IPv4
    f[18] = 6; // HLEN
    f[19] = 4; // PLEN
    f[20..22].copy_from_slice(&1u16.to_be_bytes()); // OPER = request
                                                    // SHA + SPA + THA + TPA
    f[22..28].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    f[28..32].copy_from_slice(&[192, 168, 1, 100]);
    f[32..38].copy_from_slice(&[0; 6]);
    f[38..42].copy_from_slice(&[192, 168, 1, 1]);
    f
}

#[test]
fn arp_request_is_recognized() {
    let f = arp_request_frame();
    let layers = Layers::parse_ethernet(&f).unwrap();
    let arp = layers.arp().expect("ARP slice");
    assert_eq!(arp.htype(), 1);
    assert_eq!(arp.ptype(), 0x0800);
    assert_eq!(arp.oper(), 1);
    assert_eq!(
        arp.sender_pa().unwrap(),
        std::net::Ipv4Addr::new(192, 168, 1, 100)
    );
    assert_eq!(
        arp.target_pa().unwrap(),
        std::net::Ipv4Addr::new(192, 168, 1, 1)
    );
    // ARP frames have no L3/L4.
    assert!(layers.ipv4().is_none());
    assert!(layers.tcp().is_none());
}

// ─── VXLAN tunnel ────────────────────────────────────────────────

fn vxlan_wrapped_frame() -> Vec<u8> {
    // Build: outer Eth + IPv4 + UDP(dst=4789) + VXLAN(VNI=42) +
    //        inner Eth + IPv4 + TCP
    let inner = ipv4_tcp(
        [11; 6],
        [12; 6],
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        12345,
        80,
        1000,
        0,
        0x02,
        b"",
    );
    // VXLAN header: flags 0x08 (Valid), 3-byte reserved, 3-byte VNI=42, 1-byte reserved
    let mut vxlan = vec![0x08, 0, 0, 0, 0, 0, 0x2a, 0];
    vxlan.extend_from_slice(&inner);
    // Outer UDP -> wrap in outer IPv4+Eth
    ipv4_udp([192, 168, 0, 1], [192, 168, 0, 2], 33333, 4789, &vxlan)
}

#[test]
fn vxlan_walk_finds_inner_layers() {
    let f = vxlan_wrapped_frame();
    let layers = Layers::parse_ethernet(&f).unwrap();
    assert!(layers.has_tunnel(), "should detect tunnel");
    // Outer IPv4 + inner IPv4 = 2 IPv4 layers
    let ipv4_count = layers.find_all(LayerKind::Ipv4).count();
    assert_eq!(ipv4_count, 2, "outer + inner IPv4 expected");
    // VXLAN slice present
    let vx = layers.vxlan().expect("VXLAN slice");
    assert_eq!(vx.vni(), 42);
    // Inner TCP recognized
    let tcp = layers.tcp().expect("inner TCP");
    assert_eq!(tcp.src_port(), 12345);
}

// ─── IP-in-IP ────────────────────────────────────────────────────

fn ipv4_in_ipv4_frame() -> Vec<u8> {
    use etherparse::{EtherType, Ethernet2Header, IpNumber, Ipv4Header};

    let inner = ipv4_tcp(
        [0; 6],
        [0; 6],
        [10, 1, 0, 1],
        [10, 1, 0, 2],
        80,
        443,
        0,
        0,
        0x02,
        b"hi",
    );
    // Strip the inner Ethernet header — IP-in-IP encapsulates an IP packet.
    let inner_ip_plus = &inner[14..];

    let outer_ip = Ipv4Header::new(
        inner_ip_plus.len() as u16,
        64,
        IpNumber(IP_PROTO_IPV4_OUTER),
        [192, 168, 0, 1],
        [192, 168, 0, 2],
    )
    .unwrap();
    let eth = Ethernet2Header {
        destination: [0; 6],
        source: [0; 6],
        ether_type: EtherType::IPV4,
    };
    let mut out = Vec::new();
    eth.write(&mut out).unwrap();
    outer_ip.write(&mut out).unwrap();
    out.extend_from_slice(inner_ip_plus);
    out
}

const IP_PROTO_IPV4_OUTER: u8 = 4;

#[test]
fn ipv4_in_ipv4_recognized_as_tunnel() {
    let f = ipv4_in_ipv4_frame();
    let layers = Layers::parse_ethernet(&f).unwrap();
    assert!(layers.has_tunnel(), "should detect IP-in-IP tunnel");
    let ipv4_count = layers.find_all(LayerKind::Ipv4).count();
    assert_eq!(ipv4_count, 2);
}

// ─── Truncated tunnel inner ──────────────────────────────────────

#[test]
fn truncated_inner_keeps_outer_layers() {
    // Build a VXLAN frame with a deliberately short inner payload.
    let mut vxlan = vec![0x08u8, 0, 0, 0, 0, 0, 0x2a, 0];
    vxlan.extend_from_slice(&[0, 0, 0, 0]); // 4 bytes of inner — won't parse
    let f = ipv4_udp([192, 168, 0, 1], [192, 168, 0, 2], 33333, 4789, &vxlan);
    let layers = Layers::parse_ethernet(&f).unwrap();
    // Outer layers still accessible.
    assert!(layers.ipv4().is_some());
    assert!(layers.udp().is_some());
    assert!(layers.vxlan().is_some());
    // truncated() flag set because inner re-parse failed.
    assert!(layers.truncated());
}

// ─── ICMP ────────────────────────────────────────────────────────

fn icmp_echo_frame() -> Vec<u8> {
    use etherparse::{EtherType, Ethernet2Header, IpNumber, Ipv4Header};

    // ICMP echo request: type=8, code=0, checksum, id, seq, data
    let icmp = vec![
        8, 0, // type 8, code 0
        0, 0, // checksum (zero — etherparse won't validate)
        0x12, 0x34, // id
        0, 1, // seq
        b'h', b'i',
    ];
    let ip = Ipv4Header::new(
        icmp.len() as u16,
        64,
        IpNumber(1), // ICMP
        [10, 0, 0, 1],
        [10, 0, 0, 2],
    )
    .unwrap();
    let eth = Ethernet2Header {
        destination: [0; 6],
        source: [0; 6],
        ether_type: EtherType::IPV4,
    };
    let mut out = Vec::new();
    eth.write(&mut out).unwrap();
    ip.write(&mut out).unwrap();
    out.extend_from_slice(&icmp);
    out
}

#[test]
fn icmpv4_slice_exposes_type_and_code() {
    let f = icmp_echo_frame();
    let layers = Layers::parse_ethernet(&f).unwrap();
    let icmp = layers.icmpv4().expect("ICMPv4 slice");
    assert_eq!(icmp.icmp_type(), 8);
    assert_eq!(icmp.code(), 0);
    // L4 group should pick ICMPv4.
    assert!(matches!(layers.l4().unwrap(), Layer::Icmpv4(_)));
}

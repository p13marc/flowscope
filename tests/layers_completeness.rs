//! Issue #22 (Release A) — MPLS inner-IP re-parse + IPv6
//! extension-header walking + fragment-signal coverage.

#![cfg(feature = "extractors")]

use flowscope::layers::{Layer, LayerKind, Layers};

// ─── MPLS inner-IP re-parse ──────────────────────────────

/// Build a minimal Ethernet+MPLS+IPv4 frame.
///
/// EtherType=0x8847 (MPLS unicast), one MPLS label (BOS=1),
/// then a 20-byte IPv4 header + 8-byte payload.
fn build_mpls_ipv4_frame() -> Vec<u8> {
    let mut f = Vec::new();
    // Ethernet
    f.extend_from_slice(&[0u8; 6]); // dst
    f.extend_from_slice(&[0u8; 6]); // src
    f.extend_from_slice(&[0x88, 0x47]); // EtherType = MPLS unicast
    // One MPLS label entry — label=100, TC=0, BOS=1, TTL=64
    // label[19:0] | TC[3] | BOS[1] | TTL[8]
    // label 100 = 0x064 → top-20 bits of 32-bit word
    f.extend_from_slice(&[0x00, 0x06, 0x41, 0x40]);
    // IPv4 header (20 bytes) — minimal: version=4, IHL=5, no opts
    f.push(0x45); // version=4, IHL=5
    f.push(0x00); // TOS
    f.extend_from_slice(&[0x00, 40]); // total length = 40 (20 IP + 20 TCP)
    f.extend_from_slice(&[0; 2]); // identification
    f.extend_from_slice(&[0; 2]); // flags + frag offset
    f.push(64); // TTL
    f.push(6); // protocol = TCP
    f.extend_from_slice(&[0; 2]); // header checksum (don't care)
    f.extend_from_slice(&[10, 0, 0, 1]); // src IP
    f.extend_from_slice(&[10, 0, 0, 2]); // dst IP
    // 8 bytes of "TCP" payload (fake)
    f.extend_from_slice(&[0xAB; 8]);
    f
}

#[test]
fn mpls_inner_ipv4_is_reparsed() {
    let f = build_mpls_ipv4_frame();
    let layers = Layers::parse_ethernet(&f).expect("parse");
    // Expected stack: Ethernet, Mpls, Ipv4
    let kinds: Vec<LayerKind> = layers.iter().map(|l| l.kind()).collect();
    assert!(
        kinds.contains(&LayerKind::Mpls),
        "MPLS layer missing: {kinds:?}"
    );
    assert!(
        kinds.contains(&LayerKind::Ipv4),
        "inner IPv4 NOT re-parsed (this is what issue #22 fixed): {kinds:?}"
    );
}

/// Build a minimal Ethernet+MPLS+IPv6 frame.
fn build_mpls_ipv6_frame() -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0u8; 6]); // dst
    f.extend_from_slice(&[0u8; 6]); // src
    f.extend_from_slice(&[0x88, 0x47]); // EtherType = MPLS unicast
    f.extend_from_slice(&[0x00, 0x06, 0x41, 0x40]); // one MPLS label, BOS=1
    // IPv6 header (40 bytes)
    f.push(0x60); // version=6, traffic class top 4 bits = 0
    f.extend_from_slice(&[0x00, 0x00, 0x00]); // remaining traffic class + flow label
    f.extend_from_slice(&[0x00, 20]); // payload length = 20 (TCP header)
    f.push(6); // next header = TCP
    f.push(64); // hop limit
    // src + dst (16 bytes each)
    f.extend_from_slice(&[0u8; 16]);
    f.extend_from_slice(&[0u8; 16]);
    // 8 bytes of fake L4
    // Minimal 20-byte TCP header (etherparse validates inner L4).
    f.extend_from_slice(&[0x00, 0x50, 0x00, 0x50]); // src port = 80, dst port = 80
    f.extend_from_slice(&[0; 4]); // seq
    f.extend_from_slice(&[0; 4]); // ack
    f.push(0x50); // data offset = 5
    f.push(0x02); // flags = SYN
    f.extend_from_slice(&[0xFF; 2]); // window
    f.extend_from_slice(&[0; 2]); // checksum
    f.extend_from_slice(&[0; 2]); // urgent
    f
}

#[test]
fn mpls_inner_ipv6_is_reparsed() {
    let f = build_mpls_ipv6_frame();
    let layers = Layers::parse_ethernet(&f).expect("parse");
    let kinds: Vec<LayerKind> = layers.iter().map(|l| l.kind()).collect();
    assert!(
        kinds.contains(&LayerKind::Mpls),
        "MPLS layer missing: {kinds:?}"
    );
    assert!(
        kinds.contains(&LayerKind::Ipv6),
        "inner IPv6 NOT re-parsed: {kinds:?}"
    );
}

#[test]
fn mpls_unknown_inner_returns_layers_without_l3() {
    // First byte of inner payload = 0x00 (neither IPv4 0x4* nor
    // IPv6 0x6*); should NOT push an L3 layer, but should still
    // succeed with the MPLS stack visible.
    let mut f = Vec::new();
    f.extend_from_slice(&[0u8; 6]);
    f.extend_from_slice(&[0u8; 6]);
    f.extend_from_slice(&[0x88, 0x47]);
    f.extend_from_slice(&[0x00, 0x06, 0x41, 0x40]); // BOS=1
    f.extend_from_slice(&[0x00; 16]); // unknown inner payload
    let layers = Layers::parse_ethernet(&f).expect("parse");
    let kinds: Vec<LayerKind> = layers.iter().map(|l| l.kind()).collect();
    assert!(kinds.contains(&LayerKind::Mpls));
    assert!(!kinds.contains(&LayerKind::Ipv4));
    assert!(!kinds.contains(&LayerKind::Ipv6));
}

// ─── IPv6 extension-header walker ───────────────────────

/// Build a plain IPv6 + TCP frame — no extensions.
fn build_ipv6_tcp(next_header: u8) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0u8; 6]);
    f.extend_from_slice(&[0u8; 6]);
    f.extend_from_slice(&[0x86, 0xDD]); // EtherType = IPv6
    f.push(0x60); // version=6
    f.extend_from_slice(&[0x00, 0x00, 0x00]); // tc + flow
    f.extend_from_slice(&[0x00, 20]); // payload length = 20 (TCP)
    f.push(next_header);
    f.push(64); // hop limit
    f.extend_from_slice(&[0u8; 16]); // src
    f.extend_from_slice(&[0u8; 16]); // dst
    // 20-byte fake TCP header
    f.extend_from_slice(&[0x00, 0x50, 0x00, 0x50]);
    f.extend_from_slice(&[0; 4]);
    f.extend_from_slice(&[0; 4]);
    f.push(0x50);
    f.push(0x02);
    f.extend_from_slice(&[0xFF; 2]);
    f.extend_from_slice(&[0; 2]);
    f.extend_from_slice(&[0; 2]);
    f
}

#[test]
fn ipv6_no_extensions_walker_returns_immediate_next_header() {
    let f = build_ipv6_tcp(6); // next_header = TCP
    let layers = Layers::parse_ethernet(&f).expect("parse");
    let v6 = layers
        .iter()
        .find_map(|l| match l {
            Layer::Ipv6(v6) => Some(v6),
            _ => None,
        })
        .expect("v6 layer present");
    let ext = v6.extensions();
    assert_eq!(ext.upper_header, 6);
    assert_eq!(ext.chain_depth, 0);
    assert!(!ext.fragment_present);
    assert!(!ext.chain_too_deep);
    assert!(!ext.malformed);
    assert_eq!(ext.payload_offset, 0);
}

/// Build an IPv6 frame with one Hop-by-Hop extension header
/// (next_header = 0 in IPv6 hdr; HBH points to TCP).
///
/// HBH header is 8 bytes total: next_header(1) + hdr_ext_len(1)
/// plus 6 bytes of options/padding. hdr_ext_len = 0 means no
/// extra 8-byte chunks beyond the base 8 bytes.
fn build_ipv6_hbh_tcp() -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0u8; 6]);
    f.extend_from_slice(&[0u8; 6]);
    f.extend_from_slice(&[0x86, 0xDD]);
    f.push(0x60);
    f.extend_from_slice(&[0x00, 0x00, 0x00]);
    f.extend_from_slice(&[0x00, 28]); // payload length = 28 (HBH 8 + TCP 20)
    f.push(0); // next_header = Hop-by-Hop
    f.push(64);
    f.extend_from_slice(&[0u8; 16]);
    f.extend_from_slice(&[0u8; 16]);
    // Hop-by-Hop extension (8 bytes)
    f.push(6); // next = TCP
    f.push(0); // hdr_ext_len = 0 (means 8 bytes total)
    f.extend_from_slice(&[0u8; 6]); // padding/options
    // L4
    // Minimal 20-byte TCP header (etherparse validates inner L4).
    f.extend_from_slice(&[0x00, 0x50, 0x00, 0x50]); // src port = 80, dst port = 80
    f.extend_from_slice(&[0; 4]); // seq
    f.extend_from_slice(&[0; 4]); // ack
    f.push(0x50); // data offset = 5
    f.push(0x02); // flags = SYN
    f.extend_from_slice(&[0xFF; 2]); // window
    f.extend_from_slice(&[0; 2]); // checksum
    f.extend_from_slice(&[0; 2]); // urgent
    f
}

#[test]
fn ipv6_hop_by_hop_is_walked_to_tcp() {
    let f = build_ipv6_hbh_tcp();
    let layers = Layers::parse_ethernet(&f).expect("parse");
    let v6 = layers
        .iter()
        .find_map(|l| match l {
            Layer::Ipv6(v6) => Some(v6),
            _ => None,
        })
        .expect("v6");
    assert_eq!(v6.next_header(), 0, "raw next_header points at HBH");
    let ext = v6.extensions();
    assert_eq!(ext.upper_header, 6, "walked to TCP");
    assert_eq!(ext.chain_depth, 1);
    assert_eq!(ext.payload_offset, 8);
    assert!(!ext.fragment_present);
    assert!(!ext.malformed);
}

/// Build an IPv6 frame with a Fragment extension header
/// (next_header = 44). Fragment headers are FIXED at 8 bytes
/// per RFC 8200 §4.5.
fn build_ipv6_fragment_tcp() -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0u8; 6]);
    f.extend_from_slice(&[0u8; 6]);
    f.extend_from_slice(&[0x86, 0xDD]);
    f.push(0x60);
    f.extend_from_slice(&[0x00, 0x00, 0x00]);
    f.extend_from_slice(&[0x00, 28]); // payload = Fragment 8 + TCP 20
    f.push(44); // next_header = Fragment
    f.push(64);
    f.extend_from_slice(&[0u8; 16]);
    f.extend_from_slice(&[0u8; 16]);
    // Fragment ext (8 bytes): next_header + reserved + frag_offset(13)+M(1) + identification(4)
    f.push(6); // next = TCP
    f.push(0); // reserved
    f.extend_from_slice(&[0x00, 0x00]); // offset = 0, M=0
    f.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // id
    // Minimal 20-byte TCP header (etherparse validates inner L4).
    f.extend_from_slice(&[0x00, 0x50, 0x00, 0x50]); // src port = 80, dst port = 80
    f.extend_from_slice(&[0; 4]); // seq
    f.extend_from_slice(&[0; 4]); // ack
    f.push(0x50); // data offset = 5
    f.push(0x02); // flags = SYN
    f.extend_from_slice(&[0xFF; 2]); // window
    f.extend_from_slice(&[0; 2]); // checksum
    f.extend_from_slice(&[0; 2]); // urgent
    f
}

#[test]
fn ipv6_fragment_header_flips_fragment_signal() {
    let f = build_ipv6_fragment_tcp();
    let layers = Layers::parse_ethernet(&f).expect("parse");
    let v6 = layers
        .iter()
        .find_map(|l| match l {
            Layer::Ipv6(v6) => Some(v6),
            _ => None,
        })
        .expect("v6");
    let ext = v6.extensions();
    assert!(ext.fragment_present, "Fragment header should be detected");
    assert_eq!(ext.upper_header, 6, "still walks to TCP");
    assert_eq!(ext.chain_depth, 1);
    // The Layers convenience accessor.
    assert!(layers.has_ipv6_fragment());
}

#[test]
fn layers_has_ipv6_fragment_false_when_no_extensions() {
    let f = build_ipv6_tcp(6);
    let layers = Layers::parse_ethernet(&f).expect("parse");
    assert!(!layers.has_ipv6_fragment());
}

/// Build a deeply-chained IPv6 frame (8 HBH headers) — should
/// hit the chain_too_deep cap.
fn build_ipv6_deep_chain() -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0u8; 6]);
    f.extend_from_slice(&[0u8; 6]);
    f.extend_from_slice(&[0x86, 0xDD]);
    f.push(0x60);
    f.extend_from_slice(&[0x00, 0x00, 0x00]);
    let n_ext = 10usize; // attempt 10 HBH (cap is 8)
    let payload_len = n_ext * 8 + 20; // 10 HBH × 8 + 20-byte TCP
    f.extend_from_slice(&[(payload_len >> 8) as u8, (payload_len & 0xff) as u8]);
    f.push(0); // first ext = HBH
    f.push(64);
    f.extend_from_slice(&[0u8; 16]);
    f.extend_from_slice(&[0u8; 16]);
    // Per RFC 8200 §4: HBH must be the first extension header
    // (etherparse enforces). Chain: 1 HBH then 9 Destination
    // Options (type 60) — the latter has no "must be first"
    // restriction. Each ext points to the next; final one to
    // TCP, but our 8-cap walker won't reach it.
    for i in 0..n_ext {
        let next = if i + 1 == n_ext {
            6 // TCP at the end (won't reach due to cap)
        } else {
            60 // next is Destination Options
        };
        f.push(next);
        f.push(0); // hdr_ext_len = 0 (8 bytes)
        f.extend_from_slice(&[0u8; 6]);
    }
    // Minimal 20-byte TCP header (etherparse validates inner L4).
    f.extend_from_slice(&[0x00, 0x50, 0x00, 0x50]); // src port = 80, dst port = 80
    f.extend_from_slice(&[0; 4]); // seq
    f.extend_from_slice(&[0; 4]); // ack
    f.push(0x50); // data offset = 5
    f.push(0x02); // flags = SYN
    f.extend_from_slice(&[0xFF; 2]); // window
    f.extend_from_slice(&[0; 2]); // checksum
    f.extend_from_slice(&[0; 2]); // urgent
    f
}

#[test]
fn ipv6_chain_too_deep_evasion_signal() {
    let f = build_ipv6_deep_chain();
    let layers = Layers::parse_ethernet(&f).expect("parse");
    let v6 = layers
        .iter()
        .find_map(|l| match l {
            Layer::Ipv6(v6) => Some(v6),
            _ => None,
        })
        .expect("v6");
    let ext = v6.extensions();
    assert!(
        ext.chain_too_deep,
        "deeply-chained ext headers should flip chain_too_deep"
    );
    assert_eq!(ext.chain_depth, 8, "walker stops at the 8-ext cap");
}

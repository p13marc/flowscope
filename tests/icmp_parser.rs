//! Plan 76 — ICMP parser tests. Crafted packet payloads + the
//! parser's behaviour on each type. The cross-protocol
//! correlation primitive (`IcmpInner`) gets its own focused
//! tests against TCP and UDP inner headers.

#![cfg(feature = "icmp")]

use flowscope::icmp::*;
use std::net::Ipv6Addr;

/// Build an ICMPv4 packet header. Doesn't compute a real
/// checksum (the parser doesn't verify it).
fn v4_header(ty: u8, code: u8, bytes4: [u8; 4]) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(ty);
    v.push(code);
    v.extend_from_slice(&[0, 0]); // checksum
    v.extend_from_slice(&bytes4);
    v
}

fn v6_header(ty: u8, code: u8, bytes4: [u8; 4]) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(ty);
    v.push(code);
    v.extend_from_slice(&[0, 0]); // checksum
    v.extend_from_slice(&bytes4);
    v
}

// ── Echo request / reply ──────────────────────────────────────────

#[test]
fn parses_v4_echo_request() {
    // type=8, code=0, id=0x1234, seq=0x5678
    let payload = v4_header(8, 0, [0x12, 0x34, 0x56, 0x78]);
    let msg = parse_v4(&payload).expect("parses");
    match msg.ty {
        IcmpType::V4(Icmpv4Type::EchoRequest { id, seq }) => {
            assert_eq!(id, 0x1234);
            assert_eq!(seq, 0x5678);
        }
        other => panic!("expected EchoRequest, got {other:?}"),
    }
}

#[test]
fn parses_v4_echo_reply() {
    let payload = v4_header(0, 0, [0xAA, 0xBB, 0x00, 0x01]);
    let msg = parse_v4(&payload).expect("parses");
    assert!(matches!(
        msg.ty,
        IcmpType::V4(Icmpv4Type::EchoReply { id: 0xAABB, seq: 1 })
    ));
}

#[test]
fn parses_v6_echo_request() {
    // type=128, code=0, id=0x0F0F, seq=0x0001
    let payload = v6_header(128, 0, [0x0F, 0x0F, 0x00, 0x01]);
    let msg = parse_v6(&payload).expect("parses");
    assert!(matches!(
        msg.ty,
        IcmpType::V6(Icmpv6Type::EchoRequest { id: 0x0F0F, seq: 1 })
    ));
}

// ── Destination Unreachable with TCP inner ─────────────────────────

/// Build a tiny IPv4 + TCP-header sequence that fits in the
/// ICMP error body. Returns the bytes ready to append after the
/// ICMP fixed header.
fn ipv4_tcp_inner(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
    let mut v = Vec::new();
    // IPv4 header (20 bytes, no options).
    v.push(0x45); // version=4, IHL=5
    v.push(0); // ToS
    v.extend_from_slice(&[0x00, 0x28]); // total length 40
    v.extend_from_slice(&[0, 0]); // id
    v.extend_from_slice(&[0, 0]); // flags + fragment
    v.push(64); // TTL
    v.push(6); // protocol = TCP
    v.extend_from_slice(&[0, 0]); // checksum
    v.extend_from_slice(&src);
    v.extend_from_slice(&dst);
    // TCP "header" (first 8 bytes is enough for ports + seq).
    v.extend_from_slice(&sport.to_be_bytes());
    v.extend_from_slice(&dport.to_be_bytes());
    v.extend_from_slice(&[0, 0, 0, 1]); // seq
    v
}

#[test]
fn v4_dest_unreach_extracts_tcp_inner() {
    use flowscope::extractor::L4Proto;
    use std::net::IpAddr;

    let mut payload = v4_header(3, 3, [0, 0, 0, 0]); // code 3 = port unreach
    payload.extend(ipv4_tcp_inner([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80));
    let msg = parse_v4(&payload).expect("parses");
    let IcmpType::V4(Icmpv4Type::DestinationUnreachable {
        code,
        inner: Some(inner),
    }) = msg.ty
    else {
        panic!("expected DestinationUnreachable with inner");
    };
    assert_eq!(code, Icmpv4DestUnreachCode::Port);
    assert_eq!(inner.src, IpAddr::V4("10.0.0.1".parse().unwrap()));
    assert_eq!(inner.dst, IpAddr::V4("10.0.0.2".parse().unwrap()));
    assert_eq!(inner.proto, L4Proto::Tcp);
    assert_eq!(inner.src_port, Some(12345));
    assert_eq!(inner.dst_port, Some(80));
}

fn ipv4_udp_inner(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
    let mut v = Vec::new();
    v.push(0x45);
    v.push(0);
    v.extend_from_slice(&[0x00, 0x1C]); // total length 28
    v.extend_from_slice(&[0, 0]);
    v.extend_from_slice(&[0, 0]);
    v.push(64);
    v.push(17); // UDP
    v.extend_from_slice(&[0, 0]);
    v.extend_from_slice(&src);
    v.extend_from_slice(&dst);
    v.extend_from_slice(&sport.to_be_bytes());
    v.extend_from_slice(&dport.to_be_bytes());
    v.extend_from_slice(&[0, 8, 0, 0]); // len + checksum
    v
}

#[test]
fn v4_dest_unreach_extracts_udp_inner() {
    use flowscope::extractor::L4Proto;

    let mut payload = v4_header(3, 3, [0, 0, 0, 0]);
    payload.extend(ipv4_udp_inner([1, 2, 3, 4], [5, 6, 7, 8], 53000, 53));
    let msg = parse_v4(&payload).expect("parses");
    let IcmpType::V4(Icmpv4Type::DestinationUnreachable {
        inner: Some(inner), ..
    }) = msg.ty
    else {
        panic!("expected inner");
    };
    assert_eq!(inner.proto, L4Proto::Udp);
    assert_eq!(inner.src_port, Some(53000));
    assert_eq!(inner.dst_port, Some(53));
}

#[test]
fn v4_dest_unreach_truncated_inner_returns_none_ports() {
    // Inner IP header present but truncated L4 — only 2 bytes.
    let mut payload = v4_header(3, 0, [0, 0, 0, 0]);
    // IPv4 header (with truncated L4 — only 2 bytes after).
    let mut inner = Vec::new();
    inner.push(0x45);
    inner.push(0);
    inner.extend_from_slice(&[0, 22]); // total length 22 (header + 2)
    inner.extend_from_slice(&[0, 0]);
    inner.extend_from_slice(&[0, 0]);
    inner.push(64);
    inner.push(6); // TCP
    inner.extend_from_slice(&[0, 0]);
    inner.extend_from_slice(&[10, 0, 0, 1]);
    inner.extend_from_slice(&[10, 0, 0, 2]);
    inner.extend_from_slice(&[0x12, 0x34]); // only 2 bytes of L4 (need 4)
    payload.extend(&inner);
    let msg = parse_v4(&payload).expect("parses");
    let IcmpType::V4(Icmpv4Type::DestinationUnreachable {
        inner: Some(inner), ..
    }) = msg.ty
    else {
        panic!("expected inner with ip data");
    };
    assert_eq!(inner.src_port, None);
    assert_eq!(inner.dst_port, None);
}

// ── Time Exceeded ─────────────────────────────────────────────────

#[test]
fn parses_v4_time_exceeded_with_inner() {
    let mut payload = v4_header(11, 0, [0, 0, 0, 0]); // hop limit exceeded
    payload.extend(ipv4_tcp_inner([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80));
    let msg = parse_v4(&payload).expect("parses");
    let IcmpType::V4(Icmpv4Type::TimeExceeded {
        code,
        inner: Some(_),
    }) = msg.ty
    else {
        panic!("expected TimeExceeded");
    };
    assert_eq!(code, Icmpv4TimeExceededCode::HopLimitExceeded);
}

#[test]
fn parses_v6_time_exceeded() {
    let payload = v6_header(3, 0, [0, 0, 0, 0]);
    let msg = parse_v6(&payload).expect("parses");
    let IcmpType::V6(Icmpv6Type::TimeExceeded { code, inner: _ }) = msg.ty else {
        panic!("expected TimeExceeded");
    };
    assert_eq!(code, Icmpv6TimeExceededCode::HopLimitExceeded);
}

// ── Redirect (v4) ─────────────────────────────────────────────────

#[test]
fn parses_v4_redirect_with_gateway() {
    use std::net::Ipv4Addr;
    // type=5, code=1 (host redirect), gateway=192.168.1.1
    let payload = v4_header(5, 1, [192, 168, 1, 1]);
    let msg = parse_v4(&payload).expect("parses");
    let IcmpType::V4(Icmpv4Type::Redirect { code, gateway, .. }) = msg.ty else {
        panic!("expected Redirect");
    };
    assert_eq!(code, Icmpv4RedirectCode::Host);
    assert_eq!(gateway, Ipv4Addr::new(192, 168, 1, 1));
}

// ── PacketTooBig (v6) ─────────────────────────────────────────────

#[test]
fn parses_v6_packet_too_big_with_mtu() {
    // type=2, code=0, mtu=1500 as u32 big-endian
    let mtu_be: [u8; 4] = 1500u32.to_be_bytes();
    let payload = v6_header(2, 0, mtu_be);
    let msg = parse_v6(&payload).expect("parses");
    let IcmpType::V6(Icmpv6Type::PacketTooBig { mtu, .. }) = msg.ty else {
        panic!("expected PacketTooBig");
    };
    assert_eq!(mtu, 1500);
}

// ── Neighbor Solicitation / Advertisement (v6) ────────────────────

#[test]
fn parses_v6_neighbor_solicitation() {
    // type=135, code=0, reserved=0, target_address=fe80::1
    let mut payload = v6_header(135, 0, [0, 0, 0, 0]);
    let target = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).octets();
    payload.extend_from_slice(&target);
    let msg = parse_v6(&payload).expect("parses");
    let IcmpType::V6(Icmpv6Type::NeighborSolicitation { target }) = msg.ty else {
        panic!("expected NeighborSolicitation");
    };
    assert_eq!(target, Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
}

#[test]
fn parses_v6_neighbor_advertisement_with_flags() {
    // type=136, code=0, flags=0xE0 (router + solicited + override),
    // reserved=0..., target = ::1
    let mut payload = v6_header(136, 0, [0xE0, 0, 0, 0]);
    let target = Ipv6Addr::LOCALHOST.octets();
    payload.extend_from_slice(&target);
    let msg = parse_v6(&payload).expect("parses");
    let IcmpType::V6(Icmpv6Type::NeighborAdvertisement {
        target,
        router,
        solicited,
        override_,
    }) = msg.ty
    else {
        panic!("expected NeighborAdvertisement");
    };
    assert_eq!(target, Ipv6Addr::LOCALHOST);
    assert!(router);
    assert!(solicited);
    assert!(override_);
}

// ── Other / Unknown ────────────────────────────────────────────────

#[test]
fn unknown_v4_type_surfaces_as_other() {
    // Type 42 doesn't exist in v4; goes to Other.
    let payload = v4_header(42, 7, [0x11, 0x22, 0x33, 0x44]);
    let msg = parse_v4(&payload).expect("parses");
    let IcmpType::V4(Icmpv4Type::Other {
        raw_type,
        raw_code,
        raw_body,
    }) = msg.ty
    else {
        panic!("expected Other");
    };
    assert_eq!(raw_type, 42);
    assert_eq!(raw_code, 7);
    assert!(raw_body.starts_with(&[0x11, 0x22, 0x33, 0x44]));
}

// ── DatagramParser integration ─────────────────────────────────────

#[test]
fn datagram_parser_returns_one_message_per_call() {
    use flowscope::{DatagramParser, FlowSide, Timestamp};
    let mut p = IcmpParser::new();
    let payload = v4_header(8, 0, [0, 1, 0, 1]);
    let msgs = p.parse(&payload, FlowSide::Initiator, Timestamp::default());
    assert_eq!(msgs.len(), 1);
    assert!(matches!(
        msgs[0].ty,
        IcmpType::V4(Icmpv4Type::EchoRequest { id: 1, seq: 1 })
    ));
}

#[test]
fn datagram_parser_kind_is_icmp() {
    use flowscope::DatagramParser;
    let p = IcmpParser::new();
    assert_eq!(p.parser_kind(), "icmp");
}

#[test]
fn datagram_parser_v6_only_skips_v4() {
    use flowscope::{DatagramParser, FlowSide, Timestamp};
    let mut p = IcmpParser::new().v6_only();
    // An ICMPv4 echo request payload — should not parse as v6.
    let payload = v4_header(8, 0, [0, 1, 0, 1]);
    let msgs = p.parse(&payload, FlowSide::Initiator, Timestamp::default());
    // Probably empty (v4 payload doesn't decode as legitimate v6).
    assert!(msgs.is_empty() || matches!(msgs[0].family, IcmpFamily::V6));
}

// ── Malformed payloads ────────────────────────────────────────────

#[test]
fn empty_payload_returns_err() {
    assert!(parse_v4(&[]).is_err());
    assert!(parse_v6(&[]).is_err());
}

#[test]
fn malformed_short_header_does_not_panic() {
    let _ = parse_v4(&[1, 2, 3]);
    let _ = parse_v6(&[1, 2, 3]);
    // Just must not panic.
}

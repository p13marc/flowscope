//! Plan 161 (0.14) — `FlowTracker<FiveTuple, S>::lookup_inner` +
//! `FiveTupleKey::from_inner_canonical`.

#![cfg(all(feature = "icmp", feature = "extractors", feature = "tracker"))]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use flowscope::{
    FlowTracker, PacketView, Timestamp,
    extract::{FiveTuple, FiveTupleKey, parse::test_frames::ipv4_tcp},
    extractor::L4Proto,
    icmp::IcmpInner,
};

fn synth_tcp_flow(tracker: &mut FlowTracker<FiveTuple, ()>) {
    // SYN from 10.0.0.1:33000 → 10.0.0.2:80
    let frame = ipv4_tcp(
        [1; 6],
        [2; 6],
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        33000,
        80,
        1000,
        0,
        0x02,
        b"",
    );
    let view = PacketView::new(&frame, Timestamp::new(0, 0));
    tracker.track(view);
}

// ── FiveTupleKey::from_inner_canonical ─────────────────────────

#[test]
fn from_inner_canonical_returns_none_when_tcp_ports_missing() {
    let inner = IcmpInner::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        L4Proto::Tcp,
        None,
        None,
    );
    assert!(FiveTupleKey::from_inner_canonical(&inner).is_none());
}

#[test]
fn from_inner_canonical_returns_some_for_icmp_inner_with_no_ports() {
    let inner = IcmpInner::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        L4Proto::Icmp,
        None,
        None,
    );
    let key = FiveTupleKey::from_inner_canonical(&inner).unwrap();
    assert_eq!(key.proto, L4Proto::Icmp);
}

#[test]
fn from_inner_canonical_swaps_when_src_greater_than_dst() {
    let inner = IcmpInner::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        L4Proto::Tcp,
        Some(80),
        Some(33000),
    );
    let key = FiveTupleKey::from_inner_canonical(&inner).unwrap();
    assert_eq!(key.a.ip(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    assert_eq!(key.a.port(), 33000);
    assert_eq!(key.b.ip(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    assert_eq!(key.b.port(), 80);
}

#[test]
fn from_inner_canonical_keeps_when_src_less_than_dst() {
    let inner = IcmpInner::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        L4Proto::Tcp,
        Some(33000),
        Some(80),
    );
    let key = FiveTupleKey::from_inner_canonical(&inner).unwrap();
    assert_eq!(key.a.ip(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    assert_eq!(key.a.port(), 33000);
}

#[test]
fn from_inner_literal_preserves_orientation() {
    let inner = IcmpInner::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        L4Proto::Tcp,
        Some(80),
        Some(33000),
    );
    let key = FiveTupleKey::from_inner_literal(&inner).unwrap();
    assert_eq!(key.a.ip(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    assert_eq!(key.a.port(), 80);
}

#[test]
fn from_inner_canonical_ipv6_works() {
    let inner = IcmpInner::new(
        IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
        IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2)),
        L4Proto::Udp,
        Some(53),
        Some(33000),
    );
    let key = FiveTupleKey::from_inner_canonical(&inner).unwrap();
    assert_eq!(key.proto, L4Proto::Udp);
}

// ── FlowTracker<FiveTuple, S>::lookup_inner ─────────────────────

#[test]
fn lookup_inner_matches_forward_direction() {
    let mut tracker: FlowTracker<FiveTuple, ()> = FlowTracker::new(FiveTuple::bidirectional());
    synth_tcp_flow(&mut tracker);

    let inner = IcmpInner::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        L4Proto::Tcp,
        Some(33000),
        Some(80),
    );
    let key = tracker.lookup_inner(&inner);
    assert!(
        key.is_some(),
        "forward-direction lookup should find the flow"
    );
}

#[test]
fn lookup_inner_matches_reverse_direction_canonically() {
    let mut tracker: FlowTracker<FiveTuple, ()> = FlowTracker::new(FiveTuple::bidirectional());
    synth_tcp_flow(&mut tracker);

    // Reverse direction (responder reporting).
    let inner = IcmpInner::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        L4Proto::Tcp,
        Some(80),
        Some(33000),
    );
    let key = tracker.lookup_inner(&inner);
    assert!(
        key.is_some(),
        "reverse-direction lookup should canonicalise + match"
    );
}

#[test]
fn lookup_inner_returns_none_when_flow_missing() {
    let tracker: FlowTracker<FiveTuple, ()> = FlowTracker::new(FiveTuple::bidirectional());
    let inner = IcmpInner::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        L4Proto::Tcp,
        Some(33000),
        Some(80),
    );
    assert!(tracker.lookup_inner(&inner).is_none());
}

#[test]
fn lookup_inner_returns_none_on_missing_ports_for_tcp() {
    let mut tracker: FlowTracker<FiveTuple, ()> = FlowTracker::new(FiveTuple::bidirectional());
    synth_tcp_flow(&mut tracker);

    let inner = IcmpInner::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        L4Proto::Tcp,
        None,
        None,
    );
    assert!(tracker.lookup_inner(&inner).is_none());
}

#[test]
fn stats_for_inner_returns_canonical_key_and_stats() {
    let mut tracker: FlowTracker<FiveTuple, ()> = FlowTracker::new(FiveTuple::bidirectional());
    synth_tcp_flow(&mut tracker);

    let inner = IcmpInner::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        L4Proto::Tcp,
        Some(33000),
        Some(80),
    );
    let (key, stats) = tracker.stats_for_inner(&inner).expect("should match");
    assert_eq!(stats.packets_initiator + stats.packets_responder, 1);
    assert!(key.a < key.b);
}

#[test]
fn stats_for_inner_returns_none_when_flow_missing() {
    let tracker: FlowTracker<FiveTuple, ()> = FlowTracker::new(FiveTuple::bidirectional());
    let inner = IcmpInner::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        L4Proto::Tcp,
        Some(33000),
        Some(80),
    );
    assert!(tracker.stats_for_inner(&inner).is_none());
}

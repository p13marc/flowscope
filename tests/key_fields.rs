//! Plan 130 — `KeyFields` impls on `FiveTupleKey` + `L4Proto`.
//!
//! Companion to `tests/anomaly_fields.rs` after the plan-130
//! trait split. Together they cover the surface previously
//! tested under one `AnomalyFields` umbrella.

#![cfg(all(feature = "extractors", feature = "tracker"))]

use std::net::IpAddr;

use flowscope::extract::FiveTupleKey;
use flowscope::{KeyFields, L4Proto};

// ── L4Proto ───────────────────────────────────────────────────

#[test]
fn l4proto_tcp_returns_uppercase_tcp() {
    assert_eq!(L4Proto::Tcp.proto_str(), Some("TCP"));
}

#[test]
fn l4proto_udp_returns_uppercase_udp() {
    assert_eq!(L4Proto::Udp.proto_str(), Some("UDP"));
}

#[test]
fn l4proto_icmp_v4_and_v6() {
    assert_eq!(L4Proto::Icmp.proto_str(), Some("ICMP"));
    assert_eq!(L4Proto::IcmpV6.proto_str(), Some("ICMPv6"));
}

#[test]
fn l4proto_sctp() {
    assert_eq!(L4Proto::Sctp.proto_str(), Some("SCTP"));
}

#[test]
fn l4proto_other_returns_none() {
    assert_eq!(L4Proto::Other(47).proto_str(), None);
}

// ── FiveTupleKey ──────────────────────────────────────────────

fn key() -> FiveTupleKey {
    FiveTupleKey {
        proto: L4Proto::Tcp,
        a: "10.0.0.1:33000".parse().unwrap(),
        b: "10.0.0.2:80".parse().unwrap(),
    }
}

#[test]
fn five_tuple_key_returns_split_ip_port() {
    let k = key();
    assert_eq!(k.src_ip(), Some("10.0.0.1".parse::<IpAddr>().unwrap()));
    assert_eq!(k.src_port(), Some(33000));
    assert_eq!(k.dest_ip(), Some("10.0.0.2".parse::<IpAddr>().unwrap()));
    assert_eq!(k.dest_port(), Some(80));
    assert_eq!(k.proto_str(), Some("TCP"));
}

#[test]
fn five_tuple_key_app_proto_via_well_known_port() {
    // dest_port 80 → "http" per well_known.
    let k = key();
    assert_eq!(k.app_proto_str(), Some("http"));
}

// Custom-key parity smoke test: any type implementing
// `KeyFields` flows through the emit-writer constraint by
// default. The shipped emit writers exercise this contract
// via golden integration tests; this is just the trait-bound
// compile check.
#[test]
fn custom_key_with_partial_overrides_compiles() {
    struct OnlyIp(IpAddr);
    impl KeyFields for OnlyIp {
        fn src_ip(&self) -> Option<IpAddr> {
            Some(self.0)
        }
    }
    let k = OnlyIp("10.0.0.5".parse().unwrap());
    assert_eq!(k.src_ip(), Some("10.0.0.5".parse::<IpAddr>().unwrap()));
    assert!(k.src_port().is_none());
    assert!(k.dest_ip().is_none());
}

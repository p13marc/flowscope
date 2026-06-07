//! Plan 102 sub-D — well-known ports module.
//!
//! Integration coverage for `FiveTupleKey::well_known_port()` +
//! `FiveTupleKey::protocol_label()` accessors and the curated
//! table behind them.

#![cfg(feature = "extractors")]

use flowscope::extract::FiveTupleKey;
use flowscope::extractor::L4Proto;
use std::net::SocketAddr;

fn key(a: &str, b: &str, proto: L4Proto) -> FiveTupleKey {
    let a: SocketAddr = a.parse().expect("parse a");
    let b: SocketAddr = b.parse().expect("parse b");
    let (a, b) = if a < b { (a, b) } else { (b, a) };
    FiveTupleKey { proto, a, b }
}

#[test]
fn five_tuple_well_known_port() {
    let k = key("10.0.0.1:33000", "10.0.0.2:80", L4Proto::Tcp);
    assert_eq!(k.well_known_port(), 80);
}

#[test]
fn five_tuple_protocol_label_http() {
    let k = key("10.0.0.1:33000", "10.0.0.2:80", L4Proto::Tcp);
    assert_eq!(k.protocol_label(), Some("http"));
}

#[test]
fn five_tuple_protocol_label_dns_udp() {
    let k = key("10.0.0.1:33000", "10.0.0.2:53", L4Proto::Udp);
    assert_eq!(k.protocol_label(), Some("dns"));
}

#[test]
fn five_tuple_protocol_label_lower_wins() {
    // 80 + 443 → http (lower port).
    let k = key("10.0.0.1:80", "10.0.0.2:443", L4Proto::Tcp);
    assert_eq!(k.protocol_label(), Some("http"));
}

#[test]
fn five_tuple_protocol_label_unknown_returns_none() {
    let k = key("10.0.0.1:33000", "10.0.0.2:33001", L4Proto::Tcp);
    assert_eq!(k.protocol_label(), None);
}

#[test]
fn five_tuple_protocol_label_icmp_returns_none() {
    let k = key("10.0.0.1:0", "10.0.0.2:0", L4Proto::Icmp);
    assert_eq!(k.protocol_label(), None);
}

#[test]
fn five_tuple_protocol_label_kafka() {
    let k = key("10.0.0.1:33000", "10.0.0.2:9092", L4Proto::Tcp);
    assert_eq!(k.protocol_label(), Some("kafka"));
}

#[test]
fn entries_iterates_known_rows() {
    let entries: Vec<_> = flowscope::well_known::entries().collect();
    assert!(
        entries
            .iter()
            .any(|(p, port, l)| *p == L4Proto::Tcp && *port == 80 && *l == "http")
    );
    assert!(
        entries
            .iter()
            .any(|(p, port, l)| *p == L4Proto::Udp && *port == 4789 && *l == "vxlan")
    );
}

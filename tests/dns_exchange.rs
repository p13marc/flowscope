//! Plan 107 — DnsExchangeParser coverage.

#![cfg(feature = "dns")]

use flowscope::dns::{DnsExchangeParser, DnsOutcome};
use flowscope::{DatagramParser, FlowSide, Timestamp};
use std::time::Duration;

fn build_msg(tx_id: u16, qname: &str, flags: u16, rcode_lo: u8) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&tx_id.to_be_bytes());
    let flags_with_rcode = flags | rcode_lo as u16;
    v.extend_from_slice(&flags_with_rcode.to_be_bytes());
    v.extend_from_slice(&1u16.to_be_bytes()); // qdcount
    v.extend_from_slice(&0u16.to_be_bytes());
    v.extend_from_slice(&0u16.to_be_bytes());
    v.extend_from_slice(&0u16.to_be_bytes());
    for label in qname.split('.') {
        v.push(label.len() as u8);
        v.extend_from_slice(label.as_bytes());
    }
    v.push(0);
    v.extend_from_slice(&1u16.to_be_bytes()); // qtype A
    v.extend_from_slice(&1u16.to_be_bytes()); // qclass IN
    v
}

#[test]
fn query_response_yields_completed() {
    let mut p = DnsExchangeParser::new();
    let q = build_msg(0x1234, "example.com", 0x0100, 0);
    let r = build_msg(0x1234, "example.com", 0x8100, 0);
    let mut qs = Vec::new();
    p.parse(&q, FlowSide::Initiator, Timestamp::new(0, 0), &mut qs);
    assert!(qs.is_empty(), "query alone shouldn't emit exchange");
    let mut rs = Vec::new();
    p.parse(&r, FlowSide::Responder, Timestamp::new(1, 0), &mut rs);
    assert_eq!(rs.len(), 1);
    assert_eq!(rs[0].outcome, DnsOutcome::Completed);
    assert_eq!(rs[0].transaction_id, 0x1234);
    assert_eq!(rs[0].question.name, "example.com");
}

#[test]
fn nxdomain_response_yields_failed() {
    let mut p = DnsExchangeParser::new();
    let q = build_msg(0xabcd, "missing.example", 0x0100, 0);
    let r = build_msg(0xabcd, "missing.example", 0x8100, 3); // rcode NXDOMAIN
    let mut sink = Vec::new();
    p.parse(&q, FlowSide::Initiator, Timestamp::new(0, 0), &mut sink);
    sink.clear();
    p.parse(&r, FlowSide::Responder, Timestamp::new(1, 0), &mut sink);
    assert_eq!(sink.len(), 1);
    assert!(matches!(sink[0].outcome, DnsOutcome::Failed { .. }));
}

#[test]
fn unanswered_query_yields_no_response_on_tick() {
    let mut p = flowscope::dns::DnsExchangeParser::with_config(flowscope::dns::DnsConfig {
        query_timeout: Duration::from_secs(1),
        max_pending: 1024,
    });
    let q = build_msg(0x9999, "slow.example", 0x0100, 0);
    let mut sink = Vec::new();
    p.parse(&q, FlowSide::Initiator, Timestamp::new(0, 0), &mut sink);
    // Past timeout, sweep should fire NoResponse.
    let mut ticks = Vec::new();
    p.on_tick(Timestamp::new(10, 0), &mut ticks);
    assert_eq!(ticks.len(), 1);
    assert_eq!(ticks[0].outcome, DnsOutcome::NoResponse);
}

#[test]
fn parser_kind_is_dns_exchange() {
    let p = DnsExchangeParser::new();
    assert_eq!(p.parser_kind(), "dns-exchange");
}

//! Print a one-line summary for every DNS query / response observed
//! in a pcap, with query/response RTT correlation.
//!
//! Demonstrates `PcapFlowSource::datagrams()` driving a correlating
//! `DnsUdpParser` — the typed-message DNS pipeline. `with_correlation()`
//! matches responses to queries (RTT in `DnsResponse::elapsed`) and
//! surfaces timed-out queries as `DnsMessage::Unanswered` via the
//! parser's `on_tick` hook.
//!
//! Usage:
//!     cargo run --features dns,pcap --example dns_log -- trace.pcap

use std::env;

use flowscope::{
    SessionEvent,
    dns::{DnsMessage, DnsQuery, DnsRdata, DnsResponse, DnsUdpParser},
    extract::FiveTuple,
    pcap::PcapFlowSource,
};

fn log_query(q: &DnsQuery) {
    let names: Vec<&str> = q.questions.iter().map(|q| q.name.as_str()).collect();
    println!("→ Q  id=0x{:04x} {}", q.transaction_id, names.join(","));
}

fn log_response(r: &DnsResponse) {
    let n = r.questions.first().map(|q| q.name.as_str()).unwrap_or("?");
    let ms = r
        .elapsed
        .map(|d| format!(" rtt={:.2}ms", d.as_secs_f64() * 1000.0))
        .unwrap_or_default();
    let preview = r
        .answers
        .iter()
        .take(2)
        .map(|a| match &a.data {
            DnsRdata::A(ip) => ip.to_string(),
            DnsRdata::AAAA(ip) => ip.to_string(),
            DnsRdata::CNAME(s) | DnsRdata::NS(s) | DnsRdata::PTR(s) => s.clone(),
            DnsRdata::MX { exchange, .. } => exchange.clone(),
            _ => "<…>".to_string(),
        })
        .collect::<Vec<_>>()
        .join(",");
    println!(
        "← R  id=0x{:04x} {} rcode={:?} answers={}{}{}",
        r.transaction_id,
        n,
        r.rcode,
        r.answers.len(),
        if preview.is_empty() {
            String::new()
        } else {
            format!(" [{preview}]")
        },
        ms
    );
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args().nth(1).ok_or("usage: dns_log <trace.pcap>")?;

    // `datagrams()` runs the extractor + a per-flow DnsUdpParser over
    // the pcap and flushes at end-of-input — the final flush drives
    // `on_tick`, which emits any still-unanswered queries.
    let source = PcapFlowSource::open(&path)?
        .datagrams(FiveTuple::bidirectional(), DnsUdpParser::with_correlation());

    for evt in source {
        if let SessionEvent::Application { message, .. } = evt? {
            match message {
                DnsMessage::Query(q) => log_query(&q),
                DnsMessage::Response(r) => log_response(&r),
                DnsMessage::Unanswered(q) => {
                    let n = q.questions.first().map(|q| q.name.as_str()).unwrap_or("?");
                    println!("⏱  unanswered id=0x{:04x} {n}", q.transaction_id);
                }
                _ => {}
            }
        }
    }
    Ok(())
}

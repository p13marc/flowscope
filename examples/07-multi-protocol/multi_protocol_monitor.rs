//! Plan 91 — multi-protocol monitor over a single pcap.
//!
//! Runs HTTP / TLS / DNS / ICMP parsers in parallel against the
//! same pcap, printing a unified one-line summary per L7 event in
//! observation order.
//!
//! ## Recipe shape
//!
//! Plan 121: one typed [`Driver`] hosts every parser slot. Each
//! `session_on_ports` / `datagram_on_ports` / `datagram_broadcast`
//! call returns a typed [`SlotHandle`](flowscope::driver::SlotHandle).
//! The single pcap pass drives all four parsers and we drain
//! each slot per packet, collecting `(ts, label)` rows for a
//! final chronological print.
//!
//! Usage:
//!     cargo run --features l7,pcap --example multi_protocol_monitor -- trace.pcap

use std::env;

use flowscope::dns::{DnsMessage, DnsUdpParser};
use flowscope::driver::SlotMessage;
use flowscope::driver::{Driver, Event};
use flowscope::extract::{FiveTuple, FiveTupleKey};
use flowscope::http::{HttpMessage, HttpParser};
use flowscope::icmp::{IcmpMessage, IcmpParser};
use flowscope::pcap::PcapFlowSource;
use flowscope::tls::{TlsMessage, TlsParser};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args()
        .nth(1)
        .ok_or("usage: multi_protocol_monitor <trace.pcap>")?;

    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut http_slot = builder.session_on_ports(HttpParser::default(), [80, 8080]);
    let mut tls_slot = builder.session_on_ports(TlsParser::default(), [443, 8443]);
    let mut dns_slot = builder.datagram_on_ports(DnsUdpParser::default(), [53]);
    let mut icmp_slot = builder.datagram_broadcast(IcmpParser::new());
    let mut driver = builder.build();

    let mut events: Vec<Event<FiveTupleKey>> = Vec::new();
    let mut http_msgs: Vec<SlotMessage<HttpMessage, FiveTupleKey>> = Vec::new();
    let mut tls_msgs: Vec<SlotMessage<TlsMessage, FiveTupleKey>> = Vec::new();
    let mut dns_msgs: Vec<SlotMessage<DnsMessage, FiveTupleKey>> = Vec::new();
    let mut icmp_msgs: Vec<SlotMessage<IcmpMessage, FiveTupleKey>> = Vec::new();

    let mut rows: Vec<(flowscope::Timestamp, String)> = Vec::new();

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        events.clear();
        driver.track_into(&owned, &mut events);
        http_msgs.clear();
        http_slot.drain(&mut http_msgs);
        tls_msgs.clear();
        tls_slot.drain(&mut tls_msgs);
        dns_msgs.clear();
        dns_slot.drain(&mut dns_msgs);
        icmp_msgs.clear();
        icmp_slot.drain(&mut icmp_msgs);

        for m in &http_msgs {
            if let HttpMessage::Request(req) = &m.message {
                rows.push((
                    m.ts,
                    format!(
                        "HTTP {} {} (host={})",
                        req.method_str().unwrap_or("?"),
                        req.path_str().unwrap_or("?"),
                        req.host().unwrap_or("?")
                    ),
                ));
            }
        }
        for m in &tls_msgs {
            if let TlsMessage::ClientHello(hello) = &m.message {
                rows.push((
                    m.ts,
                    format!("TLS  ClientHello sni={}", hello.sni().unwrap_or("?")),
                ));
            }
        }
        for m in &dns_msgs {
            match &m.message {
                DnsMessage::Query(q) => {
                    let n = q.questions.first().map(|q| q.name.as_str()).unwrap_or("?");
                    rows.push((m.ts, format!("DNS  Q  {n}")));
                }
                DnsMessage::Response(r) => {
                    let n = r.questions.first().map(|q| q.name.as_str()).unwrap_or("?");
                    rows.push((m.ts, format!("DNS  R  {n} ({} answers)", r.answers.len())));
                }
                _ => {}
            }
        }
        for m in &icmp_msgs {
            let message = &m.message;
            if let Some((label, inner)) = message.error_inner() {
                rows.push((
                    m.ts,
                    format!(
                        "ICMP {label} referencing {} → {} (proto={})",
                        inner.src, inner.dst, inner.proto
                    ),
                ));
            } else {
                rows.push((
                    m.ts,
                    format!("ICMP {} ({:?})", message.short_kind(), message.family),
                ));
            }
        }
    }

    // Final flush — TLS handshake aggregator and HTTP may have
    // pending state at end-of-input.
    events.clear();
    driver.finish_into(&mut events);
    http_slot.drain(&mut http_msgs);
    tls_slot.drain(&mut tls_msgs);
    dns_slot.drain(&mut dns_msgs);
    icmp_slot.drain(&mut icmp_msgs);

    // Merge by timestamp for chronological output.
    rows.sort_by_key(|(ts, _)| *ts);
    for (ts, line) in rows {
        println!("[{ts}] {line}");
    }

    Ok(())
}

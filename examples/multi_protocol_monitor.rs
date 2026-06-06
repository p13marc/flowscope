//! Plan 91 — multi-protocol monitor over a single pcap.
//!
//! Runs HTTP / TLS / DNS / ICMP parsers in parallel against the
//! same pcap, printing a unified one-line summary per L7 event in
//! observation order.
//!
//! ## Recipe shape
//!
//! Each parser owns its own [`FlowSessionDriver`] /
//! [`FlowDatagramDriver`]; the example reads the pcap once per
//! parser to keep the dispatch logic readable. For per-packet
//! dispatch (one read pass, route by port / L4) see the
//! "Multi-protocol monitoring" section in
//! `docs/SESSION_GUIDE.md` — that pattern is more efficient but
//! harder to read.
//!
//! A real composite driver is on the 0.9 RFC roadmap (round-3
//! wishlist item B2); until then, this example is the canonical
//! reference shape.
//!
//! Usage:
//!     cargo run --features l7,pcap --example multi_protocol_monitor -- trace.pcap

use std::env;

use flowscope::SessionEvent;
use flowscope::dns::{DnsMessage, DnsUdpParser};
use flowscope::extract::FiveTuple;
use flowscope::http::{HttpMessage, HttpParser};
use flowscope::icmp::IcmpParser;
use flowscope::pcap::PcapFlowSource;
use flowscope::tls::{TlsMessage, TlsParser};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args()
        .nth(1)
        .ok_or("usage: multi_protocol_monitor <trace.pcap>")?;

    let mut events: Vec<(flowscope::Timestamp, String)> = Vec::new();

    // ── HTTP ─────────────────────────────────────────────────────
    {
        let source =
            PcapFlowSource::open(&path)?.sessions(FiveTuple::bidirectional(), HttpParser::default());
        for evt in source {
            let evt = evt?;
            if let SessionEvent::Application {
                message: HttpMessage::Request(req),
                ts,
                ..
            } = evt
            {
                events.push((
                    ts,
                    format!(
                        "HTTP {} {} (host={})",
                        req.method,
                        req.path,
                        req.host().unwrap_or("?")
                    ),
                ));
            }
        }
    }

    // ── TLS ──────────────────────────────────────────────────────
    {
        let source =
            PcapFlowSource::open(&path)?.sessions(FiveTuple::bidirectional(), TlsParser::default());
        for evt in source {
            let evt = evt?;
            if let SessionEvent::Application {
                message: TlsMessage::ClientHello(hello),
                ts,
                ..
            } = evt
            {
                events.push((
                    ts,
                    format!("TLS  ClientHello sni={}", hello.sni().unwrap_or("?")),
                ));
            }
        }
    }

    // ── DNS-over-UDP ─────────────────────────────────────────────
    {
        let source = PcapFlowSource::open(&path)?
            .datagrams(FiveTuple::bidirectional(), DnsUdpParser::default());
        for evt in source {
            let evt = evt?;
            if let SessionEvent::Application { message, ts, .. } = evt {
                match message {
                    DnsMessage::Query(q) => {
                        let n = q.questions.first().map(|q| q.name.as_str()).unwrap_or("?");
                        events.push((ts, format!("DNS  Q  {n}")));
                    }
                    DnsMessage::Response(r) => {
                        let n = r.questions.first().map(|q| q.name.as_str()).unwrap_or("?");
                        events.push((
                            ts,
                            format!("DNS  R  {n} ({} answers)", r.answers.len()),
                        ));
                    }
                    _ => {}
                }
            }
        }
    }

    // ── ICMP ─────────────────────────────────────────────────────
    {
        let source =
            PcapFlowSource::open(&path)?.datagrams(FiveTuple::bidirectional(), IcmpParser::new());
        for evt in source {
            let evt = evt?;
            if let SessionEvent::Application { message, ts, .. } = evt {
                if let Some((label, inner)) = message.error_inner() {
                    events.push((
                        ts,
                        format!(
                            "ICMP {label} referencing {} → {} (proto={})",
                            inner.src, inner.dst, inner.proto
                        ),
                    ));
                } else {
                    events.push((ts, format!("ICMP {} ({:?})", message.short_kind(), message.family)));
                }
            }
        }
    }

    // Merge by timestamp for chronological output.
    events.sort_by_key(|(ts, _)| *ts);
    for (ts, line) in events {
        println!("[{ts}] {line}");
    }

    Ok(())
}

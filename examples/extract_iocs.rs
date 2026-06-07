//! Pull every Indicator of Compromise (IoC) candidate out of a
//! pcap and emit a deduplicated list. Useful for incident
//! response and threat-intel pipelines.
//!
//! Extracts:
//! - **Hostnames** — SNI from TLS, Host header from HTTP, DNS
//!   query names.
//! - **IPs** — every src/dst IP from every flow.
//! - **JA3 / JA4** — TLS client fingerprints.
//! - **User-Agents** — from HTTP requests.
//!
//! Output is grouped by category and sorted by frequency.
//!
//! ```bash
//! cargo run --features pcap,http,tls,ja3,ja4,dns,extractors --example extract_iocs
//! ```

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

use flowscope::dns::{DnsMessage, DnsUdpParser};
use flowscope::extract::FiveTuple;
use flowscope::http::{HttpMessage, HttpParser};
use flowscope::pcap::PcapFlowSource;
use flowscope::tls::{TlsHandshakeParser, TlsHandshake};
use flowscope::{FlowDatagramDriver, FlowSessionDriver, FlowTracker, SessionEvent};

#[derive(Default)]
struct Iocs {
    hostnames: HashMap<String, (u32, &'static str)>,
    ips: BTreeSet<IpAddr>,
    user_agents: HashMap<String, u32>,
    ja3s: HashMap<String, u32>,
    ja4s: HashMap<String, u32>,
}

fn main() -> flowscope::Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    // Run three drivers in parallel: HTTP/TLS (TCP) + DNS (UDP).
    let mut http_driver =
        FlowSessionDriver::new(FiveTuple::bidirectional(), HttpParser::default());
    let mut tls_driver =
        FlowSessionDriver::new(FiveTuple::bidirectional(), TlsHandshakeParser::default());
    let mut dns_driver =
        FlowDatagramDriver::new(FiveTuple::bidirectional(), DnsUdpParser::default());
    let mut flow_tracker = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());

    let mut iocs = Iocs::default();

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        for ev in flow_tracker.track(&owned) {
            if let flowscope::FlowEvent::Started { key, .. } = ev {
                iocs.ips.insert(key.a.ip());
                iocs.ips.insert(key.b.ip());
            }
        }
        for ev in http_driver.track(&owned) {
            handle_http(&mut iocs, ev);
        }
        for ev in tls_driver.track(&owned) {
            handle_tls(&mut iocs, ev);
        }
        for ev in dns_driver.track(&owned) {
            handle_dns(&mut iocs, ev);
        }
    }
    for ev in http_driver.finish() { handle_http(&mut iocs, ev); }
    for ev in tls_driver.finish() { handle_tls(&mut iocs, ev); }
    for ev in dns_driver.finish() { handle_dns(&mut iocs, ev); }

    println!("=== Hostnames ({}) ===", iocs.hostnames.len());
    let mut h: Vec<_> = iocs.hostnames.into_iter().collect();
    h.sort_by_key(|(_, (c, _))| std::cmp::Reverse(*c));
    for (name, (count, source)) in h.iter().take(40) {
        println!("  {count:>4} {source:<6} {name}");
    }
    println!();

    println!("=== IPs ({}) ===", iocs.ips.len());
    for ip in &iocs.ips {
        println!("  {ip}");
    }
    println!();

    println!("=== HTTP User-Agents ===");
    print_top(&iocs.user_agents, 20);
    println!();

    println!("=== JA3 fingerprints ===");
    print_top(&iocs.ja3s, 20);
    println!();

    println!("=== JA4 fingerprints ===");
    print_top(&iocs.ja4s, 20);
    Ok(())
}

fn handle_http(
    iocs: &mut Iocs,
    ev: SessionEvent<flowscope::extract::FiveTupleKey, HttpMessage>,
) {
    let SessionEvent::Application { message, .. } = ev else { return };
    if let HttpMessage::Request(req) = message {
        for (name, val) in &req.headers {
            if name.eq_ignore_ascii_case("host") {
                let h = String::from_utf8_lossy(val).to_string();
                let entry = iocs.hostnames.entry(h).or_insert((0, "http"));
                entry.0 += 1;
            }
            if name.eq_ignore_ascii_case("user-agent") {
                let ua = String::from_utf8_lossy(val).to_string();
                *iocs.user_agents.entry(ua).or_default() += 1;
            }
        }
    }
}

fn handle_tls(
    iocs: &mut Iocs,
    ev: SessionEvent<flowscope::extract::FiveTupleKey, TlsHandshake>,
) {
    let SessionEvent::Application { message, .. } = ev else { return };
    if let Some(sni) = message.sni {
        let entry = iocs.hostnames.entry(sni).or_insert((0, "tls"));
        entry.0 += 1;
    }
    if let Some(ja3) = message.ja3 {
        *iocs.ja3s.entry(ja3).or_default() += 1;
    }
    if let Some(ja4) = message.ja4 {
        *iocs.ja4s.entry(ja4).or_default() += 1;
    }
}

fn handle_dns(
    iocs: &mut Iocs,
    ev: SessionEvent<flowscope::extract::FiveTupleKey, DnsMessage>,
) {
    let SessionEvent::Application { message, .. } = ev else { return };
    let names: Vec<String> = match message {
        DnsMessage::Query(q) => q.questions.iter().map(|q| q.name.clone()).collect(),
        DnsMessage::Response(r) => r.questions.iter().map(|q| q.name.clone()).collect(),
        _ => Vec::new(),
    };
    for n in names {
        let entry = iocs.hostnames.entry(n).or_insert((0, "dns"));
        entry.0 += 1;
    }
}

fn print_top(counts: &HashMap<String, u32>, n: usize) {
    let mut sorted: Vec<_> = counts.iter().collect();
    sorted.sort_by_key(|(_, c)| std::cmp::Reverse(**c));
    for (key, count) in sorted.iter().take(n) {
        println!("  {count:>4} {key}");
    }
    if counts.is_empty() {
        println!("  (none)");
    }
}

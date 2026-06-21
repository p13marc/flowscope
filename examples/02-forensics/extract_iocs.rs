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
//! cargo run --features pcap,http,tls,tls-fingerprints,dns,extractors --example extract_iocs
//! ```

use std::{
    collections::{BTreeSet, HashMap},
    net::IpAddr,
};

use flowscope::{
    dns::{DnsMessage, DnsUdpParser},
    driver::{Driver, Event, SlotMessage},
    extract::{FiveTuple, FiveTupleKey},
    http::{HttpMessage, HttpParser},
    pcap::PcapFlowSource,
    tls::{TlsHandshake, TlsHandshakeParser},
};

#[derive(Default)]
struct Iocs {
    hostnames: HashMap<String, (u32, &'static str)>,
    ips: BTreeSet<IpAddr>,
    user_agents: HashMap<String, u32>,
    ja3s: HashMap<String, u32>,
    ja4s: HashMap<String, u32>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    // One unified driver with HTTP (TCP/80,8080), TLS handshake
    // (TCP/443,8443), and DNS (UDP/53) slots.
    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut http_slot = builder.session_on_ports(HttpParser::default(), [80, 8080]);
    let mut tls_slot = builder.session_on_ports(TlsHandshakeParser::default(), [443, 8443]);
    let mut dns_slot = builder.datagram_on_ports(DnsUdpParser::default(), [53]);
    let mut driver = builder.build();

    let mut iocs = Iocs::default();
    let mut events: Vec<Event<FiveTupleKey>> = Vec::new();
    let mut http_msgs: Vec<SlotMessage<HttpMessage, FiveTupleKey>> = Vec::new();
    let mut tls_msgs: Vec<SlotMessage<TlsHandshake, FiveTupleKey>> = Vec::new();
    let mut dns_msgs: Vec<SlotMessage<DnsMessage, FiveTupleKey>> = Vec::new();

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

        for ev in &events {
            if let Event::FlowStarted { key, .. } = ev {
                iocs.ips.insert(key.a.ip());
                iocs.ips.insert(key.b.ip());
            }
        }
        for m in &http_msgs {
            handle_http(&mut iocs, &m.message);
        }
        for m in &tls_msgs {
            handle_tls(&mut iocs, &m.message);
        }
        for m in &dns_msgs {
            handle_dns(&mut iocs, &m.message);
        }
    }

    events.clear();
    driver.finish_into(&mut events);
    http_msgs.clear();
    http_slot.drain(&mut http_msgs);
    tls_msgs.clear();
    tls_slot.drain(&mut tls_msgs);
    dns_msgs.clear();
    dns_slot.drain(&mut dns_msgs);
    for m in &http_msgs {
        handle_http(&mut iocs, &m.message);
    }
    for m in &tls_msgs {
        handle_tls(&mut iocs, &m.message);
    }
    for m in &dns_msgs {
        handle_dns(&mut iocs, &m.message);
    }

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

fn handle_http(iocs: &mut Iocs, message: &HttpMessage) {
    if let HttpMessage::Request(req) = message {
        for (name, val) in &req.headers {
            if name.as_ref().eq_ignore_ascii_case(b"host") {
                let h = String::from_utf8_lossy(val).to_string();
                let entry = iocs.hostnames.entry(h).or_insert((0, "http"));
                entry.0 += 1;
            }
            if name.as_ref().eq_ignore_ascii_case(b"user-agent") {
                let ua = String::from_utf8_lossy(val).to_string();
                *iocs.user_agents.entry(ua).or_default() += 1;
            }
        }
    }
}

fn handle_tls(iocs: &mut Iocs, message: &TlsHandshake) {
    if let Some(sni) = message.sni.clone() {
        let entry = iocs.hostnames.entry(sni).or_insert((0, "tls"));
        entry.0 += 1;
    }
    if let Some(ja3) = message.ja3.clone() {
        *iocs.ja3s.entry(ja3).or_default() += 1;
    }
    if let Some(ja4) = message.ja4.clone() {
        *iocs.ja4s.entry(ja4).or_default() += 1;
    }
}

fn handle_dns(iocs: &mut Iocs, message: &DnsMessage) {
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

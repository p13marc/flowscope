//! Per-host client-software catalog joining multiple
//! fingerprinting techniques in one pcap walk.
//!
//! Real operators want one row per source IP listing every
//! client-software signal the wire revealed:
//!
//! - **JA3** (TLS client) — Salesforce 2017,
//!   <https://github.com/salesforce/ja3>.
//! - **JA4** (TLS client v4) — FoxIO,
//!   <https://github.com/FoxIO-LLC/ja4>.
//! - **JA4H** (HTTP client) — FoxIO,
//!   <https://github.com/FoxIO-LLC/ja4>.
//! - **HASSH** (SSH client) — Salesforce,
//!   <https://github.com/salesforce/hassh>.
//! - **HTTP User-Agent** — RFC 9110.
//!
//! When the **same TCP fingerprint** appears with different
//! TLS / HTTP / SSH stacks across flows from one source IP,
//! that's the canonical "same OS, multiple browsers" signal —
//! or, less benignly, an evasion attempt.
//!
//! ## Extension points
//!
//! - For TCP-layer (p0f-style) fingerprints, combine with
//!   [`flowscope::tcp_fingerprint::TcpFingerprint`] under the
//!   `tcp_fingerprint` feature.
//! - For OS fingerprinting via DHCP option-55, combine with
//!   [`flowscope::dhcp::DhcpMessage::fingerbank_fingerprint`]
//!   under the `dhcp` feature.
//!
//! ## Usage
//!
//! ```bash
//! cargo run --features "pcap,extractors,tracker,tls,tls-fingerprints,http,ssh" \
//!     --example client_fingerprint_catalog -- trace.pcap
//! ```
//!
//! Closes #44.

use std::collections::HashMap;
use std::net::IpAddr;

use flowscope::driver::{Driver, Event, SlotMessage};
use flowscope::extract::{FiveTuple, FiveTupleKey};
#[cfg(feature = "ja4plus")]
use flowscope::http::ja4h_fingerprint;
use flowscope::http::{HttpMessage, HttpParser};
use flowscope::pcap::PcapFlowSource;
use flowscope::ssh::{SshMessage, SshParser};
use flowscope::tls::{TlsHandshake, TlsHandshakeParser};

#[derive(Default, Debug)]
struct ClientCatalog {
    ja3: Vec<String>,
    ja4: Vec<String>,
    ja4h: Vec<String>,
    hassh: Vec<String>,
    user_agent: Vec<String>,
}

impl ClientCatalog {
    fn push_unique(slot: &mut Vec<String>, value: String) {
        if !slot.iter().any(|v| v == &value) {
            slot.push(value);
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut tls_slot = builder.session_on_ports(TlsHandshakeParser::default(), [443, 8443]);
    let mut http_slot = builder.session_on_ports(HttpParser::default(), [80, 8080, 8000]);
    let mut ssh_slot = builder.session_on_ports(SshParser::default(), [22]);
    let mut driver = builder.build();

    let mut catalog: HashMap<IpAddr, ClientCatalog> = HashMap::new();
    let mut events: Vec<Event<FiveTupleKey>> = Vec::new();
    let mut tls_msgs: Vec<SlotMessage<TlsHandshake, FiveTupleKey>> = Vec::new();
    let mut http_msgs: Vec<SlotMessage<HttpMessage, FiveTupleKey>> = Vec::new();
    let mut ssh_msgs: Vec<SlotMessage<SshMessage, FiveTupleKey>> = Vec::new();

    for view in PcapFlowSource::open(&path)?.views() {
        let view = view?;
        events.clear();
        driver.track_into(&view, &mut events);

        tls_msgs.clear();
        tls_slot.drain(&mut tls_msgs);
        for m in tls_msgs.drain(..) {
            let src = m.key.a.ip();
            let entry = catalog.entry(src).or_default();
            if let Some(s) = m.message.ja3 {
                ClientCatalog::push_unique(&mut entry.ja3, s);
            }
            if let Some(s) = m.message.ja4 {
                ClientCatalog::push_unique(&mut entry.ja4, s);
            }
        }

        http_msgs.clear();
        http_slot.drain(&mut http_msgs);
        for m in http_msgs.drain(..) {
            if let HttpMessage::Request(req) = m.message {
                let src = m.key.a.ip();
                let entry = catalog.entry(src).or_default();
                if let Some(ua) = req.user_agent() {
                    ClientCatalog::push_unique(&mut entry.user_agent, ua.to_string());
                }
                #[cfg(feature = "ja4plus")]
                ClientCatalog::push_unique(&mut entry.ja4h, ja4h_fingerprint(&req));
            }
        }

        ssh_msgs.clear();
        ssh_slot.drain(&mut ssh_msgs);
        for m in ssh_msgs.drain(..) {
            if let SshMessage::KexInit(kex) = m.message
                && kex.from_client
            {
                let src = m.key.a.ip();
                let entry = catalog.entry(src).or_default();
                ClientCatalog::push_unique(&mut entry.hassh, kex.hassh);
            }
        }
    }

    println!("=== Client fingerprint catalog ===");
    println!("(one row per source IP; '-' = signal not observed)");
    println!();
    println!(
        "{:<24} {:<6} {:<6} {:<6} {:<6} {:<6}",
        "source", "JA3", "JA4", "JA4H", "HASSH", "UA"
    );
    let mut keys: Vec<_> = catalog.keys().collect();
    keys.sort();
    for src in keys {
        let cat = &catalog[src];
        println!(
            "{src:<24} {:<6} {:<6} {:<6} {:<6} {:<6}",
            cnt(&cat.ja3),
            cnt(&cat.ja4),
            cnt(&cat.ja4h),
            cnt(&cat.hassh),
            cnt(&cat.user_agent),
        );
    }

    println!();
    println!("--- per-IP detail ---");
    for src in catalog.keys() {
        let cat = &catalog[src];
        println!("{src}:");
        print_field("JA3", &cat.ja3);
        print_field("JA4", &cat.ja4);
        print_field("JA4H", &cat.ja4h);
        print_field("HASSH", &cat.hassh);
        print_field("User-Agent", &cat.user_agent);
    }
    Ok(())
}

fn cnt(v: &[String]) -> String {
    if v.is_empty() {
        "-".to_string()
    } else {
        v.len().to_string()
    }
}

fn print_field(label: &str, values: &[String]) {
    if values.is_empty() {
        return;
    }
    for v in values {
        println!("  {label:<12} {v}");
    }
}

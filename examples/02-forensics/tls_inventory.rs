//! Inventory every TLS handshake observed in a pcap.
//!
//! Surfaces every operationally-relevant field the
//! [`TlsHandshakeParser`] aggregator (plan 97, 0.9) emits — SNI,
//! ALPN, JA3, JA4, plus the 0.18-cycle additions:
//!
//! - **`certificate_chain`** — leaf-first TLS 1.2 cert chain
//!   (count of DER-encoded certs, since the bytes are big).
//! - **`ja4x`** — JA4X server-cert fingerprint (gated on
//!   `ja4plus`, FoxIO License 1.1).
//! - **`ech_outcome`** — Encrypted ClientHello state
//!   (NotOffered / Accepted / Rejected / Unknown).
//! - **`resumption_attempted`** — client sent PSK / session-
//!   ticket extensions.
//!
//! Plus per-version bucketing — any handshake at TLS < 1.2 is
//! flagged as a compliance signal (PCI-DSS 3.2.1, HIPAA, NIST
//! SP 800-52). On `AlertedByServer`, the raw
//! [TLS AlertDescription](https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-6)
//! code is printed alongside the variant name.
//!
//! ## MITRE ATT&CK
//!
//! - [T1573.002](https://attack.mitre.org/techniques/T1573/002/)
//!   — Encrypted Channel: Asymmetric Cryptography. ECH outcomes
//!   and cert-chain anomalies fall under this lens.
//! - [T1071.001](https://attack.mitre.org/techniques/T1071/001/)
//!   — Application Layer Protocol: Web Protocols (TLS as a C2
//!   carrier).
//!
//! ## Usage
//!
//! ```bash
//! cargo run --features "tls,tls-fingerprints,pcap" \
//!     --example tls_inventory -- trace.pcap
//!
//! # Add JA4S + JA4X server-side fingerprints (FoxIO License 1.1):
//! cargo run --features "tls,tls-fingerprints,ja4plus,pcap" \
//!     --example tls_inventory -- trace.pcap
//! ```

use std::collections::HashMap;

use flowscope::driver::{Driver, Event, SlotMessage};
use flowscope::extract::{FiveTuple, FiveTupleKey};
use flowscope::pcap::PcapFlowSource;
use flowscope::tls::{EchOutcome, HandshakeOutcome, TlsHandshake, TlsHandshakeParser, TlsVersion};

#[derive(Default, Debug)]
struct Inventory {
    handshakes: Vec<TlsHandshake>,
    sni: HashMap<String, u32>,
    ja3: HashMap<String, u32>,
    ja4: HashMap<String, u32>,
    #[cfg(feature = "ja4plus")]
    ja4x: HashMap<String, u32>,
    versions: HashMap<&'static str, u32>,
    outcomes: HashMap<String, u32>,
    ech: HashMap<&'static str, u32>,
    resumption_attempts: u32,
    cert_chains_seen: u32,
    insecure_pre_tls12: u32,
}

fn version_label(v: TlsVersion) -> &'static str {
    match v {
        TlsVersion::Ssl3_0 => "SSL 3.0",
        TlsVersion::Tls1_0 => "TLS 1.0",
        TlsVersion::Tls1_1 => "TLS 1.1",
        TlsVersion::Tls1_2 => "TLS 1.2",
        TlsVersion::Tls1_3 => "TLS 1.3",
        _ => "other",
    }
}

fn ech_label(e: EchOutcome) -> &'static str {
    match e {
        EchOutcome::NotOffered => "not-offered",
        EchOutcome::Accepted => "accepted",
        EchOutcome::Rejected => "rejected",
        EchOutcome::Unknown => "unknown",
        _ => "other",
    }
}

fn account(inv: &mut Inventory, h: TlsHandshake) {
    if let Some(sni) = h.sni.as_ref() {
        *inv.sni.entry(sni.clone()).or_default() += 1;
    }
    if let Some(s) = h.ja3.as_ref() {
        *inv.ja3.entry(s.clone()).or_default() += 1;
    }
    if let Some(s) = h.ja4.as_ref() {
        *inv.ja4.entry(s.clone()).or_default() += 1;
    }
    #[cfg(feature = "ja4plus")]
    if let Some(s) = h.ja4x.as_ref() {
        *inv.ja4x.entry(s.clone()).or_default() += 1;
    }

    if let Some(v) = h.version {
        let label = version_label(v);
        *inv.versions.entry(label).or_default() += 1;
        if matches!(
            v,
            TlsVersion::Ssl3_0 | TlsVersion::Tls1_0 | TlsVersion::Tls1_1
        ) {
            inv.insecure_pre_tls12 += 1;
        }
    }

    let outcome_label = match h.outcome {
        HandshakeOutcome::Completed => "completed".to_string(),
        HandshakeOutcome::AlertedByServer { description } => {
            format!("alerted-by-server({description})")
        }
        HandshakeOutcome::AlertedByClient { description } => {
            format!("alerted-by-client({description})")
        }
        HandshakeOutcome::Truncated => "truncated".to_string(),
        _ => "other".to_string(),
    };
    *inv.outcomes.entry(outcome_label).or_default() += 1;
    *inv.ech.entry(ech_label(h.ech_outcome)).or_default() += 1;
    if h.resumption_attempted {
        inv.resumption_attempts += 1;
    }
    if !h.certificate_chain.is_empty() {
        inv.cert_chains_seen += 1;
    }

    inv.handshakes.push(h);
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut tls_slot = builder.session_on_ports(TlsHandshakeParser::default(), [443, 8443]);
    let mut driver = builder.build();

    let mut inv = Inventory::default();
    let mut events: Vec<Event<FiveTupleKey>> = Vec::new();
    let mut msgs: Vec<SlotMessage<TlsHandshake, FiveTupleKey>> = Vec::new();

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        events.clear();
        driver.track_into(&owned, &mut events);
        msgs.clear();
        tls_slot.drain(&mut msgs);
        for m in msgs.drain(..) {
            account(&mut inv, m.message);
        }
    }
    events.clear();
    driver.finish_into(&mut events);
    msgs.clear();
    tls_slot.drain(&mut msgs);
    for m in msgs.drain(..) {
        account(&mut inv, m.message);
    }

    println!("=== TLS handshake inventory ===");
    println!("Total handshakes:           {}", inv.handshakes.len());
    println!("Cert chains observed:       {}", inv.cert_chains_seen);
    println!("Resumption attempts:        {}", inv.resumption_attempts);
    println!(
        "Insecure (< TLS 1.2):       {}{}",
        inv.insecure_pre_tls12,
        if inv.insecure_pre_tls12 > 0 {
            "  ⚠ PCI-DSS / HIPAA compliance signal"
        } else {
            ""
        },
    );
    println!();

    println!("--- Versions ---");
    let mut by_version: Vec<_> = inv.versions.iter().collect();
    by_version.sort_by_key(|(_, c)| std::cmp::Reverse(**c));
    for (v, c) in by_version {
        println!("  {v:<10} {c}");
    }
    println!();

    println!("--- ECH outcomes ---");
    let mut by_ech: Vec<_> = inv.ech.iter().collect();
    by_ech.sort_by_key(|(_, c)| std::cmp::Reverse(**c));
    for (e, c) in by_ech {
        println!("  {e:<14} {c}");
    }
    println!();

    println!("--- Outcomes ---");
    let mut by_outcome: Vec<_> = inv.outcomes.iter().collect();
    by_outcome.sort_by_key(|(_, c)| std::cmp::Reverse(**c));
    for (kind, count) in by_outcome {
        println!("  {kind:<30} {count}");
    }
    println!();

    println!("--- Top SNI ---");
    print_top_n(&inv.sni, 10);
    println!();
    println!("--- Top JA3 fingerprints ---");
    print_top_n(&inv.ja3, 10);
    println!();
    println!("--- Top JA4 fingerprints ---");
    print_top_n(&inv.ja4, 10);
    #[cfg(feature = "ja4plus")]
    {
        println!();
        println!("--- Top JA4X cert fingerprints ---");
        print_top_n(&inv.ja4x, 10);
    }

    Ok(())
}

fn print_top_n(counts: &HashMap<String, u32>, n: usize) {
    let mut sorted: Vec<_> = counts.iter().collect();
    sorted.sort_by_key(|(_, c)| std::cmp::Reverse(**c));
    for (key, count) in sorted.iter().take(n) {
        println!("  {count:>5} {key}");
    }
    if counts.is_empty() {
        println!("  (none)");
    }
}

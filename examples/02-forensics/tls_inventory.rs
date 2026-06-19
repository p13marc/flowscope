//! Inventory every TLS handshake observed in a pcap: SNI, ALPN,
//! JA3, JA4, and outcome. Common starting point for forensics
//! (IoC enumeration), threat intel (fingerprint catalogs), and
//! SSL/TLS observability dashboards.
//!
//! Uses [`TlsHandshakeParser`] — the 0.9 aggregator that bundles
//! ClientHello + ServerHello + Alert into one event per
//! handshake.
//!
//! ```bash
//! cargo run --features tls,tls-fingerprints,pcap --example tls_inventory
//! ```

use std::collections::HashMap;

use flowscope::{
    driver::{Driver, Event, SlotMessage},
    extract::{FiveTuple, FiveTupleKey},
    pcap::PcapFlowSource,
    tls::{HandshakeOutcome, TlsHandshake, TlsHandshakeParser},
};

fn main() -> flowscope::Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut tls_slot = builder.session_on_ports(TlsHandshakeParser::default(), [443, 8443]);
    let mut driver = builder.build();

    let mut handshakes = Vec::new();
    let mut sni_counts: HashMap<String, u32> = HashMap::new();
    let mut ja3_counts: HashMap<String, u32> = HashMap::new();
    let mut ja4_counts: HashMap<String, u32> = HashMap::new();
    let mut outcomes: HashMap<&'static str, u32> = HashMap::new();

    let mut events: Vec<Event<FiveTupleKey>> = Vec::new();
    let mut msgs: Vec<SlotMessage<TlsHandshake, FiveTupleKey>> = Vec::new();

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        events.clear();
        driver.track_into(&owned, &mut events);
        msgs.clear();
        tls_slot.drain(&mut msgs);
        for m in msgs.drain(..) {
            account(
                &mut handshakes,
                &mut sni_counts,
                &mut ja3_counts,
                &mut ja4_counts,
                &mut outcomes,
                m.message,
            );
        }
    }

    events.clear();
    driver.finish_into(&mut events);
    msgs.clear();
    tls_slot.drain(&mut msgs);
    for m in msgs.drain(..) {
        account(
            &mut handshakes,
            &mut sni_counts,
            &mut ja3_counts,
            &mut ja4_counts,
            &mut outcomes,
            m.message,
        );
    }

    println!("=== TLS handshake inventory ===");
    println!("Total handshakes: {}", handshakes.len());
    println!();

    println!("--- Outcomes ---");
    let mut by_outcome: Vec<_> = outcomes.iter().collect();
    by_outcome.sort_by_key(|(_, c)| std::cmp::Reverse(**c));
    for (kind, count) in by_outcome {
        println!("  {kind:<20} {count}");
    }
    println!();

    println!("--- Top SNI ---");
    print_top_n(&sni_counts, 10);
    println!();
    println!("--- Top JA3 fingerprints ---");
    print_top_n(&ja3_counts, 10);
    println!();
    println!("--- Top JA4 fingerprints ---");
    print_top_n(&ja4_counts, 10);

    Ok(())
}

fn account(
    handshakes: &mut Vec<TlsHandshake>,
    snis: &mut HashMap<String, u32>,
    ja3s: &mut HashMap<String, u32>,
    ja4s: &mut HashMap<String, u32>,
    outcomes: &mut HashMap<&'static str, u32>,
    h: TlsHandshake,
) {
    if let Some(sni) = h.sni.as_ref() {
        *snis.entry(sni.clone()).or_default() += 1;
    }
    if let Some(ja3) = h.ja3.as_ref() {
        *ja3s.entry(ja3.clone()).or_default() += 1;
    }
    if let Some(ja4) = h.ja4.as_ref() {
        *ja4s.entry(ja4.clone()).or_default() += 1;
    }
    let kind = match h.outcome {
        HandshakeOutcome::Completed => "completed",
        HandshakeOutcome::AlertedByServer { .. } => "alerted-by-server",
        HandshakeOutcome::AlertedByClient { .. } => "alerted-by-client",
        HandshakeOutcome::Truncated => "truncated",
        _ => "other",
    };
    *outcomes.entry(kind).or_default() += 1;
    handshakes.push(h);
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

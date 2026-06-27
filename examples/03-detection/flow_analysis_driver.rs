//! `flow_analysis_driver` — the full end-to-end #83 wiring: a real
//! typed [`Driver`] over a pcap feeding a [`FlowAnalyzer`], emitting
//! enriched EVE records on flow end.
//!
//! This is the "driver seam" the synthetic `flow_analysis` example
//! abstracts away. The pattern is:
//!
//! 1. register parsers on the [`Driver`] — each returns a typed
//!    `SlotHandle`;
//! 2. per packet, `track_into` produces lifecycle `Event`s while
//!    the slots fill with typed messages;
//! 3. drain the slots and feed each message to the analyzer
//!    (`observe_*`, keyed by the message's flow key);
//! 4. on each `Event::FlowEnded`, `finalize` the flow → an
//!    [`AnalyzedFlow`] you log / ship.
//!
//! Run:
//! ```text
//! cargo run --example flow_analysis_driver --features \
//!   analysis,tls,dns,pcap,emit-eve -- tests/data/mixed_short.pcap
//! ```

use std::time::Duration;

use flowscope::analysis::FlowAnalyzer;
use flowscope::dns::{DnsMessage, DnsUdpParser};
use flowscope::driver::{Driver, Event, SlotHandle, SlotMessage};
use flowscope::emit::EveJsonWriter;
use flowscope::extract::{FiveTuple, FiveTupleKey};
use flowscope::pcap::PcapFlowSource;
use flowscope::tls::{TlsHandshake, TlsHandshakeParser};

/// Drain the parser slots into the analyzer, then finalize every
/// flow that ended this batch — writing the non-clean ones as EVE.
/// Returns `(analyzed, alerted)` deltas.
fn pump(
    events: &[Event<FiveTupleKey>],
    tls_slot: &mut SlotHandle<TlsHandshake, FiveTupleKey>,
    dns_slot: &mut SlotHandle<DnsMessage, FiveTupleKey>,
    analyzer: &mut FlowAnalyzer<FiveTupleKey>,
    eve: &mut EveJsonWriter<std::io::StdoutLock<'static>>,
) -> std::io::Result<(usize, usize)> {
    let mut tls_msgs: Vec<SlotMessage<TlsHandshake, FiveTupleKey>> = Vec::new();
    let mut dns_msgs: Vec<SlotMessage<DnsMessage, FiveTupleKey>> = Vec::new();
    tls_slot.drain(&mut tls_msgs);
    dns_slot.drain(&mut dns_msgs);

    for m in &tls_msgs {
        analyzer.observe_tls(&m.key, &m.message, m.ts);
    }
    for m in &dns_msgs {
        match &m.message {
            DnsMessage::Query(q) | DnsMessage::Unanswered(q) => {
                analyzer.observe_dns_query(&m.key, q, m.ts)
            }
            DnsMessage::Response(r) => analyzer.observe_dns_response(&m.key, r, m.ts),
            _ => {}
        }
    }

    let (mut analyzed, mut alerted) = (0, 0);
    for ev in events {
        if let Event::FlowEnded { key, stats, .. } = ev {
            let rec = analyzer.finalize(key, stats.clone());
            analyzed += 1;
            if !rec.is_clean() {
                alerted += 1;
            }
            // Emit every flow as EVE (clean flows are valid records
            // too — the `flowscope` block is simply absent). Filter
            // on `rec.is_clean()` here if you only want alerts.
            eve.write_analyzed_flow(&rec)?;
        }
    }
    Ok((analyzed, alerted))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".into());

    // 1. Build the driver: TLS handshakes on 443/8443, DNS on 53.
    //    Each registration hands back a typed drain handle.
    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut tls_slot = builder.session_on_ports(TlsHandshakeParser::default(), [443, 8443]);
    let mut dns_slot = builder.datagram_on_ports(DnsUdpParser::default(), [53]);
    let mut driver = builder.build();

    // 2. The analyzer — bounded; add `.with_ioc(set)` to screen
    //    against a threat-intel feed.
    let mut analyzer =
        FlowAnalyzer::<FiveTupleKey>::with_capacity(Duration::from_secs(120), 100_000);

    let mut eve = EveJsonWriter::new(std::io::stdout().lock());
    let (mut analyzed, mut alerted) = (0usize, 0usize);
    let mut events: Vec<Event<FiveTupleKey>> = Vec::new();

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        events.clear();
        driver.track_into(&owned, &mut events);
        let (a, b) = pump(
            &events,
            &mut tls_slot,
            &mut dns_slot,
            &mut analyzer,
            &mut eve,
        )?;
        analyzed += a;
        alerted += b;
    }

    // Final flush: close out still-open flows.
    events.clear();
    driver.finish_into(&mut events);
    let (a, b) = pump(
        &events,
        &mut tls_slot,
        &mut dns_slot,
        &mut analyzer,
        &mut eve,
    )?;
    analyzed += a;
    alerted += b;

    eprintln!("\nanalyzed {analyzed} flows, {alerted} non-clean (EVE above)");
    Ok(())
}

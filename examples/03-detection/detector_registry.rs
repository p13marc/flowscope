//! `detector_registry` — the unified `DetectorRegistry` over a
//! real typed `Driver` (issue #131).
//!
//! Register a heterogeneous detector set once, then drive them
//! all from one event stream instead of hand-wiring each:
//!
//! 1. build the `Driver` (DNS on 53 for the DGA feed) — its slot
//!    hands back a typed drain handle;
//! 2. register detectors on a `DetectorRegistry` keyed by the
//!    flow key; the beacon/scan detectors pivot internally to
//!    their own aggregation keys (`HostPair` / `SrcHost`);
//! 3. per packet, `track_into` yields lifecycle `Event`s →
//!    `registry.observe_event`; drain the DNS slot →
//!    `registry.observe_dns` per query name;
//! 4. route the accumulated `OwnedAnomaly` buffer to EVE (each
//!    carries its `DetectorKind` slug + MITRE ATT&CK technique).
//!
//! Contrast `composite_c2`, which fuses cross-signal ∧-logic (a
//! host flagged by ≥ 2 of beacon/DGA/weak-TLS): the registry
//! deliberately keeps detectors independent — each emits its own
//! anomaly — so downstream policy composes them however it likes.
//!
//! Run:
//! ```text
//! cargo run --example detector_registry --features \
//!   tracker,dns,pcap,emit-eve -- tests/data/mixed_short.pcap | jq .
//! ```

use flowscope::OwnedAnomaly;
use flowscope::detect::patterns::{BeaconDetector, PortScanDetector, RitaBeaconDetector};
use flowscope::detect::{DetectorRegistry, DgaDetector, HostPair, SrcHost};
use flowscope::dns::{DnsMessage, DnsUdpParser};
use flowscope::driver::{Driver, Event, SlotHandle, SlotMessage};
use flowscope::emit::EveJsonWriter;
use flowscope::extract::{FiveTuple, FiveTupleKey};
use flowscope::pcap::PcapFlowSource;

/// Feed this batch's lifecycle events + DNS query names into the
/// registry, then flush any anomalies to EVE. Returns how many
/// anomalies fired.
fn pump(
    events: &[Event<FiveTupleKey>],
    dns_slot: &mut SlotHandle<DnsMessage, FiveTupleKey>,
    registry: &mut DetectorRegistry<FiveTupleKey>,
    anomalies: &mut Vec<OwnedAnomaly>,
    eve: &mut EveJsonWriter<std::io::StdoutLock<'static>>,
) -> std::io::Result<usize> {
    anomalies.clear();

    // Flow-lifecycle events (Started / Established / Ended / Tick).
    for ev in events {
        registry.observe_event(ev, anomalies);
    }

    // DNS query names → the DGA detector.
    let mut dns_msgs: Vec<SlotMessage<DnsMessage, FiveTupleKey>> = Vec::new();
    dns_slot.drain(&mut dns_msgs);
    for m in &dns_msgs {
        if let DnsMessage::Query(q) | DnsMessage::Unanswered(q) = &m.message
            && let Some(question) = q.questions.first()
        {
            registry.observe_dns(&m.key, &question.name, m.ts, anomalies);
        }
    }

    for a in anomalies.iter() {
        eve.write_owned_anomaly(a)?;
    }
    Ok(anomalies.len())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".into());

    // 1. Driver: DNS on 53 (the DGA feed). Add session/datagram
    //    slots for other parsers as needed.
    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut dns_slot = builder.datagram_on_ports(DnsUdpParser::default(), [53]);
    let mut driver = builder.build();

    // 2. One registry, four detectors — register once, drive from
    //    one call. Beacon/scan pivot to their aggregation keys
    //    internally; DGA feeds off DNS query names.
    let mut registry: DetectorRegistry<FiveTupleKey> = DetectorRegistry::new();
    registry
        .register(BeaconDetector::<HostPair>::new())
        .register(RitaBeaconDetector::<HostPair>::new())
        .register(PortScanDetector::<SrcHost>::new())
        .register(DgaDetector::new());
    eprintln!(
        "registered detectors: {:?}",
        registry.kinds().collect::<Vec<_>>()
    );

    let mut eve = EveJsonWriter::new(std::io::stdout().lock());
    let mut events: Vec<Event<FiveTupleKey>> = Vec::new();
    let mut anomalies: Vec<OwnedAnomaly> = Vec::new();
    let mut fired = 0usize;

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        events.clear();
        driver.track_into(&owned, &mut events);
        fired += pump(
            &events,
            &mut dns_slot,
            &mut registry,
            &mut anomalies,
            &mut eve,
        )?;
    }

    // Final flush — close out still-open flows so end-of-flow
    // detectors (beacon / scan) see them.
    events.clear();
    driver.finish_into(&mut events);
    fired += pump(
        &events,
        &mut dns_slot,
        &mut registry,
        &mut anomalies,
        &mut eve,
    )?;

    eprintln!(
        "\n{fired} anomalies emitted (EVE above); registry tracked {} keys",
        registry.tracked()
    );
    Ok(())
}

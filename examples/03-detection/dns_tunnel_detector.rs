//! Detect probable DNS tunneling with the upstreamed
//! [`DnsTunnelDetector`] (issue #132) driven through a
//! [`DetectorRegistry`].
//!
//! DNS tunneling smuggles data inside the QNAME's subdomain
//! labels, so a tunnel produces an unusually large number of
//! **distinct**, long query names under one registered domain in
//! a short window. `DnsTunnelDetector` counts distinct long
//! subdomains per `(source, registered-domain)` and fires a
//! cooldown-gated anomaly when the count crosses its threshold —
//! the running-state version of the entropy+rate heuristic this
//! example used to hand-roll.
//!
//! ```bash
//! cargo run --features tracker,pcap,dns,emit-eve \
//!   --example dns_tunnel_detector -- tests/data/dns_queries.pcap | jq .
//! ```
//!
//! ## MITRE ATT&CK
//!
//! - [T1071.004](https://attack.mitre.org/techniques/T1071/004/)
//!   — Application Layer Protocol: DNS. Emitted automatically on
//!   the anomaly as `attack_technique` (via
//!   [`DetectorKind::attack_technique`]).
//! - [T1048.003](https://attack.mitre.org/techniques/T1048/003/)
//!   — Exfiltration Over Unencrypted Non-C2 Protocol (when used
//!   for data exfil rather than C2).
//!
//! ## Known false positives
//!
//! - CDN edge probing — Akamai / Cloudflare / Fastly produce
//!   long, opaque hostnames under one apex.
//! - Anti-bot / fingerprinting services (Akamai BMP, hCaptcha)
//!   that synthesize per-page DNS lookups with random nonces.
//! - DNSSEC NSEC3 hashed denial-of-existence responses / zone
//!   walking.
//! - Some browser telemetry endpoints (Firefox shavar, Chrome
//!   safebrowsing).
//!
//! Tune `with_subdomain_threshold` / `with_min_qname_len` per
//! site, or allowlist known-good registered domains upstream.

use flowscope::OwnedAnomaly;
use flowscope::detect::DetectorRegistry;
use flowscope::detect::patterns::DnsTunnelDetector;
use flowscope::dns::{DnsMessage, DnsUdpParser};
use flowscope::driver::{Driver, Event, SlotMessage};
use flowscope::emit::EveJsonWriter;
use flowscope::extract::{FiveTuple, FiveTupleKey};
use flowscope::pcap::PcapFlowSource;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/dns_queries.pcap".to_string());

    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut dns_slot = builder.datagram_on_ports(DnsUdpParser::default(), [53]);
    let mut driver = builder.build();

    // Lower the thresholds vs the production defaults so a small
    // demo capture can trip the detector.
    let mut registry: DetectorRegistry<FiveTupleKey> = DetectorRegistry::new();
    registry.register(
        DnsTunnelDetector::new()
            .with_subdomain_threshold(20)
            .with_min_qname_len(30),
    );

    let mut eve = EveJsonWriter::new(std::io::stdout().lock());
    let mut events: Vec<Event<FiveTupleKey>> = Vec::new();
    let mut msgs: Vec<SlotMessage<DnsMessage, FiveTupleKey>> = Vec::new();
    let mut anomalies: Vec<OwnedAnomaly> = Vec::new();
    let mut fired = 0usize;

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        events.clear();
        driver.track_into(&owned, &mut events);
        msgs.clear();
        dns_slot.drain(&mut msgs);

        anomalies.clear();
        for m in &msgs {
            if let DnsMessage::Query(q) | DnsMessage::Unanswered(q) = &m.message {
                for question in &q.questions {
                    registry.observe_dns(&m.key, &question.name, m.ts, &mut anomalies);
                }
            }
        }
        for a in &anomalies {
            eve.write_owned_anomaly(a)?;
        }
        fired += anomalies.len();
    }

    if fired == 0 {
        eprintln!("(no suspected tunneling in this capture — try a known-bad pcap)");
    } else {
        eprintln!("\n{fired} DNS-tunnel anomalies emitted (EVE above)");
    }
    Ok(())
}

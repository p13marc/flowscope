//! Composite C2 detector: BeaconDetector ∧ DgaScorer ∧
//! weak-TLS-version → EVE.
//!
//! Single-walk over a pcap. Per source IP we collect three
//! independent signals:
//!
//! 1. **Beacon** ([`BeaconDetector`]) — RITA-style CV of inter-
//!    arrival times across outbound packets. Score ≥ 0.7
//!    counts.
//! 2. **DGA** ([`DgaScorer`]) — bigram log-likelihood on the
//!    SLD of any DNS query the host issued. `is_dga()` (default
//!    threshold) counts.
//! 3. **Weak TLS** — any handshake observed with
//!    `TlsVersion::{Tls1_0, Tls1_1, Ssl3_0}` counts.
//!
//! A source flagged by **≥ 2** of those signals is emitted as
//! a single Suricata-compatible EVE JSON anomaly
//! (`event_type: "anomaly"`,
//! `alert.signature: "composite-c2"`).
//!
//! Why "AND" rather than "OR": each signal alone has high false-
//! positive rates (legit beacons exist; entropy-heavy CDN
//! subdomains look DGA-shaped; legacy enterprise apps still ship
//! TLS 1.0). Requiring two-of-three collapses the false-positive
//! rate dramatically.
//!
//! ## MITRE ATT&CK
//!
//! - [T1071](https://attack.mitre.org/techniques/T1071/) —
//!   Application Layer Protocol (C2 channels).
//! - [T1568.002](https://attack.mitre.org/techniques/T1568/002/)
//!   — Dynamic Resolution: Domain Generation Algorithms.
//! - [T1573](https://attack.mitre.org/techniques/T1573/) —
//!   Encrypted Channel (downgraded TLS).
//!
//! ## Known false positives
//!
//! - Misconfigured internal CI runners (regular pings + DGA-
//!   looking artifact URLs + legacy TLS to a quarantined repo).
//! - Pen-test tooling that signals deliberately (Cobalt Strike
//!   defaults). True positive for the IR team, false positive
//!   for the SOC if not pre-coordinated.
//!
//! ## Usage
//!
//! ```bash
//! cargo run --features "pcap,extractors,tracker,dns,tls,emit-eve" \
//!     --example composite_c2 -- trace.pcap | jq .
//! ```
//!
//! Closes #42.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use flowscope::detect::patterns::{BeaconDetector, DgaScorer};
use flowscope::emit::EveJsonWriter;
use flowscope::event::Severity;
use flowscope::pcap::PcapFlowSource;
use flowscope::tls::{TlsParser, TlsVersion};
use flowscope::{DetectorKind, KeyFields, OwnedAnomaly, PacketView, SessionParser, Timestamp};

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct SrcIpKey(IpAddr);

impl KeyFields for SrcIpKey {
    fn src_ip(&self) -> Option<IpAddr> {
        Some(self.0)
    }
}

#[derive(Default, Debug)]
struct SourceProfile {
    beacon_score: f64,
    dga_hits: u32,
    weak_tls: bool,
}

impl SourceProfile {
    fn legs(&self) -> u8 {
        let beacon = (self.beacon_score >= 0.7) as u8;
        let dga = (self.dga_hits > 0) as u8;
        let tls = self.weak_tls as u8;
        beacon + dga + tls
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    let mut beacon: BeaconDetector<IpAddr> = BeaconDetector::new();
    let dga = DgaScorer::new();
    let mut profiles: HashMap<IpAddr, SourceProfile> = HashMap::new();
    let mut seen_dns_qnames: HashSet<(IpAddr, String)> = HashSet::new();

    let mut last_ts = Timestamp { sec: 0, nsec: 0 };
    let mut total_packets = 0u64;

    for view in PcapFlowSource::open(&path)?.views() {
        let view = view?;
        total_packets += 1;
        last_ts = view.timestamp;
        let pv = PacketView::new(&view.frame, view.timestamp);
        let Ok(layers) = pv.layers() else { continue };
        let src: IpAddr = if let Some(v4) = layers.ipv4() {
            IpAddr::V4(v4.source())
        } else if let Some(v6) = layers.ipv6() {
            IpAddr::V6(v6.source())
        } else {
            continue;
        };

        // (1) Beacon signal — every observed packet contributes.
        if let Some(score) = beacon.observe(src, view.timestamp, view.frame.len() as u64) {
            let entry = profiles.entry(src).or_default();
            if score.score > entry.beacon_score {
                entry.beacon_score = score.score;
            }
        }

        // (2) DGA signal — score the SLD of every DNS QNAME.
        if let Some(udp) = layers.udp()
            && (udp.src_port() == 53 || udp.dst_port() == 53)
        {
            let payload = udp.payload();
            if let Ok(flowscope::dns::DnsParseResult::Query(q)) =
                flowscope::dns::parse_message(payload)
            {
                for question in &q.questions {
                    let qname = &question.name;
                    if !seen_dns_qnames.insert((src, qname.clone())) {
                        continue;
                    }
                    let sld = sld_of(qname);
                    if sld.len() >= 4 && dga.is_dga(sld) {
                        profiles.entry(src).or_default().dga_hits += 1;
                    }
                }
            }
        }
    }

    // (3) Weak-TLS signal — second walk via the session driver
    // is cleaner than threading TLS reassembly state into the
    // packet loop above.
    for (key, message) in flowscope::pcap::session_messages::<TlsParser>(&path)? {
        if let Some(version) = handshake_version(&message)
            && matches!(
                version,
                TlsVersion::Ssl3_0 | TlsVersion::Tls1_0 | TlsVersion::Tls1_1
            )
        {
            let src = key.a.ip();
            profiles.entry(src).or_default().weak_tls = true;
        }
    }

    let mut eve = EveJsonWriter::new(std::io::stdout().lock());
    let mut composites = 0u64;
    for (src, profile) in &profiles {
        if profile.legs() >= 2 {
            composites += 1;
            let anomaly = OwnedAnomaly::new(
                DetectorKind::Other("composite-c2"),
                Severity::Critical,
                last_ts,
            )
            .with_key(&SrcIpKey(*src))
            .with_metric("beacon_score", profile.beacon_score)
            .with_metric("dga_hits", profile.dga_hits as f64)
            .with_metric("weak_tls", profile.weak_tls as u8 as f64)
            .with_metric("legs_tripped", profile.legs() as f64);
            eve.write_owned_anomaly(&anomaly)?;
        }
    }

    eprintln!(
        "\n--- composite_c2 ---\n  {total_packets} packet(s) walked\n  {} source(s) profiled\n  \
         {composites} composite alert(s) emitted (legs ≥ 2)",
        profiles.len()
    );
    Ok(())
}

/// Extract the second-level domain (label before the public
/// suffix's first label) — `foo.bar.example.com` → `"example"`.
/// Approximation: take the second-to-last label.
fn sld_of(qname: &str) -> &str {
    let trimmed = qname.trim_end_matches('.');
    let labels: Vec<&str> = trimmed.split('.').collect();
    if labels.len() >= 2 {
        labels[labels.len() - 2]
    } else {
        trimmed
    }
}

fn handshake_version(msg: &<TlsParser as SessionParser>::Message) -> Option<TlsVersion> {
    use flowscope::tls::TlsMessage;
    match msg {
        TlsMessage::ClientHello(c) => Some(c.legacy_version),
        TlsMessage::ServerHello(s) => s.supported_version.or(Some(s.legacy_version)),
        _ => None,
    }
}

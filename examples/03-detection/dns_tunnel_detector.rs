//! Detect probable DNS tunneling by flagging DNS query names with
//! suspiciously high Shannon entropy + long label lengths.
//!
//! DNS tunneling smuggles data inside the QNAME, so the labels
//! tend to be:
//! - Long (close to the 63-byte per-label limit, total > 50
//!   chars).
//! - Base32/64-encoded → high entropy ≈ 4.5-5.0 bits/char.
//! - From the same source repeating at a high rate.
//!
//! Real detectors (e.g. Suricata's `dns.query.entropy` rule)
//! combine entropy + rate + label-length thresholds. We do all
//! three.
//!
//! ```bash
//! cargo run --features pcap,dns,extractors --example dns_tunnel_detector
//! ```
//!
//! ## MITRE ATT&CK
//!
//! - [T1071.004](https://attack.mitre.org/techniques/T1071/004/)
//!   — Application Layer Protocol: DNS.
//! - [T1048.003](https://attack.mitre.org/techniques/T1048/003/)
//!   — Exfiltration Over Unencrypted Non-C2 Protocol (when
//!   used for data exfil rather than C2).
//!
//! ## Known false positives
//!
//! - CDN edge probing — Akamai / Cloudflare / Fastly produce
//!   long, opaque hostnames that look like base64 to the
//!   entropy test.
//! - Anti-bot / fingerprinting services (Akamai BMP, hCaptcha)
//!   that synthesize per-page DNS lookups with random nonces.
//! - DNSSEC NSEC3 hashed denial-of-existence responses.
//! - Some browser telemetry endpoints (Firefox shavar, Chrome
//!   safebrowsing).

use std::{collections::HashMap, net::IpAddr, time::Duration};

use flowscope::{
    correlate::TimeBucketedCounter,
    detect::shannon_entropy,
    dns::{DnsMessage, DnsUdpParser},
    driver::{Driver, Event, SlotMessage},
    extract::{FiveTuple, FiveTupleKey},
    pcap::PcapFlowSource,
};

const ENTROPY_THRESHOLD: f64 = 4.0;
const MIN_LABEL_LEN: usize = 30;
const WINDOW: Duration = Duration::from_secs(60);
const BUCKET: Duration = Duration::from_secs(10);
const RATE_THRESHOLD: u64 = 20;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/dns_queries.pcap".to_string());

    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut dns_slot = builder.datagram_on_ports(DnsUdpParser::default(), [53]);
    let mut driver = builder.build();

    let mut counter: TimeBucketedCounter<IpAddr> = TimeBucketedCounter::new(WINDOW, BUCKET, 10_000);
    let mut reported: HashMap<IpAddr, usize> = HashMap::new();

    let mut events: Vec<Event<FiveTupleKey>> = Vec::new();
    let mut msgs: Vec<SlotMessage<DnsMessage, FiveTupleKey>> = Vec::new();

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        events.clear();
        driver.track_into(&owned, &mut events);
        msgs.clear();
        dns_slot.drain(&mut msgs);

        for m in &msgs {
            let names = match &m.message {
                DnsMessage::Query(q) => q.questions.iter().map(|q| q.name.clone()).collect(),
                _ => Vec::<String>::new(),
            };
            let ts = m.ts;
            for name in names {
                let max_label = name.split('.').map(|l| l.len()).max().unwrap_or(0);
                let entropy = shannon_entropy(name.as_bytes());
                if entropy < ENTROPY_THRESHOLD || max_label < MIN_LABEL_LEN {
                    continue;
                }
                let src = m.key.a.ip();
                counter.bump(src, ts);
                let rate = counter.count(&src, ts);
                if rate >= RATE_THRESHOLD {
                    let reports = reported.entry(src).or_default();
                    if *reports == 0 {
                        println!(
                            "[{}.{:09}] suspected DNS tunnel from {src}: \
                             {rate} suspicious queries in {WINDOW:?}; latest qname: {name:?} \
                             (entropy={entropy:.2}, max_label={max_label})",
                            ts.sec, ts.nsec
                        );
                    }
                    *reports += 1;
                } else if entropy >= ENTROPY_THRESHOLD + 0.5 {
                    // Loud single-query flag for very-high entropy hits.
                    println!(
                        "  high-entropy query from {src}: {name:?} \
                         (entropy={entropy:.2}, max_label={max_label})"
                    );
                }
            }
        }
    }

    if reported.is_empty() {
        println!("(no suspected tunneling in this capture — try a known-bad pcap)");
    }
    Ok(())
}

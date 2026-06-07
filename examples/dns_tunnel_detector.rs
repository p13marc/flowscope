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

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use flowscope::correlate::TimeBucketedCounter;
use flowscope::detect::shannon_entropy;
use flowscope::dns::{DnsMessage, DnsUdpParser};
use flowscope::extract::FiveTuple;
use flowscope::pcap::PcapFlowSource;
use flowscope::{FlowDatagramDriver, SessionEvent};

const ENTROPY_THRESHOLD: f64 = 4.0;
const MIN_LABEL_LEN: usize = 30;
const WINDOW: Duration = Duration::from_secs(60);
const BUCKET: Duration = Duration::from_secs(10);
const RATE_THRESHOLD: u64 = 20;

fn main() -> flowscope::Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/dns_queries.pcap".to_string());

    let mut driver =
        FlowDatagramDriver::new(FiveTuple::bidirectional(), DnsUdpParser::default());
    let mut counter: TimeBucketedCounter<IpAddr> =
        TimeBucketedCounter::new(WINDOW, BUCKET, 10_000);
    let mut reported: HashMap<IpAddr, usize> = HashMap::new();

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        for ev in driver.track(&owned) {
            let SessionEvent::Application { key, message, ts, .. } = ev else {
                continue;
            };
            let names = match message {
                DnsMessage::Query(q) => q.questions.iter().map(|q| q.name.clone()).collect(),
                _ => Vec::<String>::new(),
            };
            for name in names {
                let max_label = name
                    .split('.')
                    .map(|l| l.len())
                    .max()
                    .unwrap_or(0);
                let entropy = shannon_entropy(name.as_bytes());
                if entropy < ENTROPY_THRESHOLD || max_label < MIN_LABEL_LEN {
                    continue;
                }
                let src = key.a.ip();
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

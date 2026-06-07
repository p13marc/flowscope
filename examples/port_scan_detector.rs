//! Detect TCP SYN-scan-shaped activity by counting distinct
//! destination ports per source IP within a sliding window.
//!
//! Real-world pattern: a source that issues SYNs to many different
//! destination ports on the same target in a short window is
//! almost certainly probing.
//!
//! Uses [`flowscope::correlate::TimeBucketedCounter`] keyed on
//! `(src_ip, dst_ip, dst_port)` to count per-source SYN-rate
//! and reports any `src_ip` whose distinct-port count crosses a
//! threshold within the window.
//!
//! ```bash
//! cargo run --features pcap,extractors,tracker --example port_scan_detector
//! ```

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use flowscope::correlate::TimeBucketedCounter;
use flowscope::layers::TcpFlagsView;
use flowscope::pcap::PcapFlowSource;
use flowscope::{PacketView, Timestamp};

const WINDOW: Duration = Duration::from_secs(10);
const BUCKET: Duration = Duration::from_secs(1);
const SYN_THRESHOLD: u64 = 5;
const PORT_DIVERSITY_THRESHOLD: usize = 5;

type ScanKey = (IpAddr, IpAddr); // (src, dst)

fn main() -> flowscope::Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    let mut syn_counter: TimeBucketedCounter<ScanKey> =
        TimeBucketedCounter::new(WINDOW, BUCKET, 100_000);

    // Per (src,dst) → set of dst_ports observed. Plain HashMap of
    // HashSet is fine for the example; production code would use
    // a probabilistic structure for memory bounds.
    let mut ports_per_pair: HashMap<ScanKey, std::collections::BTreeSet<u16>> = HashMap::new();

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        let pv = PacketView::new(&owned.frame, owned.timestamp);
        let Ok(layers) = pv.layers() else { continue };

        // Look for SYN-without-ACK (initial scan probe).
        let Some(tcp) = layers.tcp() else { continue };
        let flags: TcpFlagsView = tcp.flags();
        if !flags.syn || flags.ack {
            continue;
        }
        let (src, dst) = match (layers.ipv4(), layers.ipv6()) {
            (Some(v4), _) => (
                IpAddr::V4(v4.source()),
                IpAddr::V4(v4.destination()),
            ),
            (None, Some(v6)) => (
                IpAddr::V6(v6.source()),
                IpAddr::V6(v6.destination()),
            ),
            _ => continue,
        };
        let key = (src, dst);

        syn_counter.bump(key, owned.timestamp);
        ports_per_pair
            .entry(key)
            .or_default()
            .insert(tcp.dst_port());

        // Check if this pair just crossed the threshold.
        let now = owned.timestamp;
        let count = syn_counter.count(&key, now);
        let distinct = ports_per_pair.get(&key).map(|s| s.len()).unwrap_or(0);
        if count >= SYN_THRESHOLD && distinct >= PORT_DIVERSITY_THRESHOLD {
            report_scan(now, src, dst, count, distinct);
            // Reset so we don't fire repeatedly for the same pair.
            ports_per_pair.remove(&key);
        }
    }

    println!("--- scan done");
    Ok(())
}

fn report_scan(now: Timestamp, src: IpAddr, dst: IpAddr, syns: u64, distinct_ports: usize) {
    println!(
        "[{}.{:09}] suspected scan: src={src} dst={dst} \
         {syns} SYN-only in {WINDOW:?}, {distinct_ports} distinct dst ports",
        now.sec, now.nsec
    );
}

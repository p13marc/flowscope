//! Detect TCP SYN-scan-shaped activity by counting distinct
//! destination ports per (src, dst) pair within a sliding
//! window.
//!
//! Real-world pattern: a source that issues SYNs to many
//! different destination ports on the same target in a short
//! window is almost certainly probing.
//!
//! Migrated to [`flowscope::correlate::TimeBucketedSet`] (0.10)
//! — the distinct-values-per-key over-a-window primitive
//! replaces the hand-rolled `HashMap<ScanKey, BTreeSet<u16>>` of
//! the 0.9 version, complementing the existing
//! [`flowscope::correlate::TimeBucketedCounter`] used for SYN
//! rate.
//!
//! ```bash
//! cargo run --features pcap,extractors,tracker --example port_scan_detector
//! ```
//!
//! Plan 102 sub-A migration.

use std::net::IpAddr;
use std::time::Duration;

use flowscope::correlate::{TimeBucketedCounter, TimeBucketedSet};
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
    let mut distinct_ports: TimeBucketedSet<ScanKey, u16> =
        TimeBucketedSet::new(WINDOW, BUCKET, 100_000);

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        let pv = PacketView::new(&owned.frame, owned.timestamp);
        let Ok(layers) = pv.layers() else { continue };

        let Some(tcp) = layers.tcp() else { continue };
        let flags: TcpFlagsView = tcp.flags();
        // Initial probe = SYN without ACK.
        if !flags.syn || flags.ack {
            continue;
        }
        let (src, dst) = match (layers.ipv4(), layers.ipv6()) {
            (Some(v4), _) => (IpAddr::V4(v4.source()), IpAddr::V4(v4.destination())),
            (None, Some(v6)) => (IpAddr::V6(v6.source()), IpAddr::V6(v6.destination())),
            _ => continue,
        };
        let key = (src, dst);
        let now = owned.timestamp;

        syn_counter.bump(key, now);
        distinct_ports.insert(key, tcp.dst_port(), now);

        let count = syn_counter.count(&key, now);
        let distinct = distinct_ports.cardinality(&key, now);
        if count >= SYN_THRESHOLD && distinct >= PORT_DIVERSITY_THRESHOLD {
            report_scan(now, src, dst, count, distinct);
            // Re-insert empty to suppress duplicate reports on the
            // next packet — the TimeBucketedSet will refill as new
            // ports arrive.
            distinct_ports.evict_expired(Timestamp::MAX);
        }
    }

    println!("--- scan done");
    Ok(())
}

fn report_scan(now: Timestamp, src: IpAddr, dst: IpAddr, syns: u64, distinct: usize) {
    println!(
        "[{}.{:09}] suspected scan: src={src} dst={dst} \
         {syns} SYN-only in {WINDOW:?}, {distinct} distinct dst ports",
        now.sec, now.nsec
    );
}

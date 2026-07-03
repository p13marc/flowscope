//! Group bandwidth by an opaque owner key (issue #141) — e.g. the
//! owning PID a consumer joined from a socket table or eBPF.
//!
//! flowscope never learns the PID itself; the consumer supplies it
//! and `BandwidthByKey` does the per-owner tx/rx rate accounting.
//! Here we simulate three "processes" sending/receiving over a
//! 10-second window and print the top talkers.
//!
//! Usage:
//!     cargo run --features tracker --example bandwidth_by_owner

use std::time::Duration;

use flowscope::Timestamp;
use flowscope::correlate::{Attribution, BandwidthByKey, ByteSemantics};

fn main() {
    let mut bw = BandwidthByKey::<Attribution>::new_unbounded(
        Duration::from_secs(10),
        Duration::from_secs(1),
    );

    // Simulate 10 seconds of traffic for three owners (PIDs).
    for s in 0..10 {
        let now = Timestamp::new(s, 0);
        bw.record_tx(Attribution(1234), 1_500_000, now); // backup: heavy upload
        bw.record_rx(Attribution(1234), 40_000, now);
        bw.record_rx(Attribution(5678), 900_000, now); // stream: heavy download
        bw.record_tx(Attribution(5678), 20_000, now);
        bw.record_tx(Attribution(9012), 5_000, now); // chatty: light both ways
        bw.record_rx(Attribution(9012), 5_000, now);
    }

    let now = Timestamp::new(9, 0);
    println!(
        "Top bandwidth owners ({} bytes) over the last 10s:\n",
        bw.semantics().as_str()
    );
    println!(
        "{:<8} {:>12} {:>12} {:>12}",
        "pid", "tx B/s", "rx B/s", "total B/s"
    );
    println!("{}", "-".repeat(46));
    for (Attribution(pid), total) in bw.top_k(10, now) {
        let key = Attribution(pid);
        println!(
            "{:<8} {:>12.0} {:>12.0} {:>12.0}",
            pid,
            bw.tx_bps(&key, now),
            bw.rx_bps(&key, now),
            total,
        );
    }

    // The semantics tag keeps wire bytes from being compared against
    // an eBPF goodput feed.
    debug_assert_eq!(bw.semantics(), ByteSemantics::Wire);
}

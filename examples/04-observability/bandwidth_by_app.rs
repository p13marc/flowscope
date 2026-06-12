//! Bandwidth-by-app: per-app bytes/sec over a sliding window,
//! with site-custom port labels and a built-in top-N sort.
//!
//! Demonstrates four 0.14 additions:
//!
//! - [`RollingRate`] (plan 164) — per-key sliding-window rate.
//! - [`RollingRate::top_k`] (plan 171) — built-in sorted top-N.
//! - [`FiveTupleKey::app_label_with`] (plan 163 + 165) — always-Some
//!   port-to-label resolution with caller-supplied overrides.
//! - [`LabelTable`] (plan 165) — site-custom port label table
//!   layered on the built-in well-known table.
//!
//! Recipe: `docs/recipes.md` § "0.14 patterns" / "Bandwidth-by-app".
//! Migration doc: `docs/migration-0.13-to-0.14.md` §3, §4, §5, §13.
//!
//! ```bash
//! cargo run --features pcap,extractors,tracker --example bandwidth_by_app
//! ```
//!
//! [`RollingRate`]: flowscope::correlate::RollingRate
//! [`RollingRate::top_k`]: flowscope::correlate::RollingRate::top_k
//! [`FiveTupleKey::app_label_with`]: flowscope::extract::FiveTupleKey::app_label_with
//! [`LabelTable`]: flowscope::well_known::LabelTable

use std::time::Duration;

use flowscope::correlate::RollingRate;
use flowscope::extract::FiveTuple;
use flowscope::pcap::PcapFlowSource;
use flowscope::well_known::LabelTable;
use flowscope::{FlowEvent, FlowTracker, L4Proto, Timestamp};

fn main() -> flowscope::Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    // Site-custom overrides on top of the built-in well-known
    // table (~80 standard ports). Real deployments always have
    // a few: internal gRPC services, metrics scrape ports, etc.
    let mut labels = LabelTable::new();
    labels.extend([
        (L4Proto::Tcp, 8765, "grpc-internal"),
        (L4Proto::Tcp, 9101, "metrics-scrape"),
        (L4Proto::Tcp, 30443, "legacy-app"),
    ]);

    // 60-second sliding window, 1-second buckets — matches the
    // Prometheus rate() default.
    let mut bw: RollingRate<&'static str, u64> =
        RollingRate::new_unbounded(Duration::from_secs(60), Duration::from_secs(1));

    let mut tracker = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
    let mut last_report = Timestamp::new(0, 0);
    let mut first = true;

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        let ts = Timestamp::new(owned.timestamp.sec, owned.timestamp.nsec);
        if first {
            last_report = ts;
            first = false;
        }
        for ev in tracker.track(&owned) {
            if let FlowEvent::Packet { key, len, .. } = ev {
                // `app_label_with` always returns Some — it falls
                // back to the L4 canonical name ("tcp" / "udp" /
                // "sctp" / "other") when no port matches.
                bw.record(key.app_label_with(&labels), len as u64, ts);
            }
        }

        // Periodic top-10 report.
        if ts.saturating_sub(last_report) >= std::time::Duration::from_secs(1) {
            print_top10(&bw, ts);
            last_report = ts;
        }
    }

    // Final snapshot.
    println!("=== final top-10 ===");
    print_top10(&bw, last_report);
    Ok(())
}

fn print_top10(bw: &RollingRate<&'static str, u64>, now: Timestamp) {
    // Built-in sorted top-N (plan 171) — no manual sort needed.
    let top = bw.top_k(10, now);
    if top.is_empty() {
        return;
    }
    let t = now.to_unix_f64();
    println!("--- bandwidth-by-app at t={t:.3}s ---");
    for (label, rate) in &top {
        println!("  {label:<20} {rate:>10.0} B/s");
    }
}

//! Bandwidth breakdown by L7 protocol — bytes-per-second per
//! well-known protocol port. Useful for "what's eating my
//! bandwidth?" at-a-glance reports.
//!
//! Maps `(L4 + port) → protocol label` for the common ports,
//! aggregates bytes per ended flow, and prints a sorted ranking.
//!
//! ```bash
//! cargo run --features pcap,extractors,tracker --example bandwidth_by_protocol
//! ```

use std::collections::HashMap;

use flowscope::extract::FiveTuple;
use flowscope::pcap::PcapFlowSource;
use flowscope::{FlowEvent, FlowTracker, L4Proto};

fn label_for(proto: L4Proto, src_port: u16, dst_port: u16) -> &'static str {
    let port = src_port.min(dst_port).max(1024_u16.saturating_sub(1));
    let candidate = if src_port < 1024 || dst_port < 1024 {
        src_port.min(dst_port)
    } else {
        port
    };
    match (proto, candidate) {
        (L4Proto::Tcp, 80) | (L4Proto::Tcp, 8080) | (L4Proto::Tcp, 8000) => "http",
        (L4Proto::Tcp, 443) | (L4Proto::Tcp, 8443) => "tls/https",
        (L4Proto::Tcp, 22) => "ssh",
        (L4Proto::Tcp, 21) | (L4Proto::Tcp, 20) => "ftp",
        (L4Proto::Tcp, 25) | (L4Proto::Tcp, 587) | (L4Proto::Tcp, 465) => "smtp",
        (L4Proto::Tcp, 110) | (L4Proto::Tcp, 995) => "pop3",
        (L4Proto::Tcp, 143) | (L4Proto::Tcp, 993) => "imap",
        (L4Proto::Tcp, 5432) => "postgres",
        (L4Proto::Tcp, 3306) => "mysql",
        (L4Proto::Tcp, 6379) => "redis",
        (L4Proto::Tcp, 27017) => "mongodb",
        (L4Proto::Tcp, 5672) => "amqp",
        (L4Proto::Tcp, 9092) => "kafka",
        (L4Proto::Tcp, 1883) | (L4Proto::Tcp, 8883) => "mqtt",
        (L4Proto::Udp, 53) => "dns",
        (L4Proto::Udp, 67) | (L4Proto::Udp, 68) => "dhcp",
        (L4Proto::Udp, 123) => "ntp",
        (L4Proto::Udp, 161) | (L4Proto::Udp, 162) => "snmp",
        (L4Proto::Udp, 514) => "syslog",
        (L4Proto::Udp, 4789) => "vxlan",
        (L4Proto::Udp, 2152) => "gtp-u",
        (L4Proto::Udp, 500) | (L4Proto::Udp, 4500) => "ipsec",
        _ => "other",
    }
}

#[derive(Default, Clone, Copy)]
struct Tally {
    bytes: u64,
    flows: u64,
}

fn main() -> flowscope::Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    let mut tracker = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
    let mut totals: HashMap<&'static str, Tally> = HashMap::new();
    let mut total_bytes = 0u64;

    let mut min_ts: Option<f64> = None;
    let mut max_ts: Option<f64> = None;

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        let t = owned.timestamp.sec as f64 + owned.timestamp.nsec as f64 / 1e9;
        min_ts = Some(min_ts.map(|m: f64| m.min(t)).unwrap_or(t));
        max_ts = Some(max_ts.map(|m: f64| m.max(t)).unwrap_or(t));

        for ev in tracker.track(&owned) {
            if let FlowEvent::Ended { key, stats, .. } = ev {
                let label = label_for(key.proto, key.a.port(), key.b.port());
                let bytes = stats.bytes_initiator + stats.bytes_responder;
                let entry = totals.entry(label).or_default();
                entry.bytes += bytes;
                entry.flows += 1;
                total_bytes += bytes;
            }
        }
    }
    for ev in tracker.finish() {
        if let FlowEvent::Ended { key, stats, .. } = ev {
            let label = label_for(key.proto, key.a.port(), key.b.port());
            let bytes = stats.bytes_initiator + stats.bytes_responder;
            let entry = totals.entry(label).or_default();
            entry.bytes += bytes;
            entry.flows += 1;
            total_bytes += bytes;
        }
    }

    let duration = (max_ts.unwrap_or(0.0) - min_ts.unwrap_or(0.0)).max(1e-9);

    println!("=== Bandwidth by protocol ===");
    println!(
        "Total: {total_bytes} bytes over {duration:.3}s (= {:.1} kbps)",
        8.0 * total_bytes as f64 / duration / 1000.0
    );
    println!();
    let mut rows: Vec<_> = totals.iter().collect();
    rows.sort_by_key(|(_, t)| std::cmp::Reverse(t.bytes));
    println!(
        "{:<12} {:>10} {:>10} {:>8} {:>8}",
        "proto", "bytes", "kbps", "flows", "share"
    );
    for (label, t) in rows {
        let kbps = 8.0 * t.bytes as f64 / duration / 1000.0;
        let share = if total_bytes == 0 {
            0.0
        } else {
            t.bytes as f64 * 100.0 / total_bytes as f64
        };
        println!(
            "{:<12} {:>10} {:>10.1} {:>8} {:>7.1}%",
            label, t.bytes, kbps, t.flows, share
        );
    }
    Ok(())
}

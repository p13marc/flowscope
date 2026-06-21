//! Detect TCP overlap-evasion IOCs (Ptacek-Newsham 1998).
//!
//! When an attacker can send overlapping TCP segments to the IDS
//! with *different* bytes than what the target receives, the IDS
//! and the target see different streams — the attacker bypasses
//! signature-based detection. flowscope's
//! [`SegmentBufferReassembler`](flowscope::SegmentBufferReassembler)
//! counts `rexmit_inconsistencies` whenever a retransmitted byte
//! range disagrees with what was originally received.
//!
//! `FlowDriver::with_emit_anomalies(true)` surfaces this as
//! [`AnomalyKind::TcpRexmitInconsistency`] events on the
//! [`FlowEvent::FlowAnomaly`] stream — coalesced per (flow, side)
//! per tick.
//!
//! ## Background
//!
//! - Ptacek & Newsham 1998 — *Insertion, Evasion, and Denial of
//!   Service: Eluding Network Intrusion Detection* —
//!   <https://insecure.org/stf/secnet_ids/secnet_ids.html>
//! - Zeek implements the same signal as `rexmit_inconsistency` in
//!   conn.log.
//!
//! ## MITRE ATT&CK
//!
//! Not a direct technique, but adjacent to:
//! - [T1036](https://attack.mitre.org/techniques/T1036/) —
//!   Masquerading (broader evasion class).
//! - [T1090](https://attack.mitre.org/techniques/T1090/) — Proxy.
//!
//! ## Known false positives
//!
//! - Middlebox TCP normalization can produce overlap with
//!   different bytes (legitimate — the middlebox is fixing
//!   malformed retransmissions).
//! - Some load balancers retransmit with a different backend's
//!   timestamp; some flows reset and reuse sequence numbers.
//! - Lossy WAN links + buggy TCP stacks (rare but real).
//!
//! ## Usage
//!
//! ```bash
//! cargo run --features "pcap,extractors,tracker,reassembler" \
//!     --example tcp_evasion_detector -- trace.pcap
//! ```
//!
//! Closes #43.

use flowscope::extract::{FiveTuple, FiveTupleKey};
use flowscope::pcap::PcapFlowSource;
use flowscope::reassembler::BufferedReassemblerFactory;
use flowscope::{AnomalyKind, FlowDriver, FlowEvent, Timestamp};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    let mut driver = FlowDriver::new(
        FiveTuple::bidirectional(),
        BufferedReassemblerFactory::default(),
    )
    .with_emit_anomalies(true);

    let mut total_packets = 0u64;
    let mut total_inconsistencies = 0u64;
    let mut last_ts = Timestamp { sec: 0, nsec: 0 };

    let handle = |ev: FlowEvent<FiveTupleKey>, total: &mut u64| {
        if let FlowEvent::FlowAnomaly {
            key,
            kind: AnomalyKind::TcpRexmitInconsistency { side, count },
            ts,
        } = ev
        {
            *total += count;
            println!(
                "[evasion-ioc]  {}.{:09}  {}:{} ↔ {}:{}  side={side:?}  count={count}",
                ts.sec,
                ts.nsec,
                key.a.ip(),
                key.a.port(),
                key.b.ip(),
                key.b.port(),
            );
        }
    };

    for view in PcapFlowSource::open(&path)?.views() {
        let view = view?;
        total_packets += 1;
        last_ts = view.timestamp;
        for ev in driver.track(&view) {
            handle(ev, &mut total_inconsistencies);
        }
    }
    for ev in driver.sweep(last_ts) {
        handle(ev, &mut total_inconsistencies);
    }

    eprintln!(
        "\n--- summary ---\n  {total_packets} packet(s) processed\n  {total_inconsistencies} \
         TCP rexmit-inconsistenc{y} (Ptacek-Newsham IOC)",
        y = if total_inconsistencies == 1 {
            "y"
        } else {
            "ies"
        }
    );
    Ok(())
}

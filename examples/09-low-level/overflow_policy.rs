//! Demonstrate the three reassembly-overflow knobs that ship
//! together: per-reassembler buffer cap + cross-flow memcap +
//! their policy enums.
//!
//! Each run constructs three `FlowDriver`s with different policy
//! combinations, replays the same pcap through each, and prints
//! the resulting `Ended { reason: BufferOverflow }` events and
//! `GlobalMemcapHit` anomalies — letting you see the difference
//! between "sliding window" (lossy, parser must resync) and
//! "drop flow" (strict, flow torn down).
//!
//! ## Knobs
//!
//! - **Per-reassembler cap** —
//!   `BufferedReassemblerFactory::with_max_buffer(bytes)` +
//!   `with_overflow_policy({SlidingWindow | DropFlow})`.
//!   - `SlidingWindow` (default): drop oldest bytes; flow stays
//!     alive; parser must resync. Right for lossy protocols
//!     where a chunk boundary is recoverable (HTTP bodies, DNS
//!     message bodies).
//!   - `DropFlow`: poison the reassembler; the driver synthesises
//!     an `Ended { reason: BufferOverflow }` event. Right for
//!     strict binary protocols whose state machine can't resync
//!     mid-frame (SMB, DCE-RPC, Modbus).
//!
//! - **Cross-flow memcap** —
//!   `FlowTrackerConfig { reassembly_memcap: Some(bytes),
//!   reassembly_memcap_policy: ... }`. Total bytes across **all**
//!   live reassemblers in the tracker.
//!   - `MemcapPolicy::Ignore` (default): accept but emit a
//!     warning anomaly.
//!   - `MemcapPolicy::DropPacket`: refuse to accept new bytes
//!     past the cap (flow stays alive; downstream sees a gap).
//!   - `MemcapPolicy::DropFlow`: tear down the offending flow
//!     via `BufferOverflow`.
//!   - `MemcapPolicy::PassThrough`: silently accept (no
//!     anomaly fires).
//!
//! ## Usage
//!
//! ```bash
//! cargo run --features "pcap,extractors,tracker,reassembler" \
//!     --example overflow_policy -- trace.pcap
//! ```
//!
//! Issues #17 / #26 / #59 background.
//!
//! Closes #59.

use flowscope::extract::FiveTuple;
use flowscope::pcap::PcapFlowSource;
use flowscope::reassembler::BufferedReassemblerFactory;
use flowscope::tracker::FlowTrackerConfig;
use flowscope::{
    AnomalyKind, EndReason, FlowDriver, FlowEvent, MemcapPolicy, OverflowPolicy, Timestamp,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    println!("=== Scenario A — DropFlow per-reassembler ===");
    run(
        &path,
        "drop_flow",
        FlowTrackerConfig::default(),
        BufferedReassemblerFactory::default()
            .with_max_buffer(16 * 1024)
            .with_overflow_policy(OverflowPolicy::DropFlow),
    )?;

    println!();
    println!("=== Scenario B — SlidingWindow per-reassembler ===");
    run(
        &path,
        "sliding_window",
        FlowTrackerConfig::default(),
        BufferedReassemblerFactory::default()
            .with_max_buffer(16 * 1024)
            .with_overflow_policy(OverflowPolicy::SlidingWindow),
    )?;

    println!();
    println!("=== Scenario C — Cross-flow memcap, DropFlow ===");
    let mut cfg = FlowTrackerConfig::default();
    cfg.reassembly_memcap = Some(64 * 1024);
    cfg.reassembly_memcap_policy = MemcapPolicy::DropFlow;
    run(
        &path,
        "memcap_drop_flow",
        cfg,
        BufferedReassemblerFactory::default(),
    )?;

    Ok(())
}

fn run(
    path: &str,
    label: &str,
    cfg: FlowTrackerConfig,
    factory: BufferedReassemblerFactory,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut driver =
        FlowDriver::with_config(FiveTuple::bidirectional(), factory, cfg).with_emit_anomalies(true);
    let mut last_ts = Timestamp { sec: 0, nsec: 0 };
    let mut overflow_endings = 0u64;
    let mut memcap_hits = 0u64;
    let mut total_ended = 0u64;
    let mut total_packets = 0u64;

    for view in PcapFlowSource::open(path)?.views() {
        let view = view?;
        total_packets += 1;
        last_ts = view.timestamp;
        for ev in driver.track(&view) {
            classify(
                &ev,
                &mut overflow_endings,
                &mut memcap_hits,
                &mut total_ended,
            );
        }
    }
    for ev in driver.sweep(last_ts) {
        classify(
            &ev,
            &mut overflow_endings,
            &mut memcap_hits,
            &mut total_ended,
        );
    }

    println!(
        "[{label}]  packets={total_packets} ended={total_ended} buffer_overflow={overflow_endings} \
         memcap_hits={memcap_hits}"
    );
    Ok(())
}

fn classify<K>(
    ev: &FlowEvent<K>,
    overflow_endings: &mut u64,
    memcap_hits: &mut u64,
    total_ended: &mut u64,
) {
    match ev {
        FlowEvent::Ended {
            reason: EndReason::BufferOverflow,
            ..
        } => {
            *overflow_endings += 1;
            *total_ended += 1;
        }
        FlowEvent::Ended { .. } => *total_ended += 1,
        FlowEvent::TrackerAnomaly {
            kind: AnomalyKind::GlobalMemcapHit { .. },
            ..
        } => {
            *memcap_hits += 1;
        }
        _ => {}
    }
}

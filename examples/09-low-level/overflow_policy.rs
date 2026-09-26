//! Demonstrate the three reassembly-overflow knobs that ship
//! together: per-reassembler buffer cap + cross-flow memcap +
//! their policy enums.
//!
//! Each run constructs three `FlowDriver`s with different policy
//! combinations, replays the same pcap through each, and prints how
//! many flows had their reassembly stopped (`FlowStats::
//! reassembly_stop_*`), how many bytes were dropped for size, and the
//! `GlobalMemcapHit` anomalies — letting you see the difference
//! between "sliding window" (lossy, the parser sees a gap) and "drop
//! flow" (strict, reassembly of the side stops). Neither ends the
//! flow: it stays tracked until its FIN / RST / idle timeout.
//!
//! ## Knobs
//!
//! - **Per-reassembler cap** —
//!   `BufferedReassemblerFactory::with_max_buffer(bytes)` +
//!   `with_overflow_policy({SlidingWindow | DropFlow})`.
//!   - `SlidingWindow` (default): drop the oldest undelivered
//!     bytes; they reach a session parser as a gap (`on_gap`: a
//!     parser that resyncs answers `Continue`, the default
//!     `StopSide` stops reading that side). Right for
//!     protocols where a chunk boundary is recoverable (HTTP
//!     bodies, DNS message bodies).
//!   - `DropFlow`: stop reassembling the side; session parsers
//!     stop reading it (`ParserSideStopped`,
//!     `EndReason::BufferOverflow`) while the other side goes on. Right for
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
//!   - `MemcapPolicy::PassThrough`: release the offending side
//!     (it stops reassembling).
//!   - `MemcapPolicy::DropFlow`: release both sides of the
//!     offending flow.
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
use flowscope::{AnomalyKind, FlowDriver, FlowEvent, MemcapPolicy, OverflowPolicy, Timestamp};

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
    let mut counts = Counts::default();
    let mut total_packets = 0u64;

    for view in PcapFlowSource::open(path)?.views() {
        let view = view?;
        total_packets += 1;
        last_ts = view.timestamp;
        for ev in driver.track(&view) {
            counts.classify(&ev);
        }
    }
    let _ = last_ts;
    for ev in driver.finish() {
        counts.classify(&ev);
    }

    let Counts {
        ended,
        stopped,
        oversize_bytes,
        memcap_hits,
    } = counts;
    println!(
        "[{label}]  packets={total_packets} ended={ended} reassembly_stopped={stopped} \
         oversize_bytes={oversize_bytes} memcap_hits={memcap_hits}"
    );
    Ok(())
}

#[derive(Default)]
struct Counts {
    ended: u64,
    stopped: u64,
    oversize_bytes: u64,
    memcap_hits: u64,
}

impl Counts {
    fn classify<K>(&mut self, ev: &FlowEvent<K>) {
        match ev {
            FlowEvent::Ended { stats, .. } => {
                self.ended += 1;
                if stats.reassembly_stop_initiator.is_some()
                    || stats.reassembly_stop_responder.is_some()
                {
                    self.stopped += 1;
                }
                self.oversize_bytes += stats.reassembly_bytes_dropped_oversize_initiator
                    + stats.reassembly_bytes_dropped_oversize_responder;
            }
            FlowEvent::TrackerAnomaly {
                kind: AnomalyKind::GlobalMemcapHit { .. },
                ..
            } => self.memcap_hits += 1,
            _ => {}
        }
    }
}

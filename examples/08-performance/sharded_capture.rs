//! N-thread sharded driver example — plan 155 (0.13).
//!
//! Pattern: one [`Driver<E>`] per OS thread, each with its own
//! typed [`SlotHandle`]; cross-shard totals merged via
//! [`std::sync::atomic`] counters. Demonstrates that
//! `Driver<E>: Send + Sync` (since 0.13 plan 156) lets each
//! shard own a fully independent dispatcher.
//!
//! ```bash
//! cargo run --features pcap,http \
//!     --example sharded_capture -- tests/data/mixed_short.pcap [N=4]
//! ```
//!
//! Architecture:
//!
//! ```text
//!     pcap file
//!         │
//!         ▼ (hash 5-tuple to shard ID, send view to that shard)
//!   ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
//!   │ shard 0  │  │ shard 1  │  │ shard 2  │  │ shard 3  │
//!   │ Driver<E>│  │ Driver<E>│  │ Driver<E>│  │ Driver<E>│
//!   │ + slot   │  │ + slot   │  │ + slot   │  │ + slot   │
//!   └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘
//!        │             │             │             │
//!        ▼             ▼             ▼             ▼
//!    drain worker  drain worker  drain worker  drain worker
//!        │             │             │             │
//!        └─────────────┴──── cross-shard ────┴─────┘
//!                          AtomicU64 totals
//! ```
//!
//! Each shard is a self-contained dispatcher: zero cross-shard
//! contention on the dispatch path. Pin shards to specific CPUs
//! via the `core_affinity` crate if you want NUMA-locality.
//!
//! When to shard (the FAQ):
//! - **Helps**: multi-Gbps capture with CPU-bound parsing
//!   (HTTP, TLS handshake aggregation, JA4 fingerprinting). One
//!   shard per CPU saturates a 10/25/100 Gbps NIC much further
//!   than a single-thread dispatcher.
//! - **Hurts**: low-volume, single-flow workloads. The cross-
//!   thread dispatch overhead exceeds the parser cost. Stick
//!   with a single-thread dispatcher.

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
        mpsc,
    },
    thread,
};

use flowscope::{
    OwnedPacketView, PacketView,
    driver::{Driver, Event, SlotMessage},
    extract::{FiveTuple, FiveTupleKey},
    http::{HttpMessage, HttpParser},
    pcap::PcapFlowSource,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());
    let n_shards: usize = args.next().and_then(|s| s.parse().ok()).unwrap_or(4);

    println!("[sharded_capture] {} shards, pcap = {}", n_shards, path);

    // Cross-shard totals — what the demo aggregates.
    let total_http_msgs = Arc::new(AtomicU64::new(0));
    let total_packets = Arc::new(AtomicU64::new(0));

    // Per-shard input channels.
    let mut shard_senders: Vec<mpsc::Sender<OwnedPacketView>> = Vec::with_capacity(n_shards);
    let mut shard_threads = Vec::with_capacity(n_shards);

    for shard_id in 0..n_shards {
        let (tx, rx) = mpsc::channel::<OwnedPacketView>();
        shard_senders.push(tx);
        let http_total = Arc::clone(&total_http_msgs);
        let pkt_total = Arc::clone(&total_packets);

        shard_threads.push(thread::spawn(move || {
            shard_worker(shard_id, rx, http_total, pkt_total)
        }));
    }

    // Read pcap on the main thread; dispatch each packet to its
    // owning shard by hashing the 5-tuple. Each shard sees only
    // its own flows — no cross-shard correlation in this demo.
    let source = PcapFlowSource::open(&path)?;
    let mut dispatched = 0u64;
    for view in source.views() {
        let view = view?;
        let shard_id = hash_to_shard(&view.frame, n_shards);
        if shard_senders[shard_id].send(view).is_err() {
            // Worker dropped — bail.
            break;
        }
        dispatched += 1;
    }
    println!(
        "[sharded_capture] dispatched {} packets to shards",
        dispatched
    );

    // Drop senders so workers exit cleanly.
    drop(shard_senders);

    // Wait for workers.
    for (i, t) in shard_threads.into_iter().enumerate() {
        let r = t.join().unwrap_or_else(|_| panic!("shard {i} panicked"));
        if let Err(e) = r {
            return Err(format!("shard {i} error: {e}").into());
        }
    }

    println!(
        "[sharded_capture] total: {} packets, {} HTTP messages across {} shards",
        total_packets.load(Ordering::Relaxed),
        total_http_msgs.load(Ordering::Relaxed),
        n_shards,
    );
    Ok(())
}

/// One shard's worker. Owns a [`Driver<E>`] and an HTTP slot.
fn shard_worker(
    shard_id: usize,
    rx: mpsc::Receiver<OwnedPacketView>,
    http_total: Arc<AtomicU64>,
    pkt_total: Arc<AtomicU64>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut http_slot = builder.session_on_ports(HttpParser::default(), [80, 8080]);
    let mut driver = builder.build();

    let mut events: Vec<Event<FiveTupleKey>> = Vec::with_capacity(64);
    let mut messages: Vec<SlotMessage<HttpMessage, FiveTupleKey>> = Vec::with_capacity(64);
    let mut local_pkt = 0u64;
    let mut local_http = 0u64;

    while let Ok(view) = rx.recv() {
        events.clear();
        driver.track_into(PacketView::from(&view), &mut events);
        // Drain typed HTTP messages (bounded for back-pressure).
        let drained = http_slot.drain_n(&mut messages, 64);
        local_pkt += 1;
        local_http += drained as u64;
        if !messages.is_empty() {
            messages.clear();
        }
    }
    println!(
        "[shard {}] processed {} packets, {} HTTP messages",
        shard_id, local_pkt, local_http
    );
    pkt_total.fetch_add(local_pkt, Ordering::Relaxed);
    http_total.fetch_add(local_http, Ordering::Relaxed);
    Ok(())
}

/// Hash the raw frame's L3 source address bytes to pick a shard.
/// Real production code hashes the canonical 5-tuple after
/// extraction; this demo keeps it simple.
fn hash_to_shard(frame: &[u8], n_shards: usize) -> usize {
    if frame.len() < 30 {
        return 0;
    }
    // Ethernet (14) + IPv4 src at offset 12 of IP header → 26.
    let src_bytes = &frame[26..30];
    let h = u32::from_be_bytes([src_bytes[0], src_bytes[1], src_bytes[2], src_bytes[3]]);
    (h as usize) % n_shards
}

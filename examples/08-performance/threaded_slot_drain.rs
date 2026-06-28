//! Cross-thread slot drain using `SlotHandle: Send + Sync` (0.12).
//!
//! ```bash
//! cargo run --features pcap,http \
//!     --example threaded_slot_drain -- tests/data/mixed_short.pcap
//! ```
//!
//! Architecture:
//!
//! - Main thread drives the capture loop: `driver.track_into(view,
//!   &mut events)` per packet. The `Driver<E>` is `Send + Sync`
//!   since 0.13 (plan 156 — no `unsafe`, no opt-in knob), so you
//!   can `tokio::spawn(driver_task)` or hand it across threads
//!   directly if your shape prefers.
//! - Worker thread holds a clone of the typed `SlotHandle`, drains
//!   it in a tight loop, and forwards messages via an
//!   `std::sync::mpsc` channel for further processing.
//!
//! The slot handle is backed by `Arc<crossbeam_queue::SegQueue<…>>`
//! (lock-free MPMC). `Clone` hands out a competitive consumer:
//! each clone pops from the same queue; sum across all clones
//! equals total pushed. For broadcast semantics, drain into a
//! channel and fan out.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

use flowscope::{
    PacketView,
    driver::{Driver, Event, SlotMessage},
    extract::{FiveTuple, FiveTupleKey},
    http::{HttpMessage, HttpParser},
    pcap::PcapFlowSource,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/http_session.pcap".to_string());

    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut http_slot = builder.session_on_ports(HttpParser::default(), [80, 8080]);
    let mut driver = builder.build();

    // Clone the slot handle for the worker thread.
    let drainer_handle = http_slot.clone();
    let done = Arc::new(AtomicBool::new(false));
    let done_for_worker = Arc::clone(&done);

    // Channel from worker → final consumer (could be a tokio
    // task, a writer, a metric pipeline, …).
    let (tx, rx) = mpsc::channel::<SlotMessage<HttpMessage, FiveTupleKey>>();

    let worker = thread::spawn(move || {
        let mut h = drainer_handle;
        let mut buf = Vec::new();
        while !done_for_worker.load(Ordering::Acquire) || h.pending() > 0 {
            h.drain(&mut buf);
            for m in buf.drain(..) {
                if tx.send(m).is_err() {
                    return; // consumer hung up
                }
            }
            thread::sleep(Duration::from_micros(50));
        }
    });

    // Capture loop on the main thread.
    let mut events: Vec<Event<FiveTupleKey>> = Vec::new();
    let mut flows = 0usize;
    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        events.clear();
        driver.track_into(PacketView::from(&owned), &mut events);
        for ev in &events {
            if matches!(ev, Event::Started { .. }) {
                flows += 1;
            }
        }
    }
    // Drive the remaining lifecycle events through.
    driver.finish_into(&mut events);
    done.store(true, Ordering::Release);
    worker.join().expect("worker panicked");

    // Drain the channel — by now the worker has shut down and
    // we still have the rx end alive.
    let mut messages = 0usize;
    while let Ok(msg) = rx.try_recv() {
        let _ = msg.message; // keep the handler honest
        messages += 1;
    }
    // Also drain whatever the main-thread `http_slot` clone still
    // holds (the worker's clone shared the same Arc, but the
    // local `http_slot` is also a valid consumer).
    let mut leftover = Vec::new();
    http_slot.drain(&mut leftover);
    messages += leftover.len();

    println!("flows started: {flows}");
    println!("http messages observed: {messages}");
    Ok(())
}

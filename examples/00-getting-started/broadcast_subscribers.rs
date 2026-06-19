//! Broadcast HTTP messages to multiple subscribers — plan 150 (0.13).
//!
//! Demonstrates [`BroadcastSlotHandle`]'s fan-out semantics:
//! every clone of the handle is an independent subscriber that
//! sees every HTTP message. Contrast with the competitive-
//! consumer (MPMC) `SlotHandle::clone` semantics where clones
//! race to pop messages from a single shared queue.
//!
//! ```bash
//! cargo run --features pcap,http \
//!     --example broadcast_subscribers -- tests/data/mixed_short.pcap
//! ```
//!
//! Architecture: one HTTP parser registered through
//! [`DriverBuilder::session_on_ports_broadcast_each`]; three
//! subscribers (logger / metrics / alerter) each clone the
//! returned [`BroadcastSlotHandle`] and drain independently.

use std::env;

use flowscope::{
    PacketView,
    driver::{Driver, Event},
    extract::{FiveTuple, FiveTupleKey},
    http::HttpParser,
    pcap::PcapFlowSource,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    let mut builder = Driver::builder(FiveTuple::bidirectional());
    // Plan 150 (0.13): broadcast variant. Each clone of the
    // returned handle sees every message.
    let mut logger = builder.session_on_ports_broadcast_each(HttpParser::default(), [80, 8080]);
    let mut metrics = logger.clone();
    let mut alerter = logger.clone();
    let mut driver = builder.build();

    println!(
        "[broadcast_subscribers] {} active subscribers",
        logger.subscribers()
    );

    let mut events: Vec<Event<FiveTupleKey>> = Vec::new();
    let mut log_buf = Vec::new();
    let mut metric_buf = Vec::new();
    let mut alert_buf = Vec::new();

    let mut log_count = 0u64;
    let mut metric_count = 0u64;
    let mut alert_count = 0u64;

    for view in PcapFlowSource::open(&path)?.views() {
        let view = view?;
        events.clear();
        driver.track_into(PacketView::from(&view), &mut events);

        // Each subscriber drains its OWN queue. The same message
        // appears in all three buffers — that's the broadcast
        // contract.
        log_count += logger.drain(&mut log_buf) as u64;
        metric_count += metrics.drain(&mut metric_buf) as u64;
        alert_count += alerter.drain(&mut alert_buf) as u64;

        log_buf.clear();
        metric_buf.clear();
        alert_buf.clear();
    }

    println!(
        "[broadcast_subscribers] logger drained {log_count}, metrics drained {metric_count}, alerter drained {alert_count}"
    );
    assert_eq!(
        log_count, metric_count,
        "broadcast contract: every subscriber sees every message"
    );
    assert_eq!(metric_count, alert_count);

    Ok(())
}

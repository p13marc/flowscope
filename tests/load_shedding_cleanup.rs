//! Per-flow resources are released even when `Ended` is suppressed
//! (#185).
//!
//! Cleanup normally rides on `FlowEvent::Ended`. But that event is
//! gated on `EventMask::ENDED` while the tracker reaps the flow
//! either way, so a consumer shedding events under load used to keep
//! every reassembler and parser for the life of the driver — worst
//! precisely when shedding is switched on.

#![cfg(all(
    feature = "tracker",
    feature = "extractors",
    feature = "reassembler",
    feature = "session",
    feature = "test-helpers"
))]

use flowscope::extract::{FiveTuple, parse::test_frames::ipv4_tcp};
use flowscope::{
    BufferedReassemblerFactory, EventMask, FlowDriver, FlowTrackerConfig, PacketView, Timestamp,
};

fn view(frame: &[u8], sec: u32) -> PacketView<'_> {
    PacketView::new(frame, Timestamp::new(sec, 0))
}

/// One data packet, then a RST to end the flow.
fn short_flow(sport: u16, payload: &[u8]) -> Vec<Vec<u8>> {
    let data = ipv4_tcp(
        [0; 6],
        [0; 6],
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        sport,
        80,
        1000,
        0,
        0x18,
        payload,
    );
    let rst = ipv4_tcp(
        [0; 6],
        [0; 6],
        [10, 0, 0, 2],
        [10, 0, 0, 1],
        80,
        sport,
        1,
        0,
        0x04,
        b"",
    );
    vec![data, rst]
}

fn shedding_config() -> FlowTrackerConfig {
    FlowTrackerConfig::default().with_event_filter(EventMask::ENDED)
}

#[test]
fn reassemblers_are_released_when_ended_is_suppressed() {
    let mut d = FlowDriver::with_config(
        FiveTuple::bidirectional(),
        BufferedReassemblerFactory::default(),
        shedding_config(),
    );

    for port in 0..300u16 {
        for f in &short_flow(40000 + port, b"payload-bytes") {
            let _ = d.track(view(f, 0));
        }
    }
    // The tracker reaped every flow despite emitting no `Ended`.
    assert_eq!(d.tracker().flow_count(), 0, "flows were reaped");

    // Before #185 the reassemblers were stranded here, one pair per
    // flow, with their bytes still counted against the memcap pool.
    let _ = d.sweep(Timestamp::new(10, 0));
    assert_eq!(
        d.reassembly_memcap_bytes(),
        0,
        "stranded reassemblers must be released and their bytes refunded"
    );
}

#[test]
fn ordinary_teardown_still_refunds_and_reports() {
    // The reconciliation must not pre-empt normal cleanup: with the
    // filter off, an ended flow is still reported and still refunded.
    let mut d = FlowDriver::new(
        FiveTuple::bidirectional(),
        BufferedReassemblerFactory::default(),
    );
    let mut evs = Vec::new();
    for f in &short_flow(42000, b"payload-bytes") {
        evs.extend(d.track(view(f, 0)));
    }
    evs.extend(d.finish());
    assert!(
        evs.iter()
            .any(|e| matches!(e, flowscope::FlowEvent::Ended { .. })),
        "the flow must still be reported Ended"
    );
    assert_eq!(d.reassembly_memcap_bytes(), 0, "and still refunded");
}

//! `flowscope_packets_deduplicated_total` (#203). Own process: one
//! global recorder per binary.

#![cfg(all(
    feature = "metrics",
    feature = "extractors",
    feature = "reassembler",
    feature = "test-helpers"
))]

use flowscope::extract::FiveTuple;
use flowscope::extract::parse::test_frames::ipv4_udp;
use flowscope::obs::METRIC_PACKETS_DEDUPLICATED;
use flowscope::{BufferedReassemblerFactory, Dedup, FlowDriver, PacketView, Timestamp};
use metrics_util::MetricKind;
use metrics_util::debugging::{DebugValue, DebuggingRecorder};

#[test]
fn dedup_drop_is_counted() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    recorder.install().expect("recorder installs");

    let frame = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 33000, 53, b"query");
    let mut d = FlowDriver::new(
        FiveTuple::bidirectional(),
        BufferedReassemblerFactory::default(),
    )
    .with_dedup(Dedup::loopback());
    let _ = d.track(PacketView::new(&frame, Timestamp::new(1, 0)));
    let _ = d.track(PacketView::new(&frame, Timestamp::new(1, 100_000)));
    let _ = d.track(PacketView::new(&frame, Timestamp::new(5, 0))); // outside the window
    assert_eq!(d.dedup().map(|x| (x.seen(), x.dropped())), Some((3, 1)));

    let rows = snapshotter.snapshot().into_vec();
    let value: u64 = rows
        .iter()
        .filter(|(k, ..)| {
            k.kind() == MetricKind::Counter && k.key().name() == METRIC_PACKETS_DEDUPLICATED
        })
        .map(|(.., v)| match v {
            DebugValue::Counter(n) => *n,
            _ => 0,
        })
        .sum();
    assert_eq!(value, 1);
}

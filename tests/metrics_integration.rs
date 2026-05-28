//! Smoke test for the `metrics` feature: drive a short flow through
//! `FlowDriver` and assert the expected counters land in the
//! [`metrics_util::debugging::DebuggingRecorder`] snapshot.
//!
//! Single test (one DebuggingRecorder per process — see metrics-util
//! docs) bundling all counter assertions.

#![cfg(all(feature = "metrics", feature = "extractors", feature = "reassembler"))]

use flowscope::extract::{FiveTuple, parse::test_frames::ipv4_tcp};
use flowscope::obs::{
    METRIC_ANOMALIES, METRIC_BYTES, METRIC_FLOWS_CREATED, METRIC_FLOWS_ENDED, METRIC_RETRANSMITS,
};
use flowscope::{BufferedReassemblerFactory, FlowDriver, OverflowPolicy, PacketView, Timestamp};
use metrics_util::MetricKind;
use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};

fn install() -> Snapshotter {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    recorder.install().expect("recorder installs");
    snapshotter
}

/// Find a counter value matching `(name, label_key=label_value)`.
/// Returns 0 when no match is found (i.e. the counter never fired).
fn counter_value(
    rows: &[(
        metrics_util::CompositeKey,
        Option<metrics::Unit>,
        Option<metrics::SharedString>,
        DebugValue,
    )],
    name: &str,
    label: Option<(&str, &str)>,
) -> u64 {
    for (k, _unit, _desc, v) in rows {
        if k.kind() != MetricKind::Counter {
            continue;
        }
        if k.key().name() != name {
            continue;
        }
        if let Some((lk, lv)) = label {
            let has_label = k.key().labels().any(|l| l.key() == lk && l.value() == lv);
            if !has_label {
                continue;
            }
        }
        if let DebugValue::Counter(n) = v {
            return *n;
        }
    }
    0
}

#[test]
fn metrics_capture_basic_flow_lifecycle_and_anomalies() {
    let snap = install();

    // Configure: 64-byte cap, drop-flow policy, anomaly emission on.
    let factory = BufferedReassemblerFactory::default()
        .with_max_buffer(64)
        .with_overflow_policy(OverflowPolicy::DropFlow);
    let mut d =
        FlowDriver::<_, _>::new(FiveTuple::bidirectional(), factory).with_emit_anomalies(true);

    // 3WHS + 200B initiator data. The data segment poisons the
    // 64-byte cap; the driver synthesises an Ended{BufferOverflow}
    // and forgets the flow. We deliberately stop here — sending more
    // packets would create a fresh flow under the same 5-tuple,
    // which is correct DropFlow semantics but irrelevant to this test.
    let mac = [0u8; 6];
    let ip_a = [10, 0, 0, 1];
    let ip_b = [10, 0, 0, 2];
    let payload = vec![b'A'; 200];
    let frames = [
        ipv4_tcp(mac, mac, ip_a, ip_b, 1234, 80, 1000, 0, 0x02, b""),
        ipv4_tcp(mac, mac, ip_b, ip_a, 80, 1234, 5000, 1001, 0x12, b""),
        ipv4_tcp(mac, mac, ip_a, ip_b, 1234, 80, 1001, 5001, 0x10, b""),
        ipv4_tcp(mac, mac, ip_a, ip_b, 1234, 80, 1001, 5001, 0x18, &payload),
    ];
    for f in &frames {
        d.track(PacketView::new(f, Timestamp::default()));
    }

    // Separate flow that retransmits an initiator data segment, then
    // RST. Drives the retransmit anomaly + counter, and the
    // `retransmits_*` field on the final stats.
    let mut d2 = FlowDriver::<_, _>::new(
        FiveTuple::bidirectional(),
        BufferedReassemblerFactory::default(),
    )
    .with_emit_anomalies(true);
    let ip_c = [10, 0, 0, 3];
    let ip_d = [10, 0, 0, 4];
    let body = b"hello";
    let retx_frames = [
        ipv4_tcp(mac, mac, ip_c, ip_d, 4444, 80, 2000, 0, 0x02, b""),
        ipv4_tcp(mac, mac, ip_d, ip_c, 80, 4444, 6000, 2001, 0x12, b""),
        ipv4_tcp(mac, mac, ip_c, ip_d, 4444, 80, 2001, 6001, 0x10, b""),
        ipv4_tcp(mac, mac, ip_c, ip_d, 4444, 80, 2001, 6001, 0x18, body),
        ipv4_tcp(mac, mac, ip_c, ip_d, 4444, 80, 2001, 6001, 0x18, body),
        ipv4_tcp(mac, mac, ip_c, ip_d, 4444, 80, 2006, 6001, 0x04, b""),
    ];
    for f in &retx_frames {
        d2.track(PacketView::new(f, Timestamp::default()));
    }

    let rows = snap.snapshot().into_vec();

    assert_eq!(
        counter_value(&rows, METRIC_FLOWS_CREATED, Some(("l4", "tcp"))),
        2,
        "expected 2 tcp flows created"
    );
    assert_eq!(
        counter_value(
            &rows,
            METRIC_FLOWS_ENDED,
            Some(("reason", "buffer_overflow"))
        ),
        1,
        "expected 1 ended with reason=buffer_overflow"
    );
    let init_bytes = counter_value(&rows, METRIC_BYTES, Some(("side", "initiator")));
    assert!(init_bytes >= 200, "initiator bytes = {}", init_bytes);
    assert_eq!(
        counter_value(&rows, METRIC_ANOMALIES, Some(("kind", "buffer_overflow"))),
        1,
        "expected 1 buffer_overflow anomaly counted"
    );
    assert_eq!(
        counter_value(&rows, METRIC_ANOMALIES, Some(("kind", "retransmit"))),
        1,
        "expected 1 retransmit anomaly counted"
    );
    assert_eq!(
        counter_value(&rows, METRIC_RETRANSMITS, Some(("side", "initiator"))),
        1,
        "expected 1 initiator retransmit counted"
    );
    assert_eq!(
        counter_value(&rows, "flowscope_packets_unmatched_total", None),
        0
    );
}

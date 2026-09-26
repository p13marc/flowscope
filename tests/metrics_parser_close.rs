//! `flowscope_parser_closed_total` / `flowscope_parser_side_stopped_total`
//! (issue #191). Own process: one global recorder per binary.

#![cfg(all(
    feature = "metrics",
    feature = "extractors",
    feature = "reassembler",
    feature = "session",
    feature = "test-helpers"
))]

use flowscope::extract::FiveTuple;
use flowscope::extract::parse::test_frames::ipv4_tcp;
use flowscope::obs::{METRIC_PARSER_CLOSED, METRIC_PARSER_SIDE_STOPPED};
use flowscope::session::SessionDriver;
use flowscope::{PacketView, ParserKind, SessionParser, Timestamp};
use metrics_util::MetricKind;
use metrics_util::debugging::{DebugValue, DebuggingRecorder};

#[derive(Clone, Default)]
struct Named;

impl SessionParser for Named {
    type Message = ();
    fn feed_initiator(&mut self, _: &[u8], _: Timestamp, _: &mut Vec<()>) {}
    fn feed_responder(&mut self, _: &[u8], _: Timestamp, _: &mut Vec<()>) {}
    fn parser_kind(&self) -> ParserKind {
        ParserKind::Other("named")
    }
}

#[test]
fn parser_close_and_side_stop_metrics() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    recorder.install().expect("recorder installs");

    let m = [0u8; 6];
    let (c, s) = ([10, 0, 0, 1], [10, 0, 0, 2]);
    let frames = [
        ipv4_tcp(m, m, c, s, 40_000, 80, 1000, 0, 0x02, b""),
        ipv4_tcp(m, m, s, c, 80, 40_000, 5000, 1001, 0x12, b""),
        ipv4_tcp(m, m, c, s, 40_000, 80, 1001, 5001, 0x10, b"ab"),
        // Hole 1003..1005, corroborated by a second segment.
        ipv4_tcp(m, m, c, s, 40_000, 80, 1005, 5001, 0x10, b"ef"),
        ipv4_tcp(m, m, c, s, 40_000, 80, 1007, 5001, 0x10, b"gh"),
    ];
    let mut d = SessionDriver::new(FiveTuple::bidirectional(), Named);
    let mut out = Vec::new();
    for (i, f) in frames.iter().enumerate() {
        d.track_into(PacketView::new(f, Timestamp::new(1, i as u32)), &mut out);
    }
    d.finish_into(&mut out);

    let rows = snapshotter.snapshot().into_vec();
    let value = |name: &str, labels: &[(&str, &str)]| -> u64 {
        rows.iter()
            .filter(|(k, ..)| k.kind() == MetricKind::Counter && k.key().name() == name)
            .filter(|(k, ..)| {
                labels
                    .iter()
                    .all(|(lk, lv)| k.key().labels().any(|l| l.key() == *lk && l.value() == *lv))
            })
            .map(|(.., v)| match v {
                DebugValue::Counter(n) => *n,
                _ => 0,
            })
            .sum()
    };
    assert_eq!(
        value(
            METRIC_PARSER_SIDE_STOPPED,
            &[
                ("parser_kind", "named"),
                ("side", "initiator"),
                ("reason", "stream_gap")
            ]
        ),
        1
    );
    // The parser closes at the flow's end (finish → idle).
    assert_eq!(
        value(
            METRIC_PARSER_CLOSED,
            &[("parser_kind", "named"), ("reason", "idle")]
        ),
        1
    );
}

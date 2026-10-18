//! `flowscope_anomalies_total{kind="parse_error"}` counts parse errors
//! whenever anomalies are enabled — a mask or a pause only hides the
//! event, as for the reassembly anomalies (#204). Own process: one
//! global recorder per binary.

#![cfg(all(
    feature = "metrics",
    feature = "extractors",
    feature = "reassembler",
    feature = "session",
    feature = "test-helpers"
))]

use flowscope::extract::FiveTuple;
use flowscope::extract::parse::test_frames::ipv4_tcp;
use flowscope::obs::METRIC_ANOMALIES;
use flowscope::session::{SessionDriver, SessionEvent};
use flowscope::{EventMask, FlowTrackerConfig, PacketView, SessionParser, Timestamp};
use metrics_util::MetricKind;
use metrics_util::debugging::{DebugValue, DebuggingRecorder, Snapshotter};

/// Poisons on its first bytes.
#[derive(Clone, Default)]
struct Poison(bool);

impl SessionParser for Poison {
    type Message = ();
    fn feed_initiator(&mut self, _: &[u8], _: Timestamp, _: &mut Vec<()>) {
        self.0 = true;
    }
    fn feed_responder(&mut self, _: &[u8], _: Timestamp, _: &mut Vec<()>) {
        self.0 = true;
    }
    fn is_poisoned(&self) -> bool {
        self.0
    }
}

/// Parse errors counted since the previous snapshot (the debugging
/// recorder's snapshot drains its counters).
fn parse_errors(snapshotter: &Snapshotter) -> u64 {
    snapshotter
        .snapshot()
        .into_vec()
        .iter()
        .filter(|(k, ..)| k.kind() == MetricKind::Counter && k.key().name() == METRIC_ANOMALIES)
        .filter(|(k, ..)| {
            k.key()
                .labels()
                .any(|l| l.key() == "kind" && l.value() == "parse_error")
        })
        .map(|(.., v)| match v {
            DebugValue::Counter(n) => *n,
            _ => 0,
        })
        .sum()
}

fn run(d: &mut SessionDriver<FiveTuple, Poison>) -> usize {
    let m = [0u8; 6];
    let (c, s) = ([10, 0, 0, 1], [10, 0, 0, 2]);
    let frames = [
        ipv4_tcp(m, m, c, s, 40_000, 80, 1000, 0, 0x02, b""),
        ipv4_tcp(m, m, s, c, 80, 40_000, 5000, 1001, 0x12, b""),
        ipv4_tcp(m, m, c, s, 40_000, 80, 1001, 5001, 0x18, b"bad"),
    ];
    let mut out = Vec::new();
    for (i, f) in frames.iter().enumerate() {
        d.track_into(PacketView::new(f, Timestamp::new(1, i as u32)), &mut out);
    }
    d.finish_into(&mut out);
    out.iter()
        .filter(|e| matches!(e, SessionEvent::FlowAnomaly { .. }))
        .count()
}

#[test]
fn parse_errors_are_counted_while_hidden() {
    let recorder = DebuggingRecorder::new();
    let snapshotter = recorder.snapshotter();
    recorder.install().expect("recorder installs");

    // Paused: no event, still counted.
    let mut d =
        SessionDriver::new(FiveTuple::bidirectional(), Poison::default()).with_emit_anomalies(true);
    d.pause_events();
    assert_eq!(run(&mut d), 0);
    assert_eq!(parse_errors(&snapshotter), 1, "counted while paused");

    // FLOW_ANOMALY masked: no event, still counted.
    let cfg = FlowTrackerConfig::default().with_event_filter(EventMask::FLOW_ANOMALY);
    let mut d = SessionDriver::with_config(FiveTuple::bidirectional(), Poison::default(), cfg)
        .with_emit_anomalies(true);
    assert_eq!(run(&mut d), 0);
    assert_eq!(parse_errors(&snapshotter), 1, "counted while masked");

    // Shown: one event, counted once.
    let mut d =
        SessionDriver::new(FiveTuple::bidirectional(), Poison::default()).with_emit_anomalies(true);
    assert_eq!(run(&mut d), 1);
    assert_eq!(parse_errors(&snapshotter), 1);

    // Anomalies off: neither.
    let mut d = SessionDriver::new(FiveTuple::bidirectional(), Poison::default());
    assert_eq!(run(&mut d), 0);
    assert_eq!(parse_errors(&snapshotter), 0);
}

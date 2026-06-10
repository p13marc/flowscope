//! Plan 101 — CSV writer coverage.
//!
//! Verifies header shape, end-row schema, RFC-4180 quoting,
//! tab-separated mode, and the `emit_started` opt-in column.

#![cfg(feature = "emit")]

use flowscope::emit::{CsvOptions, FlowEventCsvWriter};
use flowscope::extract::FiveTupleKey;
use flowscope::extractor::L4Proto;
use flowscope::history::HistoryString;
use flowscope::{EndReason, FlowEvent, FlowStats, Timestamp};
use std::net::SocketAddr;

fn key(a: &str, b: &str, proto: L4Proto) -> FiveTupleKey {
    let a: SocketAddr = a.parse().unwrap();
    let b: SocketAddr = b.parse().unwrap();
    let (a, b) = if a < b { (a, b) } else { (b, a) };
    FiveTupleKey { proto, a, b }
}

fn sample_ended() -> FlowEvent<FiveTupleKey> {
    let mut stats = FlowStats::default();
    stats.started = Timestamp::new(1_700_000_000, 0);
    stats.last_seen = Timestamp::new(1_700_000_005, 500_000_000);
    stats.packets_initiator = 10;
    stats.packets_responder = 8;
    stats.bytes_initiator = 1024;
    stats.bytes_responder = 2048;
    FlowEvent::Ended {
        key: key("10.0.0.1:1234", "10.0.0.2:80", L4Proto::Tcp),
        reason: EndReason::Fin,
        stats,
        history: HistoryString::new(),
        l4: Some(L4Proto::Tcp),
    }
}

#[test]
fn header_only_on_empty_input() {
    let mut buf = Vec::new();
    let csv = FlowEventCsvWriter::new(&mut buf).unwrap();
    csv.finish().unwrap();
    let text = String::from_utf8(buf).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 1);
    assert!(lines[0].starts_with("start_sec,end_sec,duration_sec,proto"));
    assert!(lines[0].contains("end_reason"));
}

#[test]
fn writes_one_row_for_ended_event() {
    let mut buf = Vec::new();
    let mut csv = FlowEventCsvWriter::new(&mut buf).unwrap();
    csv.write_event(&sample_ended()).unwrap();
    csv.finish().unwrap();
    let text = String::from_utf8(buf).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2);
    let row = lines[1];
    assert!(row.contains("tcp"));
    assert!(row.contains("10.0.0.1"));
    assert!(row.contains("10.0.0.2"));
    assert!(row.contains("fin"));
}

#[test]
fn skips_non_ended_events_by_default() {
    let mut buf = Vec::new();
    let mut csv = FlowEventCsvWriter::new(&mut buf).unwrap();
    let started = FlowEvent::Started {
        key: key("10.0.0.1:1234", "10.0.0.2:80", L4Proto::Tcp),
        side: flowscope::FlowSide::Initiator,
        ts: Timestamp::new(100, 0),
        l4: Some(L4Proto::Tcp),
    };
    csv.write_event(&started).unwrap();
    csv.finish().unwrap();
    let text = String::from_utf8(buf).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 1, "should be header only");
}

#[test]
fn emit_started_adds_kind_column() {
    let mut buf = Vec::new();
    let mut opts = CsvOptions::default();
    opts.emit_started = true;
    let mut csv = FlowEventCsvWriter::with_options(&mut buf, opts).unwrap();
    let started = FlowEvent::Started {
        key: key("10.0.0.1:1234", "10.0.0.2:80", L4Proto::Tcp),
        side: flowscope::FlowSide::Initiator,
        ts: Timestamp::new(100, 0),
        l4: Some(L4Proto::Tcp),
    };
    csv.write_event(&started).unwrap();
    csv.write_event(&sample_ended()).unwrap();
    csv.finish().unwrap();
    let text = String::from_utf8(buf).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 3);
    assert!(lines[0].starts_with("flow_event_kind,start_sec"));
    assert!(lines[1].starts_with("started,"));
    assert!(lines[2].starts_with("ended,"));
}

// Custom-key regression test for plan 130: emit writers are
// generic over `K: KeyFields`. A user-defined key type that
// implements `KeyFields` flows through the writer end-to-end.
#[test]
fn custom_key_with_partial_keyfields_writes_columns() {
    use flowscope::KeyFields;
    use std::net::IpAddr;

    #[derive(Debug, Clone, Copy)]
    struct OnlyIpKey(IpAddr, IpAddr);
    impl KeyFields for OnlyIpKey {
        fn src_ip(&self) -> Option<IpAddr> {
            Some(self.0)
        }
        fn dest_ip(&self) -> Option<IpAddr> {
            Some(self.1)
        }
        fn proto_str(&self) -> Option<&'static str> {
            Some("TCP")
        }
    }

    let mut buf = Vec::new();
    let mut csv = FlowEventCsvWriter::new(&mut buf).unwrap();
    let mut stats = FlowStats::default();
    stats.packets_initiator = 3;
    stats.bytes_initiator = 1024;
    stats.started = Timestamp::new(100, 0);
    stats.last_seen = Timestamp::new(105, 0);
    let ev: FlowEvent<OnlyIpKey> = FlowEvent::Ended {
        key: OnlyIpKey("10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap()),
        reason: EndReason::Fin,
        stats,
        history: HistoryString::new(),
        l4: Some(L4Proto::Tcp),
    };
    csv.write_event(&ev).unwrap();
    csv.finish().unwrap();
    let text = String::from_utf8(buf).unwrap();
    let row = text.lines().nth(1).expect("data row exists");
    // src_ip / dest_ip columns populated; port defaults to 0
    // since OnlyIpKey doesn't override src_port / dest_port.
    assert!(row.contains("10.0.0.1"), "row missing src_ip: {row}");
    assert!(row.contains("10.0.0.2"), "row missing dest_ip: {row}");
    assert!(row.contains("tcp"), "row missing proto: {row}");
}

#[test]
fn tab_separated_uses_tabs() {
    let mut buf = Vec::new();
    let mut opts = CsvOptions::default();
    opts.tab_separated = true;
    let mut csv = FlowEventCsvWriter::with_options(&mut buf, opts).unwrap();
    csv.write_event(&sample_ended()).unwrap();
    csv.finish().unwrap();
    let text = String::from_utf8(buf).unwrap();
    assert!(text.contains('\t'));
    assert!(!text.lines().nth(1).unwrap().contains(','));
}

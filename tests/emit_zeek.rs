//! Plan 101 — Zeek `conn.log` writer coverage.

#![cfg(feature = "emit")]

use flowscope::emit::{ZeekConnLogWriter, ZeekOptions};
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

fn ended(reason: EndReason) -> FlowEvent<FiveTupleKey> {
    let mut stats = FlowStats::default();
    stats.started = Timestamp::new(1_700_000_000, 0);
    stats.last_seen = Timestamp::new(1_700_000_005, 0);
    stats.bytes_initiator = 1024;
    stats.bytes_responder = 2048;
    stats.packets_initiator = 5;
    stats.packets_responder = 4;
    FlowEvent::Ended {
        key: key("10.0.0.1:1234", "10.0.0.2:80", L4Proto::Tcp),
        reason,
        stats,
        history: HistoryString::new(),
        l4: Some(L4Proto::Tcp),
    }
}

#[test]
fn headers_present_by_default() {
    let mut buf = Vec::new();
    let zeek = ZeekConnLogWriter::new(&mut buf).unwrap();
    zeek.finish().unwrap();
    let text = String::from_utf8(buf).unwrap();
    assert!(text.contains("#fields"));
    assert!(text.contains("#types"));
    assert!(text.contains("#path\tconn"));
    assert!(text.contains("#close"));
}

#[test]
fn headers_suppressed_by_option() {
    let mut buf = Vec::new();
    let mut opts = ZeekOptions::default();
    opts.emit_headers = false;
    let zeek = ZeekConnLogWriter::with_options(&mut buf, opts).unwrap();
    zeek.finish().unwrap();
    let text = String::from_utf8(buf).unwrap();
    assert!(!text.contains("#fields"));
    assert!(!text.contains("#close"));
}

#[test]
fn ended_emits_row_with_zeek_state() {
    let mut buf = Vec::new();
    let mut zeek = ZeekConnLogWriter::new(&mut buf).unwrap();
    zeek.write_event(&ended(EndReason::Fin)).unwrap();
    zeek.finish().unwrap();
    let text = String::from_utf8(buf).unwrap();
    let data_line = text
        .lines()
        .find(|l| !l.starts_with('#') && !l.is_empty())
        .expect("data row");
    let fields: Vec<&str> = data_line.split('\t').collect();
    assert!(fields.len() >= 13, "row has {} fields", fields.len());
    assert_eq!(fields[6], "tcp"); // proto column
    let conn_state = fields[10];
    assert_eq!(conn_state, "SF");
}

#[test]
fn zeek_state_map_covers_every_end_reason() {
    for (reason, expected) in [
        (EndReason::Fin, "SF"),
        (EndReason::Rst, "RSTO"),
        (EndReason::IdleTimeout, "OTH"),
        (EndReason::Evicted, "OTH"),
        (EndReason::BufferOverflow, "S0"),
        (EndReason::ParseError, "REJ"),
        (EndReason::ParserDone, "SF"),
        (EndReason::ForceClosed, "OTH"),
    ] {
        assert_eq!(reason.as_zeek_state(), expected, "{reason:?}");
    }
}

#[test]
fn uids_are_distinct() {
    let mut buf = Vec::new();
    let mut zeek = ZeekConnLogWriter::new(&mut buf).unwrap();
    for _ in 0..10 {
        zeek.write_event(&ended(EndReason::Fin)).unwrap();
    }
    zeek.finish().unwrap();
    let text = String::from_utf8(buf).unwrap();
    let uids: Vec<&str> = text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|l| l.split('\t').nth(1).unwrap())
        .collect();
    assert_eq!(uids.len(), 10);
    let set: std::collections::HashSet<_> = uids.iter().collect();
    assert_eq!(set.len(), 10);
    for u in &uids {
        assert!(u.starts_with('C'));
    }
}

#[test]
fn uid_prefix_override() {
    let mut buf = Vec::new();
    let mut opts = ZeekOptions::default();
    opts.uid_prefix = "X";
    let mut zeek = ZeekConnLogWriter::with_options(&mut buf, opts).unwrap();
    zeek.write_event(&ended(EndReason::Fin)).unwrap();
    zeek.finish().unwrap();
    let text = String::from_utf8(buf).unwrap();
    let data_line = text
        .lines()
        .find(|l| !l.starts_with('#') && !l.is_empty())
        .unwrap();
    let uid = data_line.split('\t').nth(1).unwrap();
    assert!(uid.starts_with('X'));
}

#[test]
fn skips_non_ended_events() {
    let mut buf = Vec::new();
    let mut zeek = ZeekConnLogWriter::new(&mut buf).unwrap();
    let started = FlowEvent::Started {
        key: key("10.0.0.1:1234", "10.0.0.2:80", L4Proto::Tcp),
        side: flowscope::FlowSide::Initiator,
        ts: Timestamp::new(100, 0),
        l4: Some(L4Proto::Tcp),
    };
    zeek.write_event(&started).unwrap();
    zeek.finish().unwrap();
    let text = String::from_utf8(buf).unwrap();
    let data_lines: Vec<&str> = text
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .collect();
    assert_eq!(data_lines.len(), 0);
}

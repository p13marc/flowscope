//! Plan 101 — NDJSON writer coverage.

#![cfg(feature = "emit-ndjson")]

use flowscope::emit::{FlowEventNdjsonWriter, NdjsonOptions};
use flowscope::extract::FiveTupleKey;
use flowscope::extractor::L4Proto;
use flowscope::history::HistoryString;
use flowscope::{EndReason, FlowEvent, FlowSide, FlowStats, Timestamp};
use std::net::SocketAddr;

fn key(a: &str, b: &str, proto: L4Proto) -> FiveTupleKey {
    let a: SocketAddr = a.parse().unwrap();
    let b: SocketAddr = b.parse().unwrap();
    let (a, b) = if a < b { (a, b) } else { (b, a) };
    FiveTupleKey { proto, a, b }
}

fn sample_ended() -> FlowEvent<FiveTupleKey> {
    let mut stats = FlowStats::default();
    stats.started = Timestamp::new(100, 0);
    stats.last_seen = Timestamp::new(105, 0);
    FlowEvent::Ended {
        key: key("10.0.0.1:1234", "10.0.0.2:80", L4Proto::Tcp),
        reason: EndReason::Fin,
        stats,
        history: HistoryString::new(),
        l4: Some(L4Proto::Tcp),
    }
}

#[test]
fn ended_emits_one_line_per_event() {
    let mut buf = Vec::new();
    let mut writer = FlowEventNdjsonWriter::new(&mut buf);
    writer.write_event(&sample_ended()).unwrap();
    writer.write_event(&sample_ended()).unwrap();
    writer.finish().unwrap();
    let text = String::from_utf8(buf).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2);
    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["type"], "ended");
    }
}

#[test]
fn packet_events_skipped_by_default() {
    let mut buf = Vec::new();
    let mut writer = FlowEventNdjsonWriter::new(&mut buf);
    let pkt = FlowEvent::Packet {
        key: key("10.0.0.1:1234", "10.0.0.2:80", L4Proto::Tcp),
        side: FlowSide::Initiator,
        len: 100,
        ts: Timestamp::new(101, 0),
    };
    writer.write_event(&pkt).unwrap();
    writer.finish().unwrap();
    let text = String::from_utf8(buf).unwrap();
    assert!(text.is_empty(), "default options should skip Packet events");
}

#[test]
fn include_packets_emits_them() {
    let mut buf = Vec::new();
    let mut opts = NdjsonOptions::default();
    opts.include_packets = true;
    let mut writer = FlowEventNdjsonWriter::with_options(&mut buf, opts);
    let pkt = FlowEvent::Packet {
        key: key("10.0.0.1:1234", "10.0.0.2:80", L4Proto::Tcp),
        side: FlowSide::Initiator,
        len: 100,
        ts: Timestamp::new(101, 0),
    };
    writer.write_event(&pkt).unwrap();
    writer.finish().unwrap();
    let text = String::from_utf8(buf).unwrap();
    let v: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
    assert_eq!(v["type"], "packet");
}

#[test]
fn round_trip_via_serde_recovers_event() {
    let mut buf = Vec::new();
    let mut writer = FlowEventNdjsonWriter::new(&mut buf);
    writer.write_event(&sample_ended()).unwrap();
    writer.finish().unwrap();
    let text = String::from_utf8(buf).unwrap();
    let parsed: FlowEvent<FiveTupleKey> = serde_json::from_str(text.trim()).unwrap();
    assert!(matches!(
        parsed,
        FlowEvent::Ended {
            reason: EndReason::Fin,
            ..
        }
    ));
}

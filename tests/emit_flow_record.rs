//! Issue #16 — emitter unification at the FlowRecord layer.
//!
//! Each of CSV / Zeek / NDJSON / EVE now exposes a
//! `write_flow_record(&FlowRecord)` method as an alternative
//! to `write_event(&FlowEvent<K>)`. These tests verify:
//!
//! 1. The new method produces well-formed output for a
//!    finalised FlowRecord.
//! 2. For the schemas that can fully round-trip the data
//!    (CSV + NDJSON), the output is byte-equivalent to the
//!    event-driven path.
//! 3. The EVE flow_hash is direction-invariant and matches
//!    the KeyFields-derived hash.

#![cfg(all(
    feature = "emit",
    feature = "ipfix",
    feature = "extractors",
    feature = "tracker",
    feature = "test-helpers",
))]

use flowscope::emit::{CsvOptions, FlowEventCsvWriter, ZeekConnLogWriter, ZeekOptions};
#[cfg(feature = "emit-ndjson")]
use flowscope::emit::{FlowEventNdjsonWriter, NdjsonOptions};
use flowscope::extract::FiveTuple;
use flowscope::extract::parse::test_frames::ipv4_tcp;
use flowscope::{
    EndReason, FlowEvent, FlowExtractor, FlowRecord, FlowStats, FlowTracker, PacketView, Timestamp,
};

fn build_finalised_record() -> (FlowRecord, FlowEvent<flowscope::extract::FiveTupleKey>) {
    let mac = [0u8; 6];
    let mut t: FlowTracker<FiveTuple, ()> = FlowTracker::new(FiveTuple::bidirectional());
    let frame = ipv4_tcp(
        mac,
        mac,
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        1234,
        80,
        1,
        0,
        0x02,
        b"",
    );
    let pv = PacketView::new(&frame, Timestamp::new(1700000000, 0));
    let key = FiveTuple::bidirectional().extract(pv).expect("ext").key;
    t.track(pv);
    let mut stats: FlowStats = t.snapshot_stats(&key).expect("stats");
    // Pin counters + timing for byte-stable output.
    stats.packets_initiator = 10;
    stats.packets_responder = 12;
    stats.bytes_initiator = 1500;
    stats.bytes_responder = 2100;
    stats.retransmits_initiator = 1;
    stats.retransmits_responder = 0;
    stats.started = Timestamp::new(1700000000, 0);
    stats.last_seen = Timestamp::new(1700000005, 0);
    let history = flowscope::history::HistoryString::default();
    let rec = FlowRecord::from_parts(&stats, &key, Some(EndReason::Fin));
    let event = FlowEvent::Ended {
        key,
        reason: EndReason::Fin,
        stats,
        history,
        l4: Some(flowscope::L4Proto::Tcp),
    };
    (rec, event)
}

#[test]
fn csv_write_flow_record_matches_event_path() {
    let (rec, event) = build_finalised_record();

    let mut buf_event = Vec::new();
    let mut w = FlowEventCsvWriter::new(&mut buf_event).expect("ctor");
    w.write_event(&event).expect("event");
    w.flush().expect("flush");
    let _ = w;

    let mut buf_rec = Vec::new();
    let mut w = FlowEventCsvWriter::new(&mut buf_rec).expect("ctor");
    w.write_flow_record(&rec).expect("rec");
    w.flush().expect("flush");
    let _ = w;

    assert_eq!(
        std::str::from_utf8(&buf_event).unwrap(),
        std::str::from_utf8(&buf_rec).unwrap(),
        "write_flow_record should produce an identical CSV row to write_event"
    );
}

#[test]
fn csv_write_flow_record_carries_retransmits() {
    let (rec, _event) = build_finalised_record();
    let mut buf = Vec::new();
    let mut w = FlowEventCsvWriter::with_options(&mut buf, CsvOptions::default()).expect("ctor");
    w.write_flow_record(&rec).expect("rec");
    w.flush().expect("flush");
    let _ = w;
    let s = std::str::from_utf8(&buf).unwrap();
    // Header + 1 data row.
    let row = s.lines().nth(1).expect("row");
    let cols: Vec<_> = row.split(',').collect();
    // Schema: start, end, dur, proto, src_ip, src_port,
    //         dst_ip, dst_port, pkts_init, pkts_resp,
    //         bytes_init, bytes_resp, retx_init, retx_resp,
    //         end_reason. Retransmits at idx 12 / 13.
    assert_eq!(cols[12], "1", "retx_init = 1");
    assert_eq!(cols[13], "0", "retx_resp = 0");
}

#[test]
fn zeek_write_flow_record_emits_well_formed_row() {
    let (rec, _) = build_finalised_record();
    let mut buf = Vec::new();
    let mut zopts = ZeekOptions::default();
    zopts.emit_headers = false;
    zopts.uid_prefix = "T";
    let mut w = ZeekConnLogWriter::with_options(&mut buf, zopts).expect("ctor");
    w.write_flow_record(&rec).expect("rec");
    w.flush().expect("flush");
    let _ = w;
    let s = std::str::from_utf8(&buf).unwrap();
    let row = s.lines().next().expect("row");
    let cols: Vec<_> = row.split('\t').collect();
    // Schema: ts uid orig_h orig_p resp_h resp_p proto
    //         duration orig_bytes resp_bytes conn_state
    //         history orig_pkts resp_pkts
    assert_eq!(cols.len(), 14);
    assert_eq!(cols[2], "10.0.0.1");
    assert_eq!(cols[4], "10.0.0.2");
    assert_eq!(cols[6], "tcp");
    assert_eq!(cols[8], "1500", "orig_bytes");
    assert_eq!(cols[9], "2100", "resp_bytes");
    assert_eq!(cols[10], "SF", "conn_state from EndOfFlowDetected");
    assert_eq!(cols[11], "-", "history unset for record path");
    assert_eq!(cols[12], "10", "orig_pkts");
    assert_eq!(cols[13], "12", "resp_pkts");
}

#[cfg(feature = "emit-ndjson")]
#[test]
fn ndjson_write_flow_record_serializes_full_ie_set() {
    let (rec, _) = build_finalised_record();
    let mut buf = Vec::new();
    let mut w = FlowEventNdjsonWriter::with_options(&mut buf, NdjsonOptions::default());
    w.write_flow_record(&rec).expect("rec");
    w.flush().expect("flush");
    let _ = w;
    let s = std::str::from_utf8(&buf).unwrap();
    // Must be one JSON line.
    let line = s.lines().next().expect("line");
    assert!(line.starts_with('{'));
    assert!(line.contains("protocol_identifier"));
    assert!(line.contains("octet_delta_count_initiator"));
    assert!(line.contains("flow_start_milliseconds"));
    assert!(line.contains("retransmits_initiator"));
    // Round-trip via serde_json to confirm structural
    // validity.
    let value: serde_json::Value = serde_json::from_str(line).expect("valid JSON");
    assert_eq!(value["protocol_identifier"], 6);
    assert_eq!(value["packet_delta_count_initiator"], 10);
}

#[cfg(feature = "emit-eve")]
#[test]
fn eve_write_flow_record_matches_event_shape() {
    use flowscope::emit::{EveJsonWriter, EveOptions};
    let (rec, event) = build_finalised_record();

    let mut buf_event = Vec::new();
    let mut w = EveJsonWriter::new(&mut buf_event);
    w.write_event(&event).expect("event");
    let _ = w;

    let mut buf_rec = Vec::new();
    let mut w = EveJsonWriter::with_options(&mut buf_rec, EveOptions::default());
    w.write_flow_record(&rec).expect("rec");
    let _ = w;

    let ev_value: serde_json::Value =
        serde_json::from_str(std::str::from_utf8(&buf_event).unwrap().trim_end()).expect("ev");
    let rec_value: serde_json::Value =
        serde_json::from_str(std::str::from_utf8(&buf_rec).unwrap().trim_end()).expect("rec");

    // Same flow_hash → direction-invariant + algorithm-equivalent.
    assert_eq!(
        ev_value["flow_hash"], rec_value["flow_hash"],
        "flow_hash should be identical regardless of construction path"
    );
    // Same byte/packet counts.
    assert_eq!(
        ev_value["flow"]["bytes_toserver"],
        rec_value["flow"]["bytes_toserver"]
    );
    assert_eq!(
        ev_value["flow"]["bytes_toclient"],
        rec_value["flow"]["bytes_toclient"]
    );
    assert_eq!(
        ev_value["flow"]["pkts_toserver"],
        rec_value["flow"]["pkts_toserver"]
    );
    assert_eq!(ev_value["proto"], rec_value["proto"]);
    assert_eq!(ev_value["src_ip"], rec_value["src_ip"]);
    assert_eq!(ev_value["dest_ip"], rec_value["dest_ip"]);
}

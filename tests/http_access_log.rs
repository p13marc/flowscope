//! Access logging and metrics for the inline path (#168).
//!
//! An operator switching a deployment from passive observation to
//! inline proxying should not lose visibility. These tests pin the
//! two halves of that: the records reach the EVE writer in the shape
//! a SIEM already ingests, and the `flowscope_*` counters move.

#![cfg(all(feature = "http", feature = "emit-eve"))]

use bytes::Bytes;
use flowscope::emit::EveJsonWriter;
use flowscope::http::{HttpAccessLog, HttpAccessOutcome, HttpAccessRecord, HttpProxyParser};
use flowscope::{FlowSide, Timestamp};

/// Drive a connection through the proxy parser and collect the
/// access records it produces.
fn access_records(client: &[u8], server: &[u8]) -> Vec<HttpAccessRecord> {
    let mut proxy = HttpProxyParser::new();
    let mut log = HttpAccessLog::new();
    let mut out = Vec::new();
    proxy.push(FlowSide::Initiator, &Bytes::copy_from_slice(client));
    proxy.push(FlowSide::Responder, &Bytes::copy_from_slice(server));
    while let Some(ev) = proxy.next_event() {
        log.observe(&ev, &mut out);
    }
    log.finish(proxy.poison(), &mut out);
    out
}

fn to_eve(records: &[HttpAccessRecord]) -> Vec<serde_json::Value> {
    let mut buf = Vec::new();
    {
        let mut w = EveJsonWriter::new(&mut buf);
        for r in records {
            w.write_http_access(r, Timestamp::new(1_700_000_000, 0))
                .expect("write");
        }
        w.flush().expect("flush");
    }
    String::from_utf8(buf)
        .expect("utf8")
        .lines()
        .map(|l| serde_json::from_str(l).expect("every line is valid JSON"))
        .collect()
}

#[test]
fn a_completed_exchange_emits_a_suricata_shaped_http_event() {
    let recs = access_records(
        b"POST /orders HTTP/1.1\r\nHost: api.example\r\nContent-Length: 5\r\n\r\nhello",
        b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok",
    );
    let lines = to_eve(&recs);
    assert_eq!(lines.len(), 1);
    let v = &lines[0];

    assert_eq!(v["event_type"], "http");
    assert_eq!(v["app_proto"], "http");
    assert_eq!(v["http"]["hostname"], "api.example");
    assert_eq!(v["http"]["http_method"], "POST");
    assert_eq!(v["http"]["url"], "/orders");
    assert_eq!(v["http"]["status"], 201);
    assert_eq!(v["http"]["request_body_len"], 5);
    assert_eq!(v["http"]["response_body_len"], 2);
    assert_eq!(v["http"]["protocol"], "HTTP/1.1");
    assert_eq!(v["flowscope"]["outcome"], "completed");
    assert!(v["timestamp"].is_string());
}

#[test]
fn a_refused_connection_is_logged_with_its_reason() {
    // The event an operator most wants: the proxy refused to forward,
    // and the log says exactly why rather than going quiet.
    let recs = access_records(
        b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 6\r\n\
          Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        b"",
    );
    let lines = to_eve(&recs);
    for v in &lines {
        assert_eq!(v["flowscope"]["outcome"], "refused");
        assert_eq!(
            v["flowscope"]["refused_reason"],
            "content-length-with-transfer-encoding"
        );
    }
}

#[test]
fn an_unanswered_request_is_still_logged() {
    let recs = access_records(b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n", b"");
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].outcome, HttpAccessOutcome::NoResponse);
    let lines = to_eve(&recs);
    assert_eq!(lines[0]["flowscope"]["outcome"], "no_response");
    // No status field at all, rather than a fabricated zero.
    assert!(lines[0]["http"].get("status").is_none());
}

#[test]
fn a_tunnel_is_logged_as_switched() {
    let recs = access_records(
        b"CONNECT db.example:5432 HTTP/1.1\r\nHost: db.example:5432\r\n\r\n",
        b"HTTP/1.1 200 Connection Established\r\n\r\n",
    );
    let lines = to_eve(&recs);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["http"]["http_method"], "CONNECT");
    assert_eq!(lines[0]["flowscope"]["outcome"], "switched");
}

#[test]
fn pipelined_exchanges_produce_one_line_each_in_order() {
    let recs = access_records(
        b"GET /a HTTP/1.1\r\nHost: h\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA\
          HTTP/1.1 500 Server Error\r\nContent-Length: 1\r\n\r\nB",
    );
    let lines = to_eve(&recs);
    let urls: Vec<&str> = lines
        .iter()
        .map(|v| v["http"]["url"].as_str().unwrap())
        .collect();
    let codes: Vec<u64> = lines
        .iter()
        .map(|v| v["http"]["status"].as_u64().unwrap())
        .collect();
    assert_eq!(urls, vec!["/a", "/b"]);
    assert_eq!(codes, vec![200, 500]);
}

#[test]
fn access_logging_holds_no_body_bytes() {
    // The whole point of logging from the streaming path: a 1 MB
    // upload is counted, not retained.
    let mut proxy = HttpProxyParser::new();
    let mut log = HttpAccessLog::new();
    let mut out = Vec::new();

    let head =
        Bytes::from_static(b"PUT /upload HTTP/1.1\r\nHost: h\r\nContent-Length: 1048576\r\n\r\n");
    proxy.push(FlowSide::Initiator, &head);
    while let Some(ev) = proxy.next_event() {
        log.observe(&ev, &mut out);
    }

    let chunk = Bytes::from(vec![b'x'; 8192]);
    let mut sent = 0usize;
    while sent < 1_048_576 {
        let n = proxy.push(FlowSide::Initiator, &chunk);
        sent += n;
        while let Some(ev) = proxy.next_event() {
            log.observe(&ev, &mut out);
        }
        assert!(
            proxy.buffered(FlowSide::Initiator) < 1_048_576,
            "the body must never be accumulated"
        );
    }

    log.finish(proxy.poison(), &mut out);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].request_body_bytes, 1_048_576, "counted, not kept");
}

#[cfg(feature = "metrics")]
#[test]
fn streaming_path_moves_the_flowscope_counters() {
    use metrics_util::debugging::{DebuggingRecorder, Snapshotter};

    let recorder = DebuggingRecorder::new();
    let snapshotter: Snapshotter = recorder.snapshotter();
    metrics::with_local_recorder(&recorder, || {
        let mut proxy = HttpProxyParser::new();
        proxy.push(
            FlowSide::Initiator,
            &Bytes::from_static(b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n"),
        );
        proxy.push(
            FlowSide::Responder,
            &Bytes::from_static(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
        );
        while proxy.next_event().is_some() {}

        // And a refused one, so the poison counter moves too.
        let mut bad = HttpProxyParser::new();
        bad.push(
            FlowSide::Initiator,
            &Bytes::from_static(
                b"POST /a HTTP/1.1\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n",
            ),
        );
        while bad.next_event().is_some() {}
    });

    let rendered = format!("{:?}", snapshotter.snapshot().into_vec());
    assert!(
        rendered.contains("flowscope_http_messages_total"),
        "framed messages must be counted: {rendered}"
    );
    assert!(
        rendered.contains("flowscope_http_poisoned_total"),
        "refusals must be counted: {rendered}"
    );
    assert!(
        rendered.contains("content-length-with-transfer-encoding"),
        "the refusal reason must be a metric label: {rendered}"
    );
}

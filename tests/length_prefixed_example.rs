//! Integration test for the length-prefixed binary protocol example.
//!
//! Re-implements the same `SessionParser` shape that
//! `examples/length_prefixed_pcap.rs` uses (cargo doesn't share
//! source between an example and an integration test) and verifies:
//!
//! 1. Running the parser against `tests/fixtures/length_prefixed/sample.pcap`
//!    yields the expected message count, sides, and body sizes.
//! 2. The parser correctly buffers partial headers and partial
//!    bodies — feeding the same wire bytes one byte at a time
//!    produces identical output.

#![cfg(all(feature = "pcap", feature = "session", feature = "extractors"))]

use flowscope::extract::FiveTuple;
use flowscope::pcap::PcapFlowSource;
use flowscope::{FlowSessionDriver, FlowSide, SessionEvent, SessionParser};

const MARKER_2: &[u8] = b"PFX2,";
const MARKER_4: &[u8] = b"PFX4,";
const HDR_LEN_2: usize = MARKER_2.len() + 2;
const HDR_LEN_4: usize = MARKER_4.len() + 4;
const FIXTURE: &str = "tests/fixtures/length_prefixed/sample.pcap";

#[derive(Debug, Clone)]
struct Record {
    side: FlowSide,
    body: Vec<u8>,
}

#[derive(Default, Clone)]
struct LengthPrefixedParser {
    init_buf: Vec<u8>,
    resp_buf: Vec<u8>,
}

impl SessionParser for LengthPrefixedParser {
    type Message = Record;
    fn feed_initiator(&mut self, bytes: &[u8]) -> Vec<Record> {
        drain(&mut self.init_buf, bytes, FlowSide::Initiator)
    }
    fn feed_responder(&mut self, bytes: &[u8]) -> Vec<Record> {
        drain(&mut self.resp_buf, bytes, FlowSide::Responder)
    }
}

fn drain(buf: &mut Vec<u8>, incoming: &[u8], side: FlowSide) -> Vec<Record> {
    buf.extend_from_slice(incoming);
    let mut out = Vec::new();
    while let Some((hdr, body_len)) = peek_header(buf) {
        let total = hdr + body_len;
        if buf.len() < total {
            break;
        }
        let body = buf[hdr..total].to_vec();
        buf.drain(..total);
        out.push(Record { side, body });
    }
    out
}

fn peek_header(buf: &[u8]) -> Option<(usize, usize)> {
    if buf.len() < HDR_LEN_2 {
        return None;
    }
    if buf.starts_with(MARKER_4) {
        if buf.len() < HDR_LEN_4 {
            return None;
        }
        let len = u32::from_be_bytes(buf[MARKER_4.len()..HDR_LEN_4].try_into().unwrap()) as usize;
        return Some((HDR_LEN_4, len));
    }
    if buf.starts_with(MARKER_2) {
        let len = u16::from_be_bytes(buf[MARKER_2.len()..HDR_LEN_2].try_into().unwrap()) as usize;
        return Some((HDR_LEN_2, len));
    }
    None
}

fn collect_messages(path: &str) -> Vec<Record> {
    let mut driver = FlowSessionDriver::<_, LengthPrefixedParser>::new(FiveTuple::bidirectional());
    let mut messages = Vec::new();
    for view in PcapFlowSource::open(path).expect("open fixture").views() {
        let view = view.expect("read packet");
        for ev in driver.track(view.as_view()) {
            if let SessionEvent::Application { message, .. } = ev {
                messages.push(message);
            }
        }
    }
    messages
}

#[test]
fn parses_pcap_fixture() {
    let messages = collect_messages(FIXTURE);
    assert_eq!(messages.len(), 10, "expected 10 messages on the wire");

    let init: Vec<&Record> = messages
        .iter()
        .filter(|m| m.side == FlowSide::Initiator)
        .collect();
    let resp: Vec<&Record> = messages
        .iter()
        .filter(|m| m.side == FlowSide::Responder)
        .collect();
    assert_eq!(init.len(), 5);
    assert_eq!(resp.len(), 5);

    // Initiator: five PFX2 messages, each 6-byte body ("init-0".."init-4").
    for (i, m) in init.iter().enumerate() {
        assert_eq!(m.body, format!("init-{}", i).into_bytes());
    }
    // Responder: four PFX2 (6-byte) + one PFX4 (700-byte).
    for (i, m) in resp.iter().take(4).enumerate() {
        assert_eq!(m.body, format!("resp-{}", i).into_bytes());
    }
    assert_eq!(resp[4].body.len(), 700);
    assert!(resp[4].body.iter().all(|&b| b == b'X'));
}

#[test]
fn handles_split_headers_and_bodies() {
    // Construct the same wire bytes the fixture uses for the
    // initiator side, then feed the parser one byte at a time.
    let mut payload = Vec::new();
    for i in 0u16..5 {
        let body = format!("init-{}", i);
        payload.extend_from_slice(MARKER_2);
        payload.extend_from_slice(&(body.len() as u16).to_be_bytes());
        payload.extend_from_slice(body.as_bytes());
    }

    let mut parser = LengthPrefixedParser::default();
    let mut out = Vec::new();
    for byte in &payload {
        out.extend(parser.feed_initiator(std::slice::from_ref(byte)));
    }
    assert_eq!(out.len(), 5);
    for (i, m) in out.iter().enumerate() {
        assert_eq!(m.body, format!("init-{}", i).into_bytes());
        assert_eq!(m.side, FlowSide::Initiator);
    }
}

#[test]
fn parser_stalls_on_unknown_marker() {
    // The example's recovery policy is "stall the parser" rather
    // than "drop a byte and resync" — verify that contract.
    let mut parser = LengthPrefixedParser::default();
    assert!(parser.feed_initiator(b"GARBAGE-NOT-PFX").is_empty());
    // A subsequent valid frame is invisible until the parser resyncs
    // (which this minimal example does not do).
    let mut tail = Vec::new();
    tail.extend_from_slice(MARKER_2);
    tail.extend_from_slice(&3u16.to_be_bytes());
    tail.extend_from_slice(b"abc");
    assert!(parser.feed_initiator(&tail).is_empty());
}

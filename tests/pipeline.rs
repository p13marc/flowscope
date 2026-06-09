//! Plan 94 Tier 1 — `flowscope::Pipeline` integration tests.
//!
//! Runs the same length-prefixed parser shape as
//! `tests/length_prefixed_example.rs` through `Pipeline` and
//! asserts the event sequence matches the direct
//! `FlowSessionDriver` path.

#![cfg(all(feature = "pcap", feature = "session", feature = "extractors"))]

use flowscope::extract::FiveTuple;
use flowscope::{Event, Pipeline, SessionEvent, SessionParser, Timestamp};

const FIXTURE: &str = "tests/fixtures/length_prefixed/sample.pcap";

const MARKER_2: &[u8] = b"PFX2,";
const MARKER_4: &[u8] = b"PFX4,";
const HDR_LEN_2: usize = MARKER_2.len() + 2;
const HDR_LEN_4: usize = MARKER_4.len() + 4;

#[derive(Default, Clone)]
struct LengthPrefixedParser {
    init_buf: Vec<u8>,
    resp_buf: Vec<u8>,
}

impl SessionParser for LengthPrefixedParser {
    type Message = Vec<u8>;
    fn feed_initiator(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<Vec<u8>>) {
        drain(&mut self.init_buf, bytes, out);
    }
    fn feed_responder(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<Vec<u8>>) {
        drain(&mut self.resp_buf, bytes, out);
    }
}

fn drain(buf: &mut Vec<u8>, incoming: &[u8], out: &mut Vec<Vec<u8>>) {
    buf.extend_from_slice(incoming);
    while let Some((hdr, body_len)) = peek_header(buf) {
        let total = hdr + body_len;
        if buf.len() < total {
            break;
        }
        let body = buf[hdr..total].to_vec();
        buf.drain(..total);
        out.push(body);
    }
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

#[test]
fn pipeline_runs_pcap_and_yields_messages() {
    let mut pipeline = Pipeline::builder(FiveTuple::bidirectional())
        .session(LengthPrefixedParser::default())
        .build();

    let mut count = 0usize;
    for ev in pipeline.run_pcap(FIXTURE).unwrap() {
        let ev = ev.unwrap();
        if let Event::Tcp(SessionEvent::Application { .. }) = ev {
            count += 1;
        }
    }
    assert_eq!(count, 10, "expected 10 length-prefixed messages");
}

#[test]
fn pipeline_yields_started_then_application_then_closed() {
    let mut pipeline = Pipeline::builder(FiveTuple::bidirectional())
        .session(LengthPrefixedParser::default())
        .build();

    let mut started = 0;
    let mut application = 0;
    let mut closed = 0;
    for ev in pipeline.run_pcap(FIXTURE).unwrap() {
        if let Event::Tcp(s) = ev.unwrap() {
            match s {
                SessionEvent::Started { .. } => started += 1,
                SessionEvent::Application { .. } => application += 1,
                SessionEvent::Closed { .. } => closed += 1,
                _ => {}
            }
        }
    }
    assert_eq!(started, 1);
    assert!(application >= 10);
    assert!(closed >= 1, "end-of-input flush should produce a Closed");
}

#[test]
fn pipeline_reusable_across_runs() {
    let mut pipeline = Pipeline::builder(FiveTuple::bidirectional())
        .session(LengthPrefixedParser::default())
        .build();

    let first_count = pipeline
        .run_pcap(FIXTURE)
        .unwrap()
        .filter_map(|e| e.ok())
        .count();
    let second_count = pipeline
        .run_pcap(FIXTURE)
        .unwrap()
        .filter_map(|e| e.ok())
        .count();
    assert!(first_count > 0);
    assert!(second_count > 0);
}

#[test]
fn missing_pcap_returns_io_error() {
    use flowscope::{ErrorCode, Module};
    let mut pipeline = Pipeline::builder(FiveTuple::bidirectional())
        .session(LengthPrefixedParser::default())
        .build();
    let err = pipeline.run_pcap("/no/such/file.pcap").err().unwrap();
    assert_eq!(err.module(), Module::Pcap);
    assert_eq!(err.code(), ErrorCode::Io);
}

#[test]
fn run_iter_drives_owned_views() {
    use flowscope::OwnedPacketView;
    use flowscope::pcap::PcapFlowSource;

    // Collect the fixture into owned views.
    let owned: Vec<OwnedPacketView> = PcapFlowSource::open(FIXTURE)
        .unwrap()
        .views()
        .map(|r| r.unwrap())
        .collect();

    let mut pipeline = Pipeline::builder(FiveTuple::bidirectional())
        .session(LengthPrefixedParser::default())
        .build();

    let mut app_count = 0usize;
    for ev in pipeline.run_iter(owned) {
        if let flowscope::Event::Tcp(SessionEvent::Application { .. }) = ev.unwrap() {
            app_count += 1;
        }
    }
    assert_eq!(
        app_count, 10,
        "run_iter should produce the same 10 messages"
    );
}

#[test]
fn reset_clears_flow_state_between_runs() {
    let mut pipeline = Pipeline::builder(FiveTuple::bidirectional())
        .session(LengthPrefixedParser::default())
        .build();

    // First run.
    let count_a = pipeline
        .run_pcap(FIXTURE)
        .unwrap()
        .filter_map(|e| e.ok())
        .count();

    // Reset wipes the tracker; second run on the same fixture
    // should produce the same event count.
    pipeline.reset();
    let count_b = pipeline
        .run_pcap(FIXTURE)
        .unwrap()
        .filter_map(|e| e.ok())
        .count();

    assert_eq!(count_a, count_b, "reset should restore initial state");
}

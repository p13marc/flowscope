//! End-to-end test: feed the HTTP fixture through PcapFlowSource +
//! FlowSessionDriver + HttpParser (SessionParser-style API).
//!
//! Verifies that real HTTP/1.1 traffic (the synthetic exchange in
//! `http_session.pcap`) round-trips through the entire stack.

use std::io::Cursor;

use flowscope::extract::FiveTuple;
use flowscope::http::{HttpMessage, HttpParser};
use flowscope::pcap::PcapFlowSource;
use flowscope::{FlowSessionDriver, SessionEvent};

const HTTP_SESSION: &[u8] = include_bytes!("data/http_session.pcap");

#[test]
fn http_pcap_emits_request_and_response() {
    let mut driver = FlowSessionDriver::new(FiveTuple::bidirectional(), HttpParser::default());

    let src = PcapFlowSource::from_reader(Cursor::new(HTTP_SESSION)).unwrap();
    let mut reqs = Vec::new();
    let mut resps = Vec::new();
    let mut last_ts = None;
    for view in src.views() {
        let view = view.unwrap();
        last_ts = Some(view.timestamp);
        for ev in driver.track(&view) {
            if let SessionEvent::Application { message, .. } = ev {
                match message {
                    HttpMessage::Request(r) => reqs.push(r),
                    HttpMessage::Response(r) => resps.push(r),
                }
            }
        }
    }
    // Final sweep so the FIN'd flow's reassemblers fire fin().
    if let Some(ts) = last_ts {
        let far = flowscope::Timestamp::new(ts.sec.saturating_add(86_400), 0);
        for ev in driver.sweep(far) {
            if let SessionEvent::Application { message, .. } = ev {
                match message {
                    HttpMessage::Request(r) => reqs.push(r),
                    HttpMessage::Response(r) => resps.push(r),
                }
            }
        }
    }

    assert_eq!(reqs.len(), 1, "expected exactly 1 HTTP request");
    assert_eq!(resps.len(), 1, "expected exactly 1 HTTP response");

    assert_eq!(reqs[0].method_str(), Some("GET"));
    assert_eq!(reqs[0].path_str(), Some("/index.html"));
    assert!(
        reqs[0]
            .headers
            .iter()
            .any(|(n, _)| n.as_ref().eq_ignore_ascii_case(b"host")),
        "Host header expected"
    );

    assert_eq!(resps[0].status, 200);
    assert_eq!(resps[0].reason_str(), Some("OK"));
    assert_eq!(&*resps[0].body, b"Hello, world!");
}

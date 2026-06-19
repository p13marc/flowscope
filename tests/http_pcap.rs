//! End-to-end test: feed the HTTP fixture through PcapFlowSource +
//! the typed `Driver<E>` + HttpParser (plan 121 shape).
//!
//! Verifies that real HTTP/1.1 traffic (the synthetic exchange in
//! `http_session.pcap`) round-trips through the entire stack.

use std::io::Cursor;

use flowscope::{
    driver::{Driver, Event, SlotMessage},
    extract::{FiveTuple, FiveTupleKey},
    http::{HttpMessage, HttpParser},
    pcap::PcapFlowSource,
};

const HTTP_SESSION: &[u8] = include_bytes!("data/http_session.pcap");

#[test]
fn http_pcap_emits_request_and_response() {
    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut http_slot = builder.session_on_ports(HttpParser::default(), [80]);
    let mut driver = builder.build();

    let src = PcapFlowSource::from_reader(Cursor::new(HTTP_SESSION)).unwrap();
    let mut reqs = Vec::new();
    let mut resps = Vec::new();
    let mut last_ts = None;

    let mut events: Vec<Event<FiveTupleKey>> = Vec::new();
    let mut msgs: Vec<SlotMessage<HttpMessage, FiveTupleKey>> = Vec::new();

    for view in src.views() {
        let view = view.unwrap();
        last_ts = Some(view.timestamp);

        events.clear();
        driver.track_into(&view, &mut events);
        msgs.clear();
        http_slot.drain(&mut msgs);

        for m in msgs.drain(..) {
            match m.message {
                HttpMessage::Request(r) => reqs.push(r),
                HttpMessage::Response(r) => resps.push(r),
            }
        }
    }
    // Final sweep so the FIN'd flow's reassemblers fire fin().
    if let Some(ts) = last_ts {
        let far = flowscope::Timestamp::new(ts.sec.saturating_add(86_400), 0);
        events.clear();
        driver.sweep_into(far, &mut events);
        msgs.clear();
        http_slot.drain(&mut msgs);
        for m in msgs.drain(..) {
            match m.message {
                HttpMessage::Request(r) => reqs.push(r),
                HttpMessage::Response(r) => resps.push(r),
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

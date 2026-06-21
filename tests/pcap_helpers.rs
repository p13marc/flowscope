//! Smoke tests for the per-parser `*_from_pcap` helpers and
//! `Driver::run_pcap`. Walks the bundled fixtures end-to-end
//! through each one-call iterator and asserts on its shape.

#![cfg(all(feature = "pcap", feature = "extractors", feature = "tracker"))]

const HTTP_PCAP: &str = "tests/data/http_session.pcap";
const DNS_PCAP: &str = "tests/data/dns_queries.pcap";

#[test]
#[cfg(feature = "http")]
fn http_requests_from_pcap_walks_fixture() {
    let mut count = 0u32;
    for (_key, req) in flowscope::http::requests_from_pcap(HTTP_PCAP).expect("open") {
        count += 1;
        assert!(req.method_str().is_some());
    }
    assert!(count > 0, "expected ≥1 HTTP request in {HTTP_PCAP}");
}

#[test]
#[cfg(feature = "http")]
fn http_responses_from_pcap_walks_fixture() {
    let mut count = 0u32;
    for (_key, resp) in flowscope::http::responses_from_pcap(HTTP_PCAP).expect("open") {
        count += 1;
        assert!(resp.status >= 100);
    }
    assert!(count > 0, "expected ≥1 HTTP response in {HTTP_PCAP}");
}

#[test]
#[cfg(feature = "http")]
fn http_exchanges_from_pcap_walks_fixture() {
    let mut count = 0u32;
    for (_key, ex) in flowscope::http::exchanges_from_pcap(HTTP_PCAP).expect("open") {
        count += 1;
        assert!(ex.request.method_str().is_some());
    }
    assert!(count > 0);
}

#[test]
#[cfg(feature = "dns")]
fn dns_messages_from_pcap_walks_fixture() {
    let mut count = 0u32;
    for (_key, _msg) in flowscope::dns::messages_from_pcap(DNS_PCAP).expect("open") {
        count += 1;
    }
    assert!(count > 0, "expected ≥1 DNS message in {DNS_PCAP}");
}

#[test]
fn flow_summaries_from_pcap_walks_fixture() {
    let summaries: Vec<_> = flowscope::pcap::flow_summaries_from_pcap(HTTP_PCAP)
        .expect("open")
        .collect();
    assert!(!summaries.is_empty(), "expected ≥1 flow summary");
    let (_key, stats, _reason) = &summaries[0];
    assert!(stats.bytes_initiator + stats.bytes_responder > 0);
}

#[test]
fn driver_run_pcap_yields_lifecycle_events() {
    use flowscope::driver::{Driver, Event};
    use flowscope::extract::FiveTuple;

    let driver = Driver::builder(FiveTuple::bidirectional()).build();
    let mut started = 0u32;
    let mut ended = 0u32;
    for ev in driver.run_pcap(HTTP_PCAP).expect("open") {
        match ev.expect("event") {
            Event::FlowStarted { .. } => started += 1,
            Event::FlowEnded { .. } => ended += 1,
            _ => {}
        }
    }
    assert!(started > 0, "expected ≥1 FlowStarted");
    assert!(ended > 0, "expected ≥1 FlowEnded after iterator drain");
}

#[test]
#[cfg(feature = "http")]
fn driver_run_pcap_drives_registered_slots() {
    use flowscope::driver::{Driver, SlotMessage};
    use flowscope::extract::{FiveTuple, FiveTupleKey};
    use flowscope::http::{HttpMessage, HttpParser};

    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut http_slot = builder.session_on_ports(HttpParser::default(), [80, 8080]);
    let driver = builder.build();

    // Drain the iterator; messages should land in the slot.
    for ev in driver.run_pcap(HTTP_PCAP).expect("open") {
        let _ = ev.expect("event");
    }
    let mut msgs: Vec<SlotMessage<HttpMessage, FiveTupleKey>> = Vec::new();
    http_slot.drain(&mut msgs);
    assert!(
        !msgs.is_empty(),
        "expected HTTP slot to receive ≥1 message during run_pcap"
    );
}

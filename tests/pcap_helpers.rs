//! Smoke tests for the generic `pcap::session_messages` /
//! `pcap::datagram_messages` one-call iterators (issue #86) and
//! `Driver::run_pcap`. Walks the bundled fixtures end-to-end through
//! each entry point and asserts on its shape.

#![cfg(all(feature = "pcap", feature = "extractors", feature = "tracker"))]

const HTTP_PCAP: &str = "tests/data/http_session.pcap";
const DNS_PCAP: &str = "tests/data/dns_queries.pcap";

#[test]
#[cfg(feature = "http")]
fn http_requests_from_pcap_walks_fixture() {
    use flowscope::http::{HttpMessage, HttpParser};

    let mut count = 0u32;
    for (_key, msg) in flowscope::pcap::session_messages::<HttpParser>(HTTP_PCAP).expect("open") {
        if let HttpMessage::Request(req) = msg {
            count += 1;
            assert!(req.method_str().is_some());
        }
    }
    assert!(count > 0, "expected ≥1 HTTP request in {HTTP_PCAP}");
}

#[test]
#[cfg(feature = "http")]
fn http_responses_from_pcap_walks_fixture() {
    use flowscope::http::{HttpMessage, HttpParser};

    let mut count = 0u32;
    for (_key, msg) in flowscope::pcap::session_messages::<HttpParser>(HTTP_PCAP).expect("open") {
        if let HttpMessage::Response(resp) = msg {
            count += 1;
            assert!(resp.status >= 100);
        }
    }
    assert!(count > 0, "expected ≥1 HTTP response in {HTTP_PCAP}");
}

#[test]
#[cfg(feature = "http")]
fn http_exchanges_from_pcap_walks_fixture() {
    use flowscope::http::HttpExchangeParser;

    let mut count = 0u32;
    for (_key, ex) in
        flowscope::pcap::session_messages::<HttpExchangeParser>(HTTP_PCAP).expect("open")
    {
        count += 1;
        assert!(ex.request.method_str().is_some());
    }
    assert!(count > 0);
}

#[test]
#[cfg(feature = "dns")]
fn dns_messages_from_pcap_walks_fixture() {
    use flowscope::dns::DnsUdpParser;

    let mut count = 0u32;
    for (_key, _msg) in flowscope::pcap::datagram_messages::<DnsUdpParser>(DNS_PCAP).expect("open")
    {
        count += 1;
    }
    assert!(count > 0, "expected ≥1 DNS message in {DNS_PCAP}");
}

/// Focused test for the generic `pcap::session_messages::<P>` entry —
/// every yielded item is keyed by the flow's `FiveTupleKey` and the
/// message is a well-formed `HttpMessage` (issue #86).
#[test]
#[cfg(feature = "http")]
fn session_messages_generic_yields_keyed_http_messages() {
    use flowscope::http::{HttpMessage, HttpParser};

    let pairs: Vec<_> = flowscope::pcap::session_messages::<HttpParser>(HTTP_PCAP)
        .expect("open")
        .collect();

    assert!(
        !pairs.is_empty(),
        "expected ≥1 (key, HttpMessage) pair in {HTTP_PCAP}"
    );

    let mut saw_request = false;
    for (key, msg) in &pairs {
        // Every message is keyed by a non-zero-port flow endpoint.
        assert!(key.a.port() != 0 || key.b.port() != 0);
        match msg {
            HttpMessage::Request(req) => {
                saw_request = true;
                assert!(req.method_str().is_some());
            }
            HttpMessage::Response(resp) => assert!(resp.status >= 100),
            _ => {}
        }
    }
    assert!(saw_request, "expected ≥1 HTTP request among the messages");
}

/// Focused test for the generic `pcap::datagram_messages::<P>` entry
/// (UDP path) — exercises a `DatagramParser` over a DNS fixture and
/// asserts every item is keyed (issue #86).
#[test]
#[cfg(feature = "dns")]
fn datagram_messages_generic_yields_keyed_dns_messages() {
    use flowscope::dns::DnsUdpParser;

    let pairs: Vec<_> = flowscope::pcap::datagram_messages::<DnsUdpParser>(DNS_PCAP)
        .expect("open")
        .collect();

    assert!(
        !pairs.is_empty(),
        "expected ≥1 (key, DnsMessage) pair in {DNS_PCAP}"
    );
    for (key, _msg) in &pairs {
        assert!(key.a.port() != 0 || key.b.port() != 0);
    }
}

#[test]
fn flow_summaries_walks_fixture() {
    let summaries: Vec<_> = flowscope::pcap::flow_summaries(HTTP_PCAP)
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

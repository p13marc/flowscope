//! Issue #100 — public offline-L7 surface.
//!
//! The old crate-private offline-L7 iterators went private in #100.
//! This test asserts the equivalent behaviour through the public
//! replacements: [`flowscope::pcap::session_messages`] /
//! [`flowscope::pcap::datagram_messages`] for the typed-message
//! counts and [`flowscope::driver::Driver::run_pcap`] for the
//! flow-lifecycle (started / ended) counts.

use std::io::Cursor;

use flowscope::driver::{Driver, Event};
use flowscope::extract::{FiveTuple, FiveTupleKey};
use flowscope::pcap::{PcapFlowSource, datagram_messages, session_messages};
use flowscope::{DatagramParser, FlowSide, SessionParser, Timestamp};

const HTTP_SESSION_PATH: &str = "tests/data/http_session.pcap";
const DNS_QUERIES_PATH: &str = "tests/data/dns_queries.pcap";

/// A valid pcap global header with zero packets (LE, microsecond
/// magic, Ethernet linktype).
const EMPTY_PCAP: [u8; 24] = [
    0xd4, 0xc3, 0xb2, 0xa1, // magic
    0x02, 0x00, 0x04, 0x00, // version 2.4
    0x00, 0x00, 0x00, 0x00, // thiszone
    0x00, 0x00, 0x00, 0x00, // sigfigs
    0xff, 0xff, 0x00, 0x00, // snaplen 65535
    0x01, 0x00, 0x00, 0x00, // LINKTYPE_ETHERNET
];

/// Emits the byte count of every chunk fed on either side.
#[derive(Default, Clone)]
struct ByteCounter;
impl SessionParser for ByteCounter {
    type Message = usize;
    fn feed_initiator(&mut self, b: &[u8], _ts: Timestamp, out: &mut Vec<usize>) {
        out.push(b.len());
    }
    fn feed_responder(&mut self, b: &[u8], _ts: Timestamp, out: &mut Vec<usize>) {
        out.push(b.len());
    }
}

/// Emits the byte count of every UDP payload.
#[derive(Default, Clone)]
struct DgramSizer;
impl DatagramParser for DgramSizer {
    type Message = usize;
    fn parse(&mut self, payload: &[u8], _side: FlowSide, _ts: Timestamp, out: &mut Vec<usize>) {
        out.push(payload.len());
    }
}

#[test]
fn session_messages_yields_application_payload() {
    let msgs: Vec<_> = session_messages::<ByteCounter>(HTTP_SESSION_PATH)
        .expect("open pcap")
        .collect();
    assert!(!msgs.is_empty(), "the session carried payload");
}

#[test]
fn run_pcap_yields_session_lifecycle() {
    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let _slot = builder.session_broadcast(ByteCounter);
    let driver = builder.build();

    let mut started = 0usize;
    let mut ended = 0usize;
    for ev in driver.run_pcap(HTTP_SESSION_PATH).expect("open pcap") {
        match ev.expect("event") {
            Event::FlowStarted { .. } => started += 1,
            Event::FlowEnded { .. } => ended += 1,
            _ => {}
        }
    }
    assert_eq!(started, 1, "one TCP session in the fixture");
    // The session closes via FIN or the driver's end-of-input flush.
    assert_eq!(ended, 1, "the session ends exactly once");
}

#[test]
fn datagram_messages_yields_parsed_datagrams() {
    let msgs: Vec<_> = datagram_messages::<DgramSizer>(DNS_QUERIES_PATH)
        .expect("open pcap")
        .collect();
    assert!(!msgs.is_empty(), "expected at least one parsed datagram");
}

#[test]
fn run_pcap_yields_datagram_lifecycle() {
    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let _slot = builder.datagram_broadcast(DgramSizer);
    let driver = builder.build();

    let mut started = 0usize;
    let mut ended = 0usize;
    for ev in driver.run_pcap(DNS_QUERIES_PATH).expect("open pcap") {
        match ev.expect("event") {
            Event::FlowStarted { .. } => started += 1,
            Event::FlowEnded { .. } => ended += 1,
            _ => {}
        }
    }
    assert!(started >= 1, "expected at least one UDP flow");
    // The end-of-input flush must close every UDP flow it started.
    assert_eq!(ended, started, "every UDP flow ends");
}

#[test]
fn empty_pcap_yields_no_messages_or_lifecycle() {
    // Message side: no typed messages over a zero-packet pcap.
    // (`session_messages` is path-based, so drive the reader-based
    // manual loop to assert the same thing over the in-memory empty
    // pcap.)
    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut slot = builder.session_broadcast(ByteCounter);
    let mut driver = builder.build();

    let source = PcapFlowSource::from_reader(Cursor::new(&EMPTY_PCAP[..])).expect("open pcap");
    let mut events: Vec<Event<FiveTupleKey>> = Vec::new();
    for owned in source.views() {
        let owned = owned.expect("view");
        driver.track_into(&owned, &mut events);
    }
    driver.finish_into(&mut events);

    let mut msgs = Vec::new();
    slot.drain(&mut msgs);
    assert!(msgs.is_empty(), "a zero-packet pcap yields no messages");
    assert!(events.is_empty(), "a zero-packet pcap yields no events");
}

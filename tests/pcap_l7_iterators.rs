//! Plan 35 — `PcapFlowSource::sessions()` / `datagrams()` iterators.
//!
//! Verifies the one-step offline L7 pipeline: a pcap file in, a
//! stream of typed `SessionEvent`s out, with the end-of-input flush
//! folded into the iterator.

use std::io::Cursor;

use flowscope::extract::FiveTuple;
use flowscope::pcap::PcapFlowSource;
use flowscope::{DatagramParser, FlowSide, SessionEvent, SessionParser};

const HTTP_SESSION: &[u8] = include_bytes!("data/http_session.pcap");
const DNS_QUERIES: &[u8] = include_bytes!("data/dns_queries.pcap");

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
    fn feed_initiator(&mut self, b: &[u8]) -> Vec<usize> {
        vec![b.len()]
    }
    fn feed_responder(&mut self, b: &[u8]) -> Vec<usize> {
        vec![b.len()]
    }
}

/// Emits the byte count of every UDP payload.
#[derive(Default, Clone)]
struct DgramSizer;
impl DatagramParser for DgramSizer {
    type Message = usize;
    fn parse(&mut self, payload: &[u8], _side: FlowSide) -> Vec<usize> {
        vec![payload.len()]
    }
}

#[test]
fn sessions_yields_started_application_closed() {
    let events: Vec<_> = PcapFlowSource::from_reader(Cursor::new(HTTP_SESSION))
        .expect("open pcap")
        .sessions(FiveTuple::bidirectional(), ByteCounter)
        .map(|e| e.expect("event"))
        .collect();

    let started = events
        .iter()
        .filter(|e| matches!(e, SessionEvent::Started { .. }))
        .count();
    let closed = events
        .iter()
        .filter(|e| matches!(e, SessionEvent::Closed { .. }))
        .count();
    let app = events
        .iter()
        .filter(|e| matches!(e, SessionEvent::Application { .. }))
        .count();

    assert_eq!(started, 1, "one TCP session in the fixture");
    assert_eq!(closed, 1, "session closes via FIN or the final finish()");
    assert!(app > 0, "the session carried payload");
}

#[test]
fn datagrams_yields_events_for_udp() {
    let events: Vec<_> = PcapFlowSource::from_reader(Cursor::new(DNS_QUERIES))
        .expect("open pcap")
        .datagrams(FiveTuple::bidirectional(), DgramSizer)
        .map(|e| e.expect("event"))
        .collect();

    assert!(
        events
            .iter()
            .any(|e| matches!(e, SessionEvent::Started { .. })),
        "expected at least one UDP flow"
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, SessionEvent::Application { .. })),
        "expected at least one parsed datagram"
    );
    assert!(
        events
            .iter()
            .any(|e| matches!(e, SessionEvent::Closed { .. })),
        "the final finish() must close every UDP flow"
    );
}

#[test]
fn sessions_over_empty_pcap_is_empty() {
    let events: Vec<_> = PcapFlowSource::from_reader(Cursor::new(&EMPTY_PCAP[..]))
        .expect("open pcap")
        .sessions(FiveTuple::bidirectional(), ByteCounter)
        .collect();
    assert!(events.is_empty(), "a zero-packet pcap yields no events");
}

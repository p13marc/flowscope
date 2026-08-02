//! `HttpProxySession` driven through the typed `Driver` (#164).
//!
//! The adapter's unit tests call the trait methods by hand. What they
//! cannot check is the part that only exists once a driver is
//! involved: that the streaming events actually reach a slot, and
//! that poisoning the parser really does make the driver drop it
//! rather than keep feeding a parser that has lost track of where
//! messages end.
//!
//! Note the signal is `Event::ParserClosed`, not `Event::Ended`: the
//! TCP flow is not flowscope's to close. An inline proxy owns the
//! socket and tears the connection down on this event.

#![cfg(all(
    feature = "http",
    feature = "test-helpers",
    feature = "extractors",
    feature = "session",
    feature = "reassembler",
))]

use flowscope::driver::{Driver, Event};
use flowscope::extract::{FiveTuple, parse::test_frames::ipv4_tcp};
use flowscope::http::{HttpEvent, HttpProxySession};
use flowscope::{EndReason, PacketView, Timestamp};

/// PSH+ACK — an ordinary data packet.
const DATA: u8 = 0x18;

fn packet(sport: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
    ipv4_tcp(
        [1; 6],
        [2; 6],
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        sport,
        80,
        seq,
        0,
        DATA,
        payload,
    )
}

/// Server → client, so the driver sees it as the responder side.
fn response_packet(dport: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
    ipv4_tcp(
        [2; 6],
        [1; 6],
        [10, 0, 0, 2],
        [10, 0, 0, 1],
        80,
        dport,
        seq,
        0,
        DATA,
        payload,
    )
}

#[test]
fn streaming_events_reach_the_slot_through_the_driver() {
    let (mut driver, mut slot) = {
        let mut b = Driver::builder(FiveTuple::bidirectional());
        let slot = b.session_on_ports(HttpProxySession::new(), [80]);
        (b.build(), slot)
    };

    let mut events = Vec::new();
    let req = packet(
        40000,
        1000,
        b"POST /orders HTTP/1.1\r\nHost: api.example\r\nContent-Length: 5\r\n\r\nhello",
    );
    driver.track_into(PacketView::new(&req, Timestamp::new(1, 0)), &mut events);
    let resp = response_packet(
        40000,
        5000,
        b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok",
    );
    driver.track_into(PacketView::new(&resp, Timestamp::new(2, 0)), &mut events);

    let mut msgs = Vec::new();
    slot.drain(&mut msgs);

    // The head must arrive with its routing key intact, through the
    // slot rather than by calling the parser directly.
    let authority = msgs.iter().find_map(|m| match &m.message {
        HttpEvent::RequestHead(h) => h.authority().ok().map(|a| a.host),
        _ => None,
    });
    assert_eq!(authority.as_deref(), Some("api.example"));

    let status = msgs.iter().find_map(|m| match &m.message {
        HttpEvent::ResponseHead(h) => Some(h.status),
        _ => None,
    });
    assert_eq!(status, Some(201));

    let bodies: Vec<u8> = msgs
        .iter()
        .filter_map(|m| match &m.message {
            HttpEvent::Body { data, .. } => Some(data.to_vec()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .concat();
    assert_eq!(bodies, b"hellook");
}

#[test]
fn a_framing_violation_drops_the_parser() {
    // The contract that distinguishes the streaming adapter from the
    // passive one: an ambiguously framed message poisons, and the
    // driver stops feeding a parser that no longer knows where
    // messages end.
    let (mut driver, _slot) = {
        let mut b = Driver::builder(FiveTuple::bidirectional());
        let slot = b.session_on_ports(HttpProxySession::new(), [80]);
        (b.build(), slot)
    };

    let mut events = Vec::new();
    // Content-Length and Transfer-Encoding together — a CL.TE desync.
    let smuggled = packet(
        40001,
        1000,
        b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 6\r\n\
          Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
    );
    driver.track_into(
        PacketView::new(&smuggled, Timestamp::new(1, 0)),
        &mut events,
    );

    let closed = events.iter().find_map(|e| match e {
        Event::ParserClosed { reason, .. } => Some(*reason),
        _ => None,
    });
    assert_eq!(
        closed,
        Some(EndReason::ParseError),
        "a poisoned streaming parser must be dropped with a reason, got {events:?}"
    );
}

#[test]
fn a_well_framed_flow_is_not_torn_down() {
    // The counterpart: ordinary traffic must not trip the teardown.
    let (mut driver, _slot) = {
        let mut b = Driver::builder(FiveTuple::bidirectional());
        let slot = b.session_on_ports(HttpProxySession::new(), [80]);
        (b.build(), slot)
    };

    let mut events = Vec::new();
    for (i, path) in ["/a", "/b", "/c"].iter().enumerate() {
        let wire = format!("GET {path} HTTP/1.1\r\nHost: h\r\n\r\n");
        let pkt = packet(40002, 1000 + (i as u32 * 64), wire.as_bytes());
        driver.track_into(
            PacketView::new(&pkt, Timestamp::new(i as u32 + 1, 0)),
            &mut events,
        );
    }

    assert!(
        !events.iter().any(|e| matches!(
            e,
            Event::ParserClosed {
                reason: EndReason::ParseError,
                ..
            }
        )),
        "well-framed pipelined traffic must not be reported as a parse error"
    );
}

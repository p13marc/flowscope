//! `Http2Session` driven through the typed `Driver` (#196).
//!
//! The adapter's unit tests call the trait methods by hand. What they
//! cannot check is the part that only exists once a driver is
//! involved: that per-stream h2 events actually reach a slot, and
//! that a framing failure makes the driver drop the parser rather
//! than keep feeding one whose HPACK state is already meaningless.
//!
//! Note the signal is `Event::ParserClosed`, not `Event::Ended`: the
//! TCP flow is not flowscope's to close. An inline proxy owns the
//! socket and tears the connection down on this event.

#![cfg(all(
    feature = "http2",
    feature = "test-helpers",
    feature = "extractors",
    feature = "session",
    feature = "reassembler",
))]

use flowscope::detect::signatures::http2_preface;
use flowscope::driver::{Driver, Event};
use flowscope::extract::{FiveTuple, parse::test_frames::ipv4_tcp};
use flowscope::http2::{Http2Event, Http2Session, PREFACE};
use flowscope::{EndReason, PacketView, Timestamp};

/// PSH+ACK — an ordinary data packet.
const DATA_PKT: u8 = 0x18;

const HEADERS: u8 = 0x1;
const DATA: u8 = 0x0;
const SETTINGS: u8 = 0x4;
const END_STREAM: u8 = 0x1;
const END_HEADERS: u8 = 0x4;

fn packet(sport: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
    ipv4_tcp(
        [1; 6],
        [2; 6],
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        sport,
        8080,
        seq,
        0,
        DATA_PKT,
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
        8080,
        dport,
        seq,
        0,
        DATA_PKT,
        payload,
    )
}

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    let len = payload.len() as u32;
    v.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
    v.push(kind);
    v.push(flags);
    v.extend_from_slice(&stream.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// A literal field with an incremental-indexing prefix.
fn literal(name: &str, value: &str) -> Vec<u8> {
    let mut v = vec![0x40, name.len() as u8];
    v.extend_from_slice(name.as_bytes());
    v.push(value.len() as u8);
    v.extend_from_slice(value.as_bytes());
    v
}

fn driver() -> (
    Driver<FiveTuple>,
    flowscope::driver::SlotHandle<Http2Event, flowscope::extract::FiveTupleKey>,
) {
    let mut b = Driver::builder(FiveTuple::bidirectional());
    let slot = b.session_on_ports(Http2Session::new(), [8080]);
    (b.build(), slot)
}

#[test]
fn h2_stream_events_reach_the_slot_through_the_driver() {
    let (mut driver, mut slot) = driver();
    let mut events = Vec::new();

    let mut req_block = vec![0x82, 0x87]; // :method GET, :scheme https
    req_block.extend(literal(":authority", "api.example"));
    req_block.extend(literal(":path", "/v1/things"));
    let mut client = PREFACE.to_vec();
    client.extend(frame(SETTINGS, 0, 0, &[]));
    client.extend(frame(HEADERS, END_HEADERS | END_STREAM, 1, &req_block));
    driver.track_into(
        PacketView::new(&packet(40000, 1000, &client), Timestamp::new(1, 0)),
        &mut events,
    );

    let mut server = frame(SETTINGS, 0, 0, &[]);
    server.extend(frame(HEADERS, END_HEADERS, 1, &[0x88])); // :status 200
    server.extend(frame(DATA, END_STREAM, 1, b"pong"));
    driver.track_into(
        PacketView::new(&response_packet(40000, 5000, &server), Timestamp::new(2, 0)),
        &mut events,
    );

    let mut msgs = Vec::new();
    slot.drain(&mut msgs);

    // The routing key must arrive intact, through the slot rather
    // than by calling the parser directly.
    let authority = msgs.iter().find_map(|m| match &m.message {
        Http2Event::Head(h) => h.authority().map(str::to_owned),
        _ => None,
    });
    assert_eq!(authority.as_deref(), Some("api.example"));

    let status = msgs.iter().find_map(|m| match &m.message {
        Http2Event::Head(h) => h.status(),
        _ => None,
    });
    assert_eq!(status, Some(200));

    let body: Vec<u8> = msgs
        .iter()
        .filter_map(|m| match &m.message {
            Http2Event::Body { data, .. } => Some(data.to_vec()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .concat();
    assert_eq!(body, b"pong");

    assert!(
        msgs.iter()
            .any(|m| matches!(&m.message, Http2Event::End { stream_id: 1, .. })),
        "the stream must be reported complete, got {msgs:?}"
    );
}

#[test]
fn a_framing_violation_drops_the_h2_parser() {
    let (mut driver, _slot) = driver();
    let mut events = Vec::new();

    // A field block left open, then a DATA frame on the same stream.
    // RFC 9113 §6.10 forbids the interleave, and HPACK state cannot
    // be trusted afterwards.
    let mut wire = PREFACE.to_vec();
    wire.extend(frame(HEADERS, 0, 1, &[0x82]));
    wire.extend(frame(DATA, 0, 1, b"x"));
    driver.track_into(
        PacketView::new(&packet(40001, 1000, &wire), Timestamp::new(1, 0)),
        &mut events,
    );

    let closed = events.iter().find_map(|e| match e {
        Event::ParserClosed { reason, .. } => Some(*reason),
        _ => None,
    });
    assert_eq!(
        closed,
        Some(EndReason::ParseError),
        "a poisoned h2 parser must be dropped with a reason, got {events:?}"
    );
}

/// Issue #196's motivating case: the driver may pick a flow up
/// mid-connection, and the preface is long gone. A strict parser
/// would report that as a protocol violation when nothing is wrong.
#[test]
fn a_mid_stream_join_is_not_a_parse_error() {
    let (mut driver, mut slot) = driver();
    let mut events = Vec::new();

    let mut block = vec![0x82, 0x87];
    block.extend(literal(":authority", "late.example"));
    block.extend(literal(":path", "/joined"));
    // Straight into a HEADERS frame — no preface, no SETTINGS.
    driver.track_into(
        PacketView::new(
            &packet(40002, 1000, &frame(HEADERS, END_HEADERS, 9, &block)),
            Timestamp::new(1, 0),
        ),
        &mut events,
    );

    assert!(
        !events.iter().any(|e| matches!(
            e,
            Event::ParserClosed {
                reason: EndReason::ParseError,
                ..
            }
        )),
        "joining late is not a framing error, got {events:?}"
    );

    let mut msgs = Vec::new();
    slot.drain(&mut msgs);
    let head = msgs.iter().find_map(|m| match &m.message {
        Http2Event::Head(h) => Some(h),
        _ => None,
    });
    assert_eq!(
        head.and_then(|h| h.authority()),
        Some("late.example"),
        "and the stream must still route"
    );
}

#[test]
fn a_well_framed_h2_flow_is_not_torn_down() {
    let (mut driver, _slot) = driver();
    let mut events = Vec::new();

    let mut first = PREFACE.to_vec();
    first.extend(frame(SETTINGS, 0, 0, &[]));
    driver.track_into(
        PacketView::new(&packet(40003, 1000, &first), Timestamp::new(1, 0)),
        &mut events,
    );

    // Three sequential streams across three further packets.
    let mut seq = 1000 + first.len() as u32;
    for (i, path) in ["/a", "/b", "/c"].iter().enumerate() {
        let stream = (i as u32) * 2 + 1;
        let mut block = vec![0x82, 0x87];
        block.extend(literal(":authority", "h"));
        block.extend(literal(":path", path));
        let wire = frame(HEADERS, END_HEADERS | END_STREAM, stream, &block);
        driver.track_into(
            PacketView::new(&packet(40003, seq, &wire), Timestamp::new(i as u32 + 2, 0)),
            &mut events,
        );
        seq += wire.len() as u32;
    }

    assert!(
        !events.iter().any(|e| matches!(
            e,
            Event::ParserClosed {
                reason: EndReason::ParseError,
                ..
            }
        )),
        "well-framed multiplexed traffic must not be reported as a parse error, got {events:?}"
    );
}

/// Issue #201: h2 on a *heuristic* slot, with no port to route on.
///
/// This is what `Http2Session`'s preface tolerance was built for. The
/// probe consumes the packets that carry the preface, so by the time
/// the parser is pinned those bytes are already spent — a strict
/// parser would then see a bare HEADERS frame and refuse it as
/// `BadPreface`. #166 makes the driver replay probe frames into the
/// pinned parser, so in fact it sees them; the tolerance is the
/// belt-and-braces for when a segment was missed entirely.
#[test]
fn a_heuristic_slot_pins_h2_on_the_preface() {
    let (mut driver, mut slot) = {
        let mut b = Driver::builder(FiveTuple::bidirectional());
        // No port set: the signature decides.
        let slot = b.session_heuristic(Http2Session::new(), http2_preface);
        (b.build(), slot)
    };

    let mut events = Vec::new();
    let mut block = vec![0x82, 0x87];
    block.extend(literal(":authority", "probe.example"));
    block.extend(literal(":path", "/pinned"));

    // The preface arrives split across two packets, so the signature
    // has to say NeedMoreData before it can say Match.
    let mut wire = PREFACE.to_vec();
    wire.extend(frame(SETTINGS, 0, 0, &[]));
    wire.extend(frame(HEADERS, END_HEADERS | END_STREAM, 1, &block));
    let (first, rest) = wire.split_at(10);

    driver.track_into(
        PacketView::new(&packet(41000, 1000, first), Timestamp::new(1, 0)),
        &mut events,
    );
    driver.track_into(
        PacketView::new(
            &packet(41000, 1000 + first.len() as u32, rest),
            Timestamp::new(2, 0),
        ),
        &mut events,
    );

    let mut msgs = Vec::new();
    slot.drain(&mut msgs);
    let authority = msgs.iter().find_map(|m| match &m.message {
        Http2Event::Head(h) => h.authority(),
        _ => None,
    });
    assert_eq!(
        authority,
        Some("probe.example"),
        "the flow must pin to h2 and route, got {msgs:?}"
    );
    assert!(
        !events.iter().any(|e| matches!(
            e,
            Event::ParserClosed {
                reason: EndReason::ParseError,
                ..
            }
        )),
        "pinning on the preface must not then reject it"
    );
}

/// The other half: traffic that is definitively not h2 must not pin.
#[test]
fn a_heuristic_slot_leaves_non_h2_alone() {
    let (mut driver, mut slot) = {
        let mut b = Driver::builder(FiveTuple::bidirectional());
        let slot = b.session_heuristic(Http2Session::new(), http2_preface);
        (b.build(), slot)
    };

    let mut events = Vec::new();
    driver.track_into(
        PacketView::new(
            &packet(41001, 1000, b"GET /ordinary HTTP/1.1\r\nHost: h\r\n\r\n"),
            Timestamp::new(1, 0),
        ),
        &mut events,
    );

    let mut msgs = Vec::new();
    slot.drain(&mut msgs);
    assert!(
        msgs.is_empty(),
        "HTTP/1 must not reach the h2 slot: {msgs:?}"
    );
}

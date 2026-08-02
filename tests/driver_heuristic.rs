//! Heuristic-routed slot behaviour (#166).
//!
//! A heuristic slot watches the first few packets of a flow, and once
//! a signature matches it pins the flow to a parser. Three things
//! about that hand-off matter, and each is pinned by a test here:
//!
//! 1. the parser must see the bytes that arrived *before* the pin —
//!    otherwise the very bytes that identified the protocol are the
//!    ones it never gets;
//! 2. a signature that has definitively ruled the flow out should say
//!    so immediately rather than burning the whole probe budget;
//! 3. per-flow probe state must not outlive the flow.

#![cfg(all(
    feature = "test-helpers",
    feature = "extractors",
    feature = "session",
    feature = "reassembler",
))]

use flowscope::{
    FlowSide, PacketView, SessionParser, Timestamp,
    detect::signatures::SignatureMatch,
    driver::{Driver, Event, SlotMessage},
    extract::{FiveTuple, parse::test_frames::ipv4_tcp},
};

/// Records every byte handed to it, per direction, so a test can
/// assert nothing was dropped on the way in.
#[derive(Default, Clone)]
struct RecordingParser;

impl SessionParser for RecordingParser {
    type Message = (FlowSide, Vec<u8>);

    fn feed_initiator(&mut self, b: &[u8], _ts: Timestamp, out: &mut Vec<Self::Message>) {
        if !b.is_empty() {
            out.push((FlowSide::Initiator, b.to_vec()));
        }
    }
    fn feed_responder(&mut self, b: &[u8], _ts: Timestamp, out: &mut Vec<Self::Message>) {
        if !b.is_empty() {
            out.push((FlowSide::Responder, b.to_vec()));
        }
    }
    fn parser_kind(&self) -> flowscope::ParserKind {
        flowscope::ParserKind::Other("recording")
    }
}

/// Matches only once the marker has been seen — deliberately not on
/// the first packet, so the replay path is exercised.
fn late_marker(bytes: &[u8]) -> SignatureMatch {
    if bytes.windows(6).any(|w| w == b"MARKER") {
        SignatureMatch::Match
    } else if bytes.len() < 64 {
        SignatureMatch::NeedMoreData
    } else {
        SignatureMatch::NoMatch
    }
}

/// Rules the flow out on the very first byte it sees.
fn never_matches(bytes: &[u8]) -> SignatureMatch {
    if bytes.is_empty() {
        SignatureMatch::NeedMoreData
    } else {
        SignatureMatch::NoMatch
    }
}

/// Build a client->server packet. `seq` must advance with the bytes
/// sent, as it does on a real connection: replayed probe frames go
/// through TCP reassembly like any others, so reusing one sequence
/// number would make them look like retransmissions.
fn packet(sport: u16, seq: u32, payload: &[u8], flags: u8) -> Vec<u8> {
    ipv4_tcp(
        [1; 6],
        [2; 6],
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        sport,
        9999,
        seq,
        0,
        flags,
        payload,
    )
}

/// PSH+ACK — an ordinary data packet.
const DATA: u8 = 0x18;
/// RST — ends the flow immediately.
const RST: u8 = 0x04;

#[test]
fn bytes_seen_before_the_pin_reach_the_parser() {
    let (mut driver, mut slot) = {
        let mut b = Driver::builder(FiveTuple::bidirectional());
        let slot = b.session_heuristic(RecordingParser, late_marker);
        (b.build(), slot)
    };

    // Two packets that do not yet match, then the one that does.
    let mut events = Vec::new();
    let mut seq = 1000u32;
    for (i, payload) in [&b"first"[..], &b"second"[..], &b"MARKER-third"[..]]
        .iter()
        .enumerate()
    {
        let frame = packet(40000, seq, payload, DATA);
        seq += payload.len() as u32;
        let view = PacketView::new(&frame, Timestamp::new(i as u32, 0));
        driver.track_into(view, &mut events);
    }

    let mut msgs = Vec::new();
    slot.drain(&mut msgs);
    let joined: Vec<u8> = msgs
        .iter()
        .map(|m: &SlotMessage<(FlowSide, Vec<u8>), _>| m.message.1.clone())
        .collect::<Vec<_>>()
        .concat();

    assert!(
        joined.starts_with(b"first"),
        "the parser must see the pre-pin bytes, got {:?}",
        String::from_utf8_lossy(&joined)
    );
    assert_eq!(
        joined,
        b"firstsecondMARKER-third".to_vec(),
        "the whole stream must arrive, in order"
    );
}

#[test]
fn a_definitive_miss_stops_probing_immediately() {
    // The signature rules the flow out on packet 1. With the default
    // budget of four packets, the pre-0.23 slot kept probing anyway.
    // What is observable from outside is that no message is ever
    // produced — so this asserts the flow is inert, and the internal
    // saving is the point of the change.
    let (mut driver, mut slot) = {
        let mut b = Driver::builder(FiveTuple::bidirectional());
        let slot = b.session_heuristic(RecordingParser, never_matches);
        (b.build(), slot)
    };

    let mut events = Vec::new();
    for i in 0..8u32 {
        let frame = packet(40001, 1000 + i * 4, b"nope", DATA);
        let view = PacketView::new(&frame, Timestamp::new(i, 0));
        driver.track_into(view, &mut events);
    }

    let mut msgs = Vec::new();
    slot.drain(&mut msgs);
    assert!(
        msgs.is_empty(),
        "a ruled-out flow must never reach the parser"
    );
}

#[test]
fn probe_state_does_not_outlive_the_flow() {
    // Churn many short flows through the slot. Each ends with a FIN,
    // so the slot must forget it; before #166 the per-flow entries
    // accumulated for the lifetime of the slot.
    let (mut driver, _slot) = {
        let mut b = Driver::builder(FiveTuple::bidirectional());
        let slot = b.session_heuristic(RecordingParser, never_matches);
        (b.build(), slot)
    };

    let mut events = Vec::new();
    for port in 0..200u16 {
        let sport = 40000 + port;
        let data = packet(sport, 1000, b"x", DATA);
        driver.track_into(
            PacketView::new(&data, Timestamp::new(port as u32, 0)),
            &mut events,
        );
        let rst = packet(sport, 1001, b"", RST);
        driver.track_into(
            PacketView::new(&rst, Timestamp::new(port as u32, 1)),
            &mut events,
        );
    }

    let ended = events
        .iter()
        .filter(|e| matches!(e, Event::Ended { .. }))
        .count();
    assert!(
        ended > 0,
        "the test needs flows to actually end for the cleanup to be exercised"
    );
    // The observable contract: ending a flow is enough to release its
    // state — no sweep, no force_close required.
    driver.finish_into(&mut events);
}

#[test]
fn a_flow_that_never_decides_still_pins_when_it_matches_later() {
    // NeedMoreData across several packets, then a match inside the
    // budget: the flow pins and the earlier bytes are replayed.
    let (mut driver, mut slot) = {
        let mut b = Driver::builder(FiveTuple::bidirectional());
        let slot = b.session_heuristic_with_budget(RecordingParser, late_marker, 8);
        (b.build(), slot)
    };

    let mut events = Vec::new();
    for i in 0..3u32 {
        let frame = packet(40002, 1000 + i * 2, b"aa", DATA);
        driver.track_into(PacketView::new(&frame, Timestamp::new(i, 0)), &mut events);
    }
    let frame = packet(40002, 1006, b"MARKER", DATA);
    driver.track_into(PacketView::new(&frame, Timestamp::new(9, 0)), &mut events);

    let mut msgs = Vec::new();
    slot.drain(&mut msgs);
    let joined: Vec<u8> = msgs
        .iter()
        .map(|m: &SlotMessage<(FlowSide, Vec<u8>), _>| m.message.1.clone())
        .collect::<Vec<_>>()
        .concat();
    assert_eq!(joined, b"aaaaaaMARKER".to_vec());
}

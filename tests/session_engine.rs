//! The shared session engine (0.25): one flow table feeding every
//! parser, parser closes that never resurrect, explicit gaps.
//!
//! Scenarios F1/F2/F3 and X1 come from the des-capture report
//! against 0.24.1 (flowscope `Driver` slots each ran a private flow
//! table), the others pin the new guarantees.

#![cfg(all(
    feature = "extractors",
    feature = "reassembler",
    feature = "session",
    feature = "test-helpers"
))]

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use flowscope::driver::{Driver, Event};
use flowscope::extract::parse::test_frames::{ipv4_tcp, ipv4_udp};
use flowscope::extract::{FiveTuple, FiveTupleKey};
use flowscope::session::{SessionDriver, SessionEvent};
use flowscope::{
    AnomalyKind, DatagramParser, Dedup, EndReason, EventMask, FlowSide, FlowTrackerConfig,
    GapResponse, Orientation, OverflowPolicy, PacketView, SessionParser, Timestamp,
};

const SYN: u8 = 0x02;
const ACK: u8 = 0x10;
const PSH: u8 = 0x08;
const FIN: u8 = 0x01;

fn ts_ms(ms: u64) -> Timestamp {
    let d = Duration::from_millis(ms);
    Timestamp::new(d.as_secs() as u32, d.subsec_nanos())
}

/// Client 10.0.0.1:40000 → server 10.0.0.2:9000. `segments` are
/// (seq offset from ISN+1, payload) sent by the client after the
/// handshake; then a FIN exchange. Frames are 1 ms apart from t=1 s.
fn flow(segments: &[(u32, Vec<u8>)]) -> Vec<(Timestamp, Vec<u8>)> {
    let (c, s) = ([10, 0, 0, 1], [10, 0, 0, 2]);
    let (cp, sp) = (40_000, 9_000);
    let (cisn, sisn) = (1000u32, 5000u32);
    let m = [0u8; 6];
    let mut v = vec![
        ipv4_tcp(m, m, c, s, cp, sp, cisn, 0, SYN, &[]),
        ipv4_tcp(m, m, s, c, sp, cp, sisn, cisn + 1, SYN | ACK, &[]),
        ipv4_tcp(m, m, c, s, cp, sp, cisn + 1, sisn + 1, ACK, &[]),
    ];
    let mut end = cisn + 1;
    for (off, payload) in segments {
        let seq = cisn + 1 + off;
        v.push(ipv4_tcp(
            m,
            m,
            c,
            s,
            cp,
            sp,
            seq,
            sisn + 1,
            PSH | ACK,
            payload,
        ));
        end = end.max(seq + payload.len() as u32);
    }
    v.push(ipv4_tcp(m, m, c, s, cp, sp, end, sisn + 1, FIN | ACK, &[]));
    v.push(ipv4_tcp(
        m,
        m,
        s,
        c,
        sp,
        cp,
        sisn + 1,
        end + 1,
        FIN | ACK,
        &[],
    ));
    v.push(ipv4_tcp(m, m, c, s, cp, sp, end + 1, sisn + 2, ACK, &[]));
    v.into_iter()
        .enumerate()
        .map(|(i, f)| (ts_ms(1_000 + i as u64), f))
        .collect()
}

/// Poisons after its first feed; counts feeds across clones.
#[derive(Clone, Default)]
struct PoisonAfterFirstFeed {
    feeds: Arc<AtomicUsize>,
    poisoned: bool,
}

impl SessionParser for PoisonAfterFirstFeed {
    type Message = usize;
    fn feed_initiator(&mut self, bytes: &[u8], _: Timestamp, out: &mut Vec<usize>) {
        self.feeds.fetch_add(1, Ordering::SeqCst);
        self.poisoned = true;
        out.push(bytes.len());
    }
    fn feed_responder(&mut self, bytes: &[u8], ts: Timestamp, out: &mut Vec<usize>) {
        self.feed_initiator(bytes, ts, out);
    }
    fn is_poisoned(&self) -> bool {
        self.poisoned
    }
    fn poison_reason(&self) -> Option<&str> {
        self.poisoned.then_some("bad magic")
    }
}

/// Collects every byte fed, per side, and records gaps.
#[derive(Clone, Default)]
struct Collect {
    continue_on_gap: bool,
}

#[derive(Debug, Clone, PartialEq)]
enum Piece {
    Data(FlowSide, Vec<u8>),
    Gap(FlowSide, u64),
    Fin(FlowSide),
}

impl SessionParser for Collect {
    type Message = Piece;
    fn feed_initiator(&mut self, b: &[u8], _: Timestamp, out: &mut Vec<Piece>) {
        out.push(Piece::Data(FlowSide::Initiator, b.to_vec()));
    }
    fn feed_responder(&mut self, b: &[u8], _: Timestamp, out: &mut Vec<Piece>) {
        out.push(Piece::Data(FlowSide::Responder, b.to_vec()));
    }
    fn fin_initiator(&mut self, out: &mut Vec<Piece>) {
        out.push(Piece::Fin(FlowSide::Initiator));
    }
    fn on_gap(
        &mut self,
        side: FlowSide,
        n: u64,
        _: Timestamp,
        out: &mut Vec<Piece>,
    ) -> GapResponse {
        out.push(Piece::Gap(side, n));
        if self.continue_on_gap {
            GapResponse::Continue
        } else {
            GapResponse::Stop
        }
    }
}

fn session_events<P>(
    driver: &mut SessionDriver<FiveTuple, P>,
    frames: &[(Timestamp, Vec<u8>)],
) -> Vec<SessionEvent<FiveTupleKey, P::Message>>
where
    P: SessionParser + Default + Clone,
{
    let mut out = Vec::new();
    for (t, f) in frames {
        driver.track_into(PacketView::new(f, *t), &mut out);
    }
    driver.finish_into(&mut out);
    out
}

// ── F2 ─────────────────────────────────────────────────────────

#[test]
fn f2_poisoned_slot_parser_is_closed_once_and_never_recreated() {
    let frames = flow(&[
        (0, vec![b'a'; 10]),
        (10, vec![b'b'; 10]),
        (20, vec![b'c'; 10]),
    ]);
    let mut b = Driver::builder(FiveTuple::bidirectional());
    b.emit_anomalies(true);
    let parser = PoisonAfterFirstFeed::default();
    let feeds = parser.feeds.clone();
    let mut slot = b.session_broadcast(parser);
    let mut driver = b.build();
    let mut events = Vec::new();
    for (t, f) in &frames {
        driver.track_into(PacketView::new(f, *t), &mut events);
    }
    driver.finish_into(&mut events);
    let mut msgs = Vec::new();
    slot.drain(&mut msgs);

    assert_eq!(
        feeds.load(Ordering::SeqCst),
        1,
        "fed once, then never again"
    );
    assert_eq!(msgs.len(), 1);
    let closed: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            Event::ParserClosed { reason, detail, .. } => Some((*reason, detail.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(
        closed,
        vec![(EndReason::ParseError, Some("bad magic".to_string()))],
        "exactly one close, carrying the poison reason"
    );
    let parse_errors = events
        .iter()
        .filter(|e| {
            matches!(
                e,
                Event::FlowAnomaly {
                    kind: AnomalyKind::SessionParseError { .. },
                    ..
                }
            )
        })
        .count();
    assert_eq!(
        parse_errors, 1,
        "slot parser poison is surfaced as an anomaly"
    );
    let ended: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            Event::Ended { reason, .. } => Some(*reason),
            _ => None,
        })
        .collect();
    assert_eq!(ended, vec![EndReason::Fin]);
}

// ── F1 ─────────────────────────────────────────────────────────

/// Counts parser instances (clones).
#[derive(Default)]
struct CountInstances {
    instances: Arc<AtomicUsize>,
}

impl Clone for CountInstances {
    fn clone(&self) -> Self {
        self.instances.fetch_add(1, Ordering::SeqCst);
        Self {
            instances: self.instances.clone(),
        }
    }
}

impl SessionParser for CountInstances {
    type Message = ();
    fn feed_initiator(&mut self, _: &[u8], _: Timestamp, _: &mut Vec<()>) {}
    fn feed_responder(&mut self, _: &[u8], _: Timestamp, _: &mut Vec<()>) {}
}

#[test]
fn f1_idle_timeout_fn_governs_parser_lifetime_too() {
    // Two data segments 10 s apart; idle_timeout_fn says 1 s.
    let mut frames = flow(&[(0, vec![b'a'; 10]), (10, vec![b'b'; 10])]);
    for f in frames.iter_mut().skip(4) {
        f.0 = ts_ms(f.0.to_duration().as_millis() as u64 + 10_000);
    }
    let mut b = Driver::builder(FiveTuple::bidirectional());
    b.idle_timeout_fn(|_, _| Some(Duration::from_secs(1)));
    let parser = CountInstances::default();
    let instances = parser.instances.clone();
    let _slot = b.session_broadcast(parser);
    instances.store(0, Ordering::SeqCst);
    let mut driver = b.build();
    let mut events = Vec::new();
    for (t, f) in &frames {
        driver.sweep_into(*t, &mut events);
        driver.track_into(PacketView::new(f, *t), &mut events);
    }
    driver.finish_into(&mut events);

    let ended: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            Event::Ended { reason, .. } => Some(*reason),
            _ => None,
        })
        .collect();
    let closed: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            Event::ParserClosed { reason, .. } => Some(*reason),
            _ => None,
        })
        .collect();
    assert_eq!(ended.len(), 2, "the gap splits the flow in two");
    assert_eq!(instances.load(Ordering::SeqCst), 2, "one parser per flow");
    assert_eq!(closed, ended, "parser closes follow the lifecycle exactly");
}

#[derive(Clone, Default)]
struct CountDatagrams;

impl DatagramParser for CountDatagrams {
    type Message = usize;
    fn parse(&mut self, p: &[u8], _: FlowSide, _: Timestamp, out: &mut Vec<usize>) {
        out.push(p.len());
    }
}

#[test]
fn f1_dedup_applies_to_parsers() {
    let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 5000, 53, b"query");
    let mut b = Driver::builder(FiveTuple::bidirectional());
    b.dedup(Dedup::loopback());
    let mut slot = b.datagram_broadcast(CountDatagrams);
    let mut driver = b.build();
    let mut events = Vec::new();
    // The same frame twice within the dedup window (loopback shape).
    driver.track_into(PacketView::new(&f, ts_ms(1_000)), &mut events);
    driver.track_into(PacketView::new(&f, ts_ms(1_000)), &mut events);
    let mut msgs = Vec::new();
    slot.drain(&mut msgs);
    assert_eq!(msgs.len(), 1, "the duplicate never reaches the parser");
}

// ── X1: builder order ──────────────────────────────────────────

#[derive(Clone, Default)]
struct CountBytes {
    bytes: Arc<AtomicUsize>,
}

impl SessionParser for CountBytes {
    type Message = ();
    fn feed_initiator(&mut self, b: &[u8], _: Timestamp, _: &mut Vec<()>) {
        self.bytes.fetch_add(b.len(), Ordering::SeqCst);
    }
    fn feed_responder(&mut self, b: &[u8], ts: Timestamp, out: &mut Vec<()>) {
        self.feed_initiator(b, ts, out);
    }
}

#[test]
fn x1_builder_config_is_order_independent() {
    for config_first in [true, false] {
        let frames = flow(&[(0, vec![b'x'; 500]), (500, vec![b'y'; 10])]);
        let mut cfg = FlowTrackerConfig::default();
        cfg.max_reassembler_buffer = Some(100);
        cfg.overflow_policy = OverflowPolicy::DropFlow;
        let mut b = Driver::builder(FiveTuple::bidirectional());
        let parser = CountBytes::default();
        let bytes = parser.bytes.clone();
        if config_first {
            b.config(cfg.clone());
        }
        let _slot = b.session_broadcast(parser);
        if !config_first {
            b.config(cfg);
        }
        let mut driver = b.build();
        let mut events = Vec::new();
        for (t, f) in &frames {
            driver.track_into(PacketView::new(f, *t), &mut events);
        }
        driver.finish_into(&mut events);
        let closed: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                Event::ParserClosed { reason, .. } => Some(*reason),
                _ => None,
            })
            .collect();
        assert_eq!(
            bytes.load(Ordering::SeqCst),
            0,
            "config_first={config_first}"
        );
        assert_eq!(
            closed,
            vec![EndReason::BufferOverflow],
            "config_first={config_first}"
        );
        let ended: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                Event::Ended { stats, .. } => Some(stats.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(
            ended.len(),
            1,
            "the overflow never ends or re-creates the flow"
        );
        assert_eq!(
            ended[0].reassembly_stop_initiator,
            Some(flowscope::ReassemblyStop::Overflow),
            "the stop survives the stream being discarded afterwards"
        );
    }
}

// ── F3 ─────────────────────────────────────────────────────────

#[test]
fn f3_slot_messages_carry_orientation_and_reassembly_reaches_lifecycle() {
    // In-order, a hole (10..20 never sent), then data after it.
    let frames = flow(&[
        (0, vec![b'a'; 10]),
        (20, vec![b'c'; 10]),
        (0, vec![b'a'; 10]),
    ]);
    let mut b = Driver::builder(FiveTuple::bidirectional());
    b.emit_anomalies(true);
    let mut slot = b.session_broadcast(Collect {
        continue_on_gap: true,
    });
    let mut driver = b.build();
    let mut events = Vec::new();
    for (t, f) in &frames {
        driver.track_into(PacketView::new(f, *t), &mut events);
    }
    driver.finish_into(&mut events);
    let mut msgs = Vec::new();
    slot.drain(&mut msgs);

    let started_orientation = events
        .iter()
        .find_map(|e| match e {
            Event::Started { orientation, .. } => Some(*orientation),
            _ => None,
        })
        .unwrap();
    assert!(msgs.iter().all(|m| m.orientation == started_orientation));

    let kinds: Vec<&'static str> = events
        .iter()
        .filter_map(|e| match e {
            Event::FlowAnomaly { kind, .. } => Some(kind.short_kind()),
            _ => None,
        })
        .collect();
    assert!(kinds.contains(&"retransmit"), "{kinds:?}");
    let ended_stats = events
        .iter()
        .find_map(|e| match e {
            Event::Ended { stats, .. } => Some(stats.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(ended_stats.retransmits_initiator, 1);
    assert!(ended_stats.reassembler_high_watermark_initiator > 0);
    assert_eq!(ended_stats.reassembly_gap_bytes_initiator, 10);
}

// ── Gaps ───────────────────────────────────────────────────────

#[test]
fn a_gap_stops_the_parser_by_default_and_is_reported() {
    let frames = flow(&[(0, b"hello".to_vec()), (10, b"world".to_vec())]);
    let mut d = SessionDriver::new(FiveTuple::bidirectional(), Collect::default())
        .with_emit_anomalies(true);
    let events = session_events(&mut d, &frames);
    let pieces: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            SessionEvent::Application { message, .. } => Some(message.clone()),
            _ => None,
        })
        .collect();
    // At flow end the hole is given up on: the gap is reported and
    // the default response stops the parser — "world" is never fed.
    assert_eq!(
        pieces,
        vec![
            Piece::Data(FlowSide::Initiator, b"hello".to_vec()),
            Piece::Gap(FlowSide::Initiator, 5),
        ]
    );
    let closed: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            SessionEvent::ParserClosed { reason, detail, .. } => Some((*reason, detail.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(closed.len(), 1);
    assert_eq!(closed[0].0, EndReason::StreamGap);
    assert!(closed[0].1.as_deref().unwrap().contains("5 bytes"));
    assert!(events.iter().any(|e| matches!(
        e,
        SessionEvent::FlowAnomaly {
            kind: AnomalyKind::StreamGap { bytes: 5, .. },
            ..
        }
    )));
    assert!(matches!(
        events.last(),
        Some(SessionEvent::Closed {
            reason: EndReason::Fin,
            ..
        })
    ));
}

#[test]
fn a_parser_that_accepts_gaps_keeps_going() {
    let frames = flow(&[(0, b"hello".to_vec()), (10, b"world".to_vec())]);
    let mut cfg = FlowTrackerConfig::default();
    cfg.reassembly_ooo_buffer = 0; // never wait for holes
    let mut d = SessionDriver::with_config(
        FiveTuple::bidirectional(),
        flowscope::TemplateFactory(Collect {
            continue_on_gap: true,
        }),
        cfg,
    );
    let mut out = Vec::new();
    for (t, f) in &frames {
        d.track_into(PacketView::new(f, *t), &mut out);
    }
    d.finish_into(&mut out);
    let pieces: Vec<_> = out
        .iter()
        .filter_map(|e| match e {
            SessionEvent::Application { message, .. } => Some(message.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(
        pieces,
        vec![
            Piece::Data(FlowSide::Initiator, b"hello".to_vec()),
            Piece::Gap(FlowSide::Initiator, 5),
            Piece::Data(FlowSide::Initiator, b"world".to_vec()),
            Piece::Fin(FlowSide::Initiator),
        ]
    );
}

#[test]
fn reordering_is_healed_without_a_gap() {
    // The segment at 10 arrives after the one at 20.
    let frames = flow(&[
        (0, b"0123456789".to_vec()),
        (20, b"KLMNOPQRST".to_vec()),
        (10, b"ABCDEFGHIJ".to_vec()),
    ]);
    let mut d = SessionDriver::new(FiveTuple::bidirectional(), Collect::default());
    let events = session_events(&mut d, &frames);
    let data: Vec<u8> = events
        .iter()
        .filter_map(|e| match e {
            SessionEvent::Application {
                message: Piece::Data(_, d),
                ..
            } => Some(d.clone()),
            _ => None,
        })
        .flatten()
        .collect();
    assert_eq!(data, b"0123456789ABCDEFGHIJKLMNOPQRST");
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, SessionEvent::ParserClosed { .. }))
    );
}

// ── Ordering, orientation, load shedding ───────────────────────

#[test]
fn session_driver_orders_messages_before_close() {
    let frames = flow(&[(0, b"ping".to_vec())]);
    let mut d = SessionDriver::new(FiveTuple::bidirectional(), Collect::default());
    let events = session_events(&mut d, &frames);
    let shape: Vec<&'static str> = events
        .iter()
        .map(|e| match e {
            SessionEvent::Started { .. } => "started",
            SessionEvent::Application {
                message: Piece::Fin(_),
                ..
            } => "fin",
            SessionEvent::Application { .. } => "data",
            SessionEvent::Closed { .. } => "closed",
            _ => "other",
        })
        .collect();
    assert_eq!(shape, vec!["started", "data", "fin", "closed"]);
    let SessionEvent::Application { orientation, .. } = &events[1] else {
        unreachable!()
    };
    assert_eq!(*orientation, Orientation::Forward);
}

#[test]
fn shedding_packet_events_does_not_stop_parsing() {
    let frames = flow(&[(0, b"abc".to_vec()), (3, b"def".to_vec())]);
    let cfg = FlowTrackerConfig::default().with_event_filter(EventMask::PACKET);
    let mut d = SessionDriver::with_config(FiveTuple::bidirectional(), Collect::default(), cfg);
    let events = session_events(&mut d, &frames);
    let data = events
        .iter()
        .filter(|e| {
            matches!(
                e,
                SessionEvent::Application {
                    message: Piece::Data(..),
                    ..
                }
            )
        })
        .count();
    assert_eq!(data, 2);
}

#[test]
fn done_parser_is_closed_and_flow_ends_normally() {
    #[derive(Clone, Default)]
    struct OneShot {
        done: bool,
    }
    impl SessionParser for OneShot {
        type Message = ();
        fn feed_initiator(&mut self, _: &[u8], _: Timestamp, out: &mut Vec<()>) {
            out.push(());
            self.done = true;
        }
        fn feed_responder(&mut self, _: &[u8], _: Timestamp, _: &mut Vec<()>) {}
        fn is_done(&self) -> bool {
            self.done
        }
    }
    let frames = flow(&[(0, b"a".to_vec()), (1, b"b".to_vec())]);
    let mut d = SessionDriver::new(FiveTuple::bidirectional(), OneShot::default());
    let events = session_events(&mut d, &frames);
    let messages = events
        .iter()
        .filter(|e| matches!(e, SessionEvent::Application { .. }))
        .count();
    assert_eq!(messages, 1);
    let closes: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            SessionEvent::ParserClosed { reason, .. } => Some(*reason),
            SessionEvent::Closed { reason, .. } => Some(*reason),
            _ => None,
        })
        .collect();
    assert_eq!(closes, vec![EndReason::ParserDone, EndReason::Fin]);
}

#[test]
fn stats_on_close_include_reassembly_counters() {
    // Exact retransmit of the first segment.
    let frames = flow(&[(0, b"abc".to_vec()), (0, b"abc".to_vec())]);
    let mut d = SessionDriver::new(FiveTuple::bidirectional(), Collect::default());
    let events = session_events(&mut d, &frames);
    let Some(SessionEvent::Closed { stats, .. }) = events.last() else {
        panic!("last event is Closed");
    };
    assert_eq!(stats.retransmits_initiator, 1);
    assert_eq!(stats.reassembler_high_watermark_initiator, 3);
}

#[test]
fn a_flow_nobody_parses_any_more_is_no_longer_reassembled() {
    // The parser poisons on the first segment; the rest of the flow
    // (including a hole that would otherwise be buffered and later
    // reported as a gap) must cost nothing.
    let frames = flow(&[
        (0, vec![b'a'; 10]),
        (20, vec![b'c'; 10]),
        (30, vec![b'd'; 10]),
    ]);
    let mut d = SessionDriver::new(FiveTuple::bidirectional(), PoisonAfterFirstFeed::default());
    let events = session_events(&mut d, &frames);
    let Some(SessionEvent::Closed { stats, .. }) = events.last() else {
        panic!("last event is Closed");
    };
    assert_eq!(
        stats.reassembly_gap_bytes_initiator, 0,
        "nothing after the close was buffered"
    );
    assert_eq!(
        stats.reassembly_stop_initiator, None,
        "discarding is not a reassembly stop"
    );
    assert_eq!(stats.reassembler_high_watermark_initiator, 10);
}

#[test]
fn heuristic_rejection_stops_reassembly_of_the_flow() {
    use flowscope::detect::signatures::SignatureMatch;
    fn never(_: &[u8]) -> SignatureMatch {
        SignatureMatch::NoMatch
    }
    let frames = flow(&[(0, vec![b'a'; 10]), (20, vec![b'c'; 10])]);
    let mut b = Driver::builder(FiveTuple::bidirectional());
    let _slot = b.session_heuristic(Collect::default(), never);
    let mut driver = b.build();
    let mut events = Vec::new();
    for (t, f) in &frames {
        driver.track_into(PacketView::new(f, *t), &mut events);
    }
    driver.finish_into(&mut events);
    let stats = events
        .iter()
        .find_map(|e| match e {
            Event::Ended { stats, .. } => Some(stats.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(stats.reassembly_gap_bytes_initiator, 0);
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, Event::ParserClosed { .. }))
    );
}

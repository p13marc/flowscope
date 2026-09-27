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
const MAC: [u8; 6] = [0; 6];

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
    let d = driver.dedup().expect("configured through the builder");
    assert_eq!((d.seen(), d.dropped()), (2, 1));
}

/// The session drivers hand their dedup back too (#203).
#[test]
fn session_and_datagram_drivers_expose_dedup_counts() {
    let frames = flow(&[]);
    let mut d = SessionDriver::new(FiveTuple::bidirectional(), Collect::default())
        .with_dedup(Dedup::loopback());
    assert_eq!(d.dedup().map(Dedup::seen), Some(0));
    let mut out = Vec::new();
    for (t, f) in &frames {
        d.track_into(PacketView::new(f, *t), &mut out);
        d.track_into(PacketView::new(f, *t), &mut out);
    }
    let dd = d.dedup().expect("configured");
    assert_eq!(
        (dd.seen(), dd.dropped()),
        (2 * frames.len() as u64, frames.len() as u64)
    );
    d.set_dedup(None);
    assert!(d.dedup().is_none());

    let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 5000, 53, b"query");
    let mut d = flowscope::session::DatagramDriver::new(FiveTuple::bidirectional(), CountDatagrams)
        .with_dedup(Dedup::loopback());
    let mut out = Vec::new();
    d.track_into(PacketView::new(&f, ts_ms(1)), &mut out);
    d.track_into(PacketView::new(&f, ts_ms(1)), &mut out);
    let dd = d.dedup().expect("configured");
    assert_eq!((dd.seen(), dd.dropped()), (2, 1));
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
        let stopped: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                Event::ParserSideStopped { side, reason, .. } => Some((*side, *reason)),
                _ => None,
            })
            .collect();
        assert_eq!(
            bytes.load(Ordering::SeqCst),
            0,
            "config_first={config_first}"
        );
        // The overflow stops the side that overflowed; the parser
        // keeps the other side.
        assert_eq!(
            stopped,
            vec![(FlowSide::Initiator, EndReason::BufferOverflow)],
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

/// Reports `is_done()` after its first feed.
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

#[test]
fn done_parser_is_closed_and_flow_ends_normally() {
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

/// The typed `Driver` closes every slot's parser at the flow's end
/// (transport reason, right before `Ended`); an early close carries a
/// parser reason. `EndReason::is_transport` / `is_parser` are the
/// exact test for which one it was. #202.
#[test]
fn typed_driver_flow_end_close_is_transport_early_close_is_parser() {
    let frames = flow(&[(0, b"a".to_vec()), (1, b"b".to_vec())]);
    let mut b = Driver::builder(FiveTuple::bidirectional());
    let one_shot = b.session_broadcast(OneShot::default());
    let collect = b.session_broadcast(Collect::default());
    let mut driver = b.build();
    let mut events = Vec::new();
    for (t, f) in &frames {
        driver.track_into(PacketView::new(f, *t), &mut events);
    }
    driver.finish_into(&mut events);

    let closes: Vec<(usize, flowscope::SlotId, EndReason)> = events
        .iter()
        .enumerate()
        .filter_map(|(i, e)| match e {
            Event::ParserClosed { slot, reason, .. } => Some((i, *slot, *reason)),
            _ => None,
        })
        .collect();
    let (ended_idx, ended_reason) = events
        .iter()
        .enumerate()
        .find_map(|(i, e)| match e {
            Event::Ended { reason, .. } => Some((i, *reason)),
            _ => None,
        })
        .expect("flow ends");
    assert_eq!(ended_reason, EndReason::Fin);
    assert!(ended_reason.is_transport());

    assert_eq!(closes.len(), 2, "one close per slot: {closes:?}");
    let (early_idx, _, early) = closes
        .iter()
        .find(|(_, s, _)| *s == one_shot.slot_id())
        .copied()
        .expect("OneShot slot closed");
    assert_eq!(early, EndReason::ParserDone);
    assert!(early.is_parser() && !early.is_transport());
    let (late_idx, _, late) = closes
        .iter()
        .find(|(_, s, _)| *s == collect.slot_id())
        .copied()
        .expect("Collect slot closed");
    assert_eq!(
        late,
        EndReason::Fin,
        "flow-end close carries the transport reason"
    );
    assert!(late.is_transport() && !late.is_parser());
    assert!(
        early_idx < ended_idx && late_idx < ended_idx,
        "closes precede Ended"
    );
}

/// The session drivers report a parser still open at flow end through
/// `Closed` alone (no `ParserClosed`); early closes are pinned by
/// `done_parser_is_closed_and_flow_ends_normally` and side stops by
/// `responder_keeps_parsing_and_fins_after_an_initiator_gap`. #202.
#[test]
fn session_driver_reports_no_flow_end_parser_closed() {
    let frames = flow(&[(0, b"ping".to_vec())]);
    let mut d = SessionDriver::new(FiveTuple::bidirectional(), Collect::default());
    let events = session_events(&mut d, &frames);
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, SessionEvent::ParserClosed { .. })),
        "{events:?}"
    );
    let closed = events
        .iter()
        .find_map(|e| match e {
            SessionEvent::Closed { reason, .. } => Some(*reason),
            _ => None,
        })
        .expect("Closed");
    assert!(closed.is_transport() && !closed.is_parser());
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

/// Issue #196: a retransmitted FIN from the side that closed first
/// must not end the flow before the other side closes.
#[test]
fn retransmitted_fin_does_not_end_the_flow_early() {
    use flowscope::{EndReason, FlowEvent, FlowTracker, extract::FiveTuple};
    let mut t: FlowTracker<FiveTuple> = FlowTracker::new(FiveTuple::bidirectional());
    let c = [10, 0, 0, 1];
    let s = [10, 0, 0, 2];
    let frames = [
        ipv4_tcp(MAC, MAC, c, s, 1234, 80, 100, 0, 0x02, b""),
        ipv4_tcp(MAC, MAC, s, c, 80, 1234, 500, 101, 0x12, b""),
        ipv4_tcp(MAC, MAC, c, s, 1234, 80, 101, 501, 0x10, b""),
        // Initiator FIN, then the same FIN again, then an ACK.
        ipv4_tcp(MAC, MAC, c, s, 1234, 80, 101, 501, 0x11, b""),
        ipv4_tcp(MAC, MAC, c, s, 1234, 80, 101, 501, 0x11, b""),
        ipv4_tcp(MAC, MAC, s, c, 80, 1234, 501, 102, 0x10, b""),
    ];
    let mut ended = Vec::new();
    for f in &frames {
        for e in t.track(PacketView::new(f, Timestamp::new(1, 0))) {
            if let FlowEvent::Ended { reason, .. } = e {
                ended.push(reason);
            }
        }
    }
    assert!(ended.is_empty(), "flow must stay open: {ended:?}");
    // The responder's FIN and the last ACK close it.
    let fin = ipv4_tcp(MAC, MAC, s, c, 80, 1234, 501, 102, 0x11, b"");
    let ack = ipv4_tcp(MAC, MAC, c, s, 1234, 80, 102, 502, 0x10, b"");
    let _ = t.track(PacketView::new(&fin, Timestamp::new(1, 0)));
    let evs = t.track(PacketView::new(&ack, Timestamp::new(1, 0)));
    let stats = evs
        .iter()
        .find_map(|e| match e {
            FlowEvent::Ended {
                reason: EndReason::Fin,
                stats,
                ..
            } => Some(stats.clone()),
            _ => None,
        })
        .expect("closed by FIN");
    assert!(stats.fin_initiator && stats.fin_responder);
}

// ── #181: a gap stops one side, not the parser ───────────────────

/// Server 10.0.0.2:9000 answers each client segment; the client's
/// segment `lose` is never captured. Each side's `fin_*` is recorded.
fn request_response(lose: usize) -> Vec<(Timestamp, Vec<u8>)> {
    let (c, s) = ([10, 0, 0, 1], [10, 0, 0, 2]);
    let (cp, sp) = (40_000u16, 9_000u16);
    let (mut cseq, mut sseq) = (1000u32, 5000u32);
    let mut v = vec![
        ipv4_tcp(MAC, MAC, c, s, cp, sp, cseq, 0, SYN, &[]),
        ipv4_tcp(MAC, MAC, s, c, sp, cp, sseq, cseq + 1, SYN | ACK, &[]),
    ];
    cseq += 1;
    sseq += 1;
    v.push(ipv4_tcp(MAC, MAC, c, s, cp, sp, cseq, sseq, ACK, &[]));
    for i in 0..4 {
        let req = format!("req{i}\n");
        if i != lose {
            v.push(ipv4_tcp(
                MAC,
                MAC,
                c,
                s,
                cp,
                sp,
                cseq,
                sseq,
                PSH | ACK,
                req.as_bytes(),
            ));
        }
        cseq += req.len() as u32;
        let resp = format!("resp{i}\n");
        v.push(ipv4_tcp(
            MAC,
            MAC,
            s,
            c,
            sp,
            cp,
            sseq,
            cseq,
            PSH | ACK,
            resp.as_bytes(),
        ));
        sseq += resp.len() as u32;
    }
    v.push(ipv4_tcp(MAC, MAC, c, s, cp, sp, cseq, sseq, FIN | ACK, &[]));
    v.push(ipv4_tcp(
        MAC,
        MAC,
        s,
        c,
        sp,
        cp,
        sseq,
        cseq + 1,
        FIN | ACK,
        &[],
    ));
    v.push(ipv4_tcp(
        MAC,
        MAC,
        c,
        s,
        cp,
        sp,
        cseq + 1,
        sseq + 1,
        ACK,
        &[],
    ));
    v.into_iter()
        .enumerate()
        .map(|(i, f)| (ts_ms(1_000 + i as u64), f))
        .collect()
}

/// Line parser with the default gap response.
#[derive(Clone, Default)]
struct Lines {
    buf: [Vec<u8>; 2],
}

#[derive(Debug, Clone, PartialEq)]
enum Line {
    Text(FlowSide, String),
    Fin(FlowSide),
}

impl Lines {
    fn push(&mut self, side: FlowSide, b: &[u8], out: &mut Vec<Line>) {
        let i = usize::from(side == FlowSide::Responder);
        self.buf[i].extend_from_slice(b);
        while let Some(p) = self.buf[i].iter().position(|&c| c == b'\n') {
            let line: Vec<u8> = self.buf[i].drain(..=p).collect();
            out.push(Line::Text(side, String::from_utf8_lossy(&line[..p]).into()));
        }
    }
}

impl SessionParser for Lines {
    type Message = Line;
    fn feed_initiator(&mut self, b: &[u8], _: Timestamp, out: &mut Vec<Line>) {
        self.push(FlowSide::Initiator, b, out);
    }
    fn feed_responder(&mut self, b: &[u8], _: Timestamp, out: &mut Vec<Line>) {
        self.push(FlowSide::Responder, b, out);
    }
    fn fin_initiator(&mut self, out: &mut Vec<Line>) {
        out.push(Line::Fin(FlowSide::Initiator));
    }
    fn fin_responder(&mut self, out: &mut Vec<Line>) {
        out.push(Line::Fin(FlowSide::Responder));
    }
}

#[test]
fn responder_keeps_parsing_and_fins_after_an_initiator_gap() {
    let mut d = SessionDriver::new(FiveTuple::bidirectional(), Lines::default());
    let events = session_events(&mut d, &request_response(1));
    let lines: Vec<Line> = events
        .iter()
        .filter_map(|e| match e {
            SessionEvent::Application { message, .. } => Some(message.clone()),
            _ => None,
        })
        .collect();
    let resp: Vec<_> = lines
        .iter()
        .filter(|l| matches!(l, Line::Text(FlowSide::Responder, _)))
        .collect();
    assert_eq!(resp.len(), 4, "every response parsed: {lines:?}");
    assert!(lines.contains(&Line::Fin(FlowSide::Responder)));
    assert!(
        !lines.contains(&Line::Fin(FlowSide::Initiator)),
        "a stopped side gets no fin"
    );
    let stops: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            SessionEvent::ParserSideStopped { side, reason, .. } => Some((*side, *reason)),
            _ => None,
        })
        .collect();
    assert_eq!(stops, vec![(FlowSide::Initiator, EndReason::StreamGap)]);
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, SessionEvent::ParserClosed { .. })),
        "the parser stays open"
    );
}

/// The gap only shows up in the final flush (the hole is still open
/// when the flow ends): the other side's fin still runs.
#[test]
fn gap_in_finals_does_not_skip_the_other_sides_fin() {
    let mut d = SessionDriver::new(FiveTuple::bidirectional(), Lines::default());
    let events = session_events(&mut d, &request_response(2));
    let fins: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            SessionEvent::Application {
                message: Line::Fin(s),
                ..
            } => Some(*s),
            _ => None,
        })
        .collect();
    assert_eq!(fins, vec![FlowSide::Responder]);
}

/// `GapResponse::Stop` still closes the whole parser.
#[test]
fn stop_still_closes_the_parser() {
    #[derive(Clone, Default)]
    struct StopAll(Lines);
    impl SessionParser for StopAll {
        type Message = Line;
        fn feed_initiator(&mut self, b: &[u8], t: Timestamp, out: &mut Vec<Line>) {
            self.0.feed_initiator(b, t, out);
        }
        fn feed_responder(&mut self, b: &[u8], t: Timestamp, out: &mut Vec<Line>) {
            self.0.feed_responder(b, t, out);
        }
        fn on_gap(&mut self, _: FlowSide, _: u64, _: Timestamp, _: &mut Vec<Line>) -> GapResponse {
            GapResponse::Stop
        }
    }
    let mut d = SessionDriver::new(FiveTuple::bidirectional(), StopAll::default());
    let events = session_events(&mut d, &request_response(1));
    assert!(events.iter().any(|e| matches!(
        e,
        SessionEvent::ParserClosed {
            reason: EndReason::StreamGap,
            ..
        }
    )));
}

/// Both sides stopped: the parser closes, once.
#[test]
fn both_sides_stopped_close_the_parser_once() {
    let mut cfg = FlowTrackerConfig::default();
    cfg.max_reassembler_buffer = Some(2);
    cfg.overflow_policy = OverflowPolicy::DropFlow;
    let mut d = SessionDriver::with_config(FiveTuple::bidirectional(), Lines::default(), cfg);
    let events = session_events(&mut d, &request_response(99));
    let stops = events
        .iter()
        .filter(|e| matches!(e, SessionEvent::ParserSideStopped { .. }))
        .count();
    let closes: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            SessionEvent::ParserClosed { reason, detail, .. } => Some((*reason, detail.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(stops, 2);
    assert_eq!(
        closes,
        vec![(
            EndReason::BufferOverflow,
            Some("both sides stopped".to_owned())
        )]
    );
}

// ── #191: slot identity and channel merge ────────────────────────

#[test]
fn session_parse_error_has_kind_and_slot() {
    let frames = flow(&[(0, vec![b'a'; 10])]);
    let mut b = Driver::builder(FiveTuple::bidirectional());
    b.emit_anomalies(true);
    let first = b.session_broadcast(PoisonAfterFirstFeed::default());
    let second = b.session_broadcast(PoisonAfterFirstFeed::default());
    assert_ne!(first.slot_id(), second.slot_id());
    let mut d = b.build();
    let mut events = Vec::new();
    for (t, f) in &frames {
        d.track_into(PacketView::new(f, *t), &mut events);
    }
    let mut slots: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            Event::FlowAnomaly {
                kind:
                    AnomalyKind::SessionParseError {
                        slot, parser_kind, ..
                    },
                ..
            } => Some((*slot, *parser_kind)),
            _ => None,
        })
        .collect();
    slots.sort_by_key(|(slot, _)| *slot);
    assert_eq!(
        slots,
        vec![
            (Some(first.slot_id()), flowscope::ParserKind::Unspecified),
            (Some(second.slot_id()), flowscope::ParserKind::Unspecified),
        ]
    );
    let closed: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            Event::ParserClosed { slot, .. } => Some(*slot),
            _ => None,
        })
        .collect();
    assert_eq!(closed, vec![first.slot_id(), second.slot_id()]);
}

/// Merging the typed driver's two channels by `lifecycle_pos` / `seq`
/// reproduces the single-parser driver's total order.
#[test]
fn merge_by_lifecycle_pos_reproduces_session_driver_order() {
    let frames = flow(&[(0, b"one".to_vec()), (3, b"two".to_vec())]);
    // Reference order.
    let mut sd = SessionDriver::new(FiveTuple::bidirectional(), Collect::default());
    let reference: Vec<String> = session_events(&mut sd, &frames)
        .into_iter()
        .filter_map(|e| match e {
            SessionEvent::Started { .. } => Some("started".to_owned()),
            SessionEvent::Application { message, .. } => Some(format!("{message:?}")),
            SessionEvent::Closed { .. } => Some("ended".to_owned()),
            _ => None,
        })
        .collect();

    let mut b = Driver::builder(FiveTuple::bidirectional());
    let mut slot = b.session_broadcast(Collect::default());
    let mut d = b.build();
    let mut events = Vec::new();
    for (t, f) in &frames {
        d.track_into(PacketView::new(f, *t), &mut events);
    }
    d.finish_into(&mut events);
    assert_eq!(d.lifecycle_seq(), events.len() as u64);
    let mut msgs = Vec::new();
    slot.drain(&mut msgs);
    msgs.sort_by_key(|m| (m.lifecycle_pos, m.seq));
    let mut merged = Vec::new();
    let mut next = msgs.into_iter().peekable();
    for (i, e) in events.iter().enumerate() {
        while next.peek().is_some_and(|m| m.lifecycle_pos <= i as u64) {
            merged.push(format!("{:?}", next.next().unwrap().message));
        }
        match e {
            Event::Started { .. } => merged.push("started".to_owned()),
            Event::Ended { .. } => merged.push("ended".to_owned()),
            _ => {}
        }
    }
    merged.extend(next.map(|m| format!("{:?}", m.message)));
    assert_eq!(merged, reference);
}

// ── #193: API ────────────────────────────────────────────────────

/// A per-flow factory builds one parser per flow from the flow key.
#[test]
fn driver_builder_accepts_per_flow_factories() {
    #[derive(Clone)]
    struct Tagged(u16);
    impl SessionParser for Tagged {
        type Message = u16;
        fn feed_initiator(&mut self, _: &[u8], _: Timestamp, out: &mut Vec<u16>) {
            out.push(self.0);
        }
        fn feed_responder(&mut self, _: &[u8], _: Timestamp, _: &mut Vec<u16>) {}
    }
    struct ByClientPort;
    impl flowscope::SessionParserFactory<FiveTupleKey> for ByClientPort {
        type Parser = Tagged;
        fn new_parser(&mut self, key: &FiveTupleKey) -> Tagged {
            Tagged(key.a.port().min(key.b.port()))
        }
    }
    let frames = flow(&[(0, b"x".to_vec())]);
    let mut b = Driver::builder(FiveTuple::bidirectional());
    let mut slot = b.session_factory_on_ports(ByClientPort, [9000]);
    let mut d = b.build();
    let mut events = Vec::new();
    for (t, f) in &frames {
        d.track_into(PacketView::new(f, *t), &mut events);
    }
    let mut msgs = Vec::new();
    slot.drain(&mut msgs);
    assert_eq!(
        msgs.iter().map(|m| m.message).collect::<Vec<_>>(),
        vec![9000]
    );
}

/// `emit_packet_source_idx(true)` survives a later `config(..)`.
#[test]
fn emit_packet_source_idx_is_order_independent() {
    let mut b = Driver::builder(FiveTuple::bidirectional());
    b.emit_packet_source_idx(true);
    b.config(FlowTrackerConfig::default());
    let _slot = b.session_broadcast(Collect::default());
    let d = b.build();
    assert!(d.tracker().config().emit_packet_source_idx);
}

/// A pending `poll_recv` is woken by the next message (netring's
/// `EventStream` hung forever without this).
#[test]
fn broadcast_handle_wakes_a_pending_receiver() {
    use std::sync::atomic::AtomicBool;
    use std::task::{Context, Poll, Wake, Waker};
    struct Flag(AtomicBool);
    impl Wake for Flag {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let flag = Arc::new(Flag(AtomicBool::new(false)));
    let waker = Waker::from(Arc::clone(&flag));
    let mut cx = Context::from_waker(&waker);

    let mut b = Driver::builder(FiveTuple::bidirectional());
    let mut sub = b.session_on_ports_broadcast_each(Collect::default(), [9000]);
    let mut d = b.build();
    assert!(sub.poll_recv(&mut cx).is_pending());
    let frames = flow(&[(0, b"x".to_vec())]);
    let mut events = Vec::new();
    for (t, f) in &frames {
        d.track_into(PacketView::new(f, *t), &mut events);
    }
    assert!(flag.0.load(Ordering::SeqCst), "woken by the push");
    assert!(matches!(sub.poll_recv(&mut cx), Poll::Ready(_)));
}

//! Engine lifecycle guarantees (0.25): sweeps and `finish` never lose
//! released data (#180), the driver owns `Ended` and auto-sweeps
//! (#187), events keep their order and `finish` never stamps
//! `Timestamp::MAX` (#188), the memcap frees memory whatever the
//! reassembler does (#185), discarding costs nothing (#183).

#![cfg(all(
    feature = "extractors",
    feature = "reassembler",
    feature = "session",
    feature = "test-helpers"
))]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use flowscope::driver::{Driver, Event};
use flowscope::extract::FiveTuple;
use flowscope::extract::parse::test_frames::ipv4_tcp;
use flowscope::session::{SessionDriver, SessionEvent};
use flowscope::{
    AnomalyKind, BufferedReassemblerFactory, EndReason, EventMask, FlowDriver, FlowEvent, FlowSide,
    FlowTrackerConfig, GapResponse, MemcapPolicy, PacketView, Reassembler, ReassemblerFactory,
    ReassemblyStop, SessionParser, Timestamp,
};

const SYN: u8 = 0x02;
const ACK: u8 = 0x10;
const PSH: u8 = 0x08;
const FIN: u8 = 0x01;
const M: [u8; 6] = [0; 6];
const C: [u8; 4] = [10, 0, 0, 1];
const S: [u8; 4] = [10, 0, 0, 2];
const CISN: u32 = 1000;
const SISN: u32 = 5000;

fn t(ms: u64) -> Timestamp {
    let d = Duration::from_millis(ms);
    Timestamp::new(d.as_secs() as u32, d.subsec_nanos())
}

fn handshake(cp: u16) -> Vec<Vec<u8>> {
    vec![
        ipv4_tcp(M, M, C, S, cp, 9000, CISN, 0, SYN, &[]),
        ipv4_tcp(M, M, S, C, 9000, cp, SISN, CISN + 1, SYN | ACK, &[]),
        ipv4_tcp(M, M, C, S, cp, 9000, CISN + 1, SISN + 1, ACK, &[]),
    ]
}

/// Client data at stream offset `off`.
fn data(cp: u16, off: u32, payload: &[u8]) -> Vec<u8> {
    ipv4_tcp(
        M,
        M,
        C,
        S,
        cp,
        9000,
        CISN + 1 + off,
        SISN + 1,
        PSH | ACK,
        payload,
    )
}

fn fin_exchange(cp: u16, end: u32) -> Vec<Vec<u8>> {
    vec![
        ipv4_tcp(
            M,
            M,
            C,
            S,
            cp,
            9000,
            CISN + 1 + end,
            SISN + 1,
            FIN | ACK,
            &[],
        ),
        ipv4_tcp(
            M,
            M,
            S,
            C,
            9000,
            cp,
            SISN + 1,
            CISN + 2 + end,
            FIN | ACK,
            &[],
        ),
        ipv4_tcp(M, M, C, S, cp, 9000, CISN + 2 + end, SISN + 2, ACK, &[]),
    ]
}

/// Frames 1 ms apart from t = 1 s.
fn timed(frames: Vec<Vec<u8>>) -> Vec<(Timestamp, Vec<u8>)> {
    frames
        .into_iter()
        .enumerate()
        .map(|(i, f)| (t(1_000 + i as u64), f))
        .collect()
}

#[derive(Debug, Clone, PartialEq)]
enum Piece {
    Data(Vec<u8>),
    Gap(u64),
    Tick(Timestamp),
}

/// Records bytes and gaps (continuing past gaps) and tick times.
#[derive(Clone, Default)]
struct Collect;

impl SessionParser for Collect {
    type Message = Piece;
    fn feed_initiator(&mut self, b: &[u8], _: Timestamp, out: &mut Vec<Piece>) {
        out.push(Piece::Data(b.to_vec()));
    }
    fn feed_responder(&mut self, b: &[u8], _: Timestamp, out: &mut Vec<Piece>) {
        out.push(Piece::Data(b.to_vec()));
    }
    fn on_gap(&mut self, _: FlowSide, n: u64, _: Timestamp, out: &mut Vec<Piece>) -> GapResponse {
        out.push(Piece::Gap(n));
        GapResponse::Continue
    }
    fn on_tick(&mut self, now: Timestamp, out: &mut Vec<Piece>) {
        out.push(Piece::Tick(now));
    }
}

fn pieces(events: &[SessionEvent<flowscope::extract::FiveTupleKey, Piece>]) -> Vec<Piece> {
    events
        .iter()
        .filter_map(|e| match e {
            SessionEvent::Application { message, .. } => match message {
                Piece::Tick(_) => None,
                m => Some(m.clone()),
            },
            _ => None,
        })
        .collect()
}

fn joined(p: &[Piece]) -> (Vec<u8>, u64) {
    let mut bytes = Vec::new();
    let mut gap = 0;
    for x in p {
        match x {
            Piece::Data(d) => bytes.extend_from_slice(d),
            Piece::Gap(n) => gap += n,
            Piece::Tick(_) => {}
        }
    }
    (bytes, gap)
}

// ── #180: sweeps / finish never drop released data ──────────────

/// A hole on a flow that then idles out: the data behind the hole
/// is delivered (after a gap) before the flow's end.
#[test]
fn sweep_delivers_released_tail_of_ending_flow() {
    let mut frames = handshake(40_000);
    frames.push(data(40_000, 0, b"hello"));
    frames.push(data(40_000, 10, b"world"));
    let mut d = SessionDriver::new(FiveTuple::bidirectional(), Collect);
    let mut out = Vec::new();
    for (ts, f) in timed(frames) {
        d.track_into(PacketView::new(&f, ts), &mut out);
    }
    // Idle timeout (300 s) and the hole deadline expire together.
    d.sweep_into(t(400_000), &mut out);
    assert!(matches!(
        out.last(),
        Some(SessionEvent::Closed {
            reason: EndReason::IdleTimeout,
            ..
        })
    ));
    assert_eq!(joined(&pieces(&out)), (b"helloworld".to_vec(), 5));
}

#[test]
fn finish_delivers_ooo_tail() {
    let mut frames = handshake(40_000);
    frames.push(data(40_000, 0, b"hello"));
    frames.push(data(40_000, 10, b"world"));
    frames.push(data(40_000, 20, b"again"));
    let mut d = SessionDriver::new(FiveTuple::bidirectional(), Collect);
    let mut out = Vec::new();
    for (ts, f) in timed(frames) {
        d.track_into(PacketView::new(&f, ts), &mut out);
    }
    d.finish_into(&mut out);
    assert_eq!(joined(&pieces(&out)), (b"helloworldagain".to_vec(), 10));
}

/// The first data segment of a flow arrives out of order; its hole
/// expires in a sweep. A port-selected parser still gets it.
#[test]
fn ports_selector_admits_flow_first_seen_in_sweep() {
    let mut frames = handshake(40_000);
    frames.push(data(40_000, 5, b"late start"));
    let mut b = Driver::builder(FiveTuple::bidirectional());
    let mut slot = b.session_on_ports(Collect, [9000]);
    let mut d = b.build();
    let mut events = Vec::new();
    for (ts, f) in timed(frames) {
        d.track_into(PacketView::new(&f, ts), &mut events);
    }
    // Lone out-of-order segment: skipped after four deadlines, long
    // before the idle timeout.
    d.sweep_into(t(10_000), &mut events);
    let mut msgs = Vec::new();
    slot.drain(&mut msgs);
    let got: Vec<_> = msgs
        .into_iter()
        .map(|m| m.message)
        .filter(|m| !matches!(m, Piece::Tick(_)))
        .collect();
    assert_eq!(
        got,
        vec![Piece::Gap(5), Piece::Data(b"late start".to_vec())]
    );
}

// ── #187: the driver owns Ended and the auto-sweep ──────────────

/// With `Ended` suppressed, per-flow state is still released, and a
/// new connection on the same 5-tuple starts fresh.
#[test]
fn masked_ended_frees_state_and_reuse_is_fresh() {
    let cfg = FlowTrackerConfig::default().with_event_filter(EventMask::ENDED);
    let mut b = Driver::builder(FiveTuple::bidirectional());
    b.config(cfg);
    let mut slot = b.session_broadcast(Collect);
    let mut d = b.build();
    let mut frames = handshake(40_000);
    frames.push(data(40_000, 0, b"first"));
    frames.extend(fin_exchange(40_000, 5));
    let mut events = Vec::new();
    for (ts, f) in timed(frames) {
        d.track_into(PacketView::new(&f, ts), &mut events);
    }
    assert!(!events.iter().any(|e| matches!(e, Event::Ended { .. })));
    assert_eq!(d.flow_driver().stream_count(), 0, "stream state released");
    assert_eq!(d.tracker().flow_count(), 0);

    // Same 5-tuple, new connection with a different ISN.
    let reuse = [
        ipv4_tcp(M, M, C, S, 40_000, 9000, 77_000, 0, SYN, &[]),
        ipv4_tcp(M, M, S, C, 9000, 40_000, 88_000, 77_001, SYN | ACK, &[]),
        ipv4_tcp(
            M,
            M,
            C,
            S,
            40_000,
            9000,
            77_001,
            88_001,
            PSH | ACK,
            b"second",
        ),
    ];
    for f in &reuse {
        d.track_into(PacketView::new(f, t(5_000)), &mut events);
    }
    let mut msgs = Vec::new();
    slot.drain(&mut msgs);
    let data: Vec<_> = msgs
        .into_iter()
        .filter_map(|m| match m.message {
            Piece::Data(d) => Some(d),
            _ => None,
        })
        .collect();
    assert_eq!(data, vec![b"first".to_vec(), b"second".to_vec()]);
}

/// `auto_sweep_interval` runs the whole sweep — reassembler
/// deadlines included — not just the tracker's.
#[test]
fn auto_sweep_runs_advance_time() {
    let mut cfg = FlowTrackerConfig::default();
    cfg.auto_sweep_interval = Some(Duration::from_secs(1));
    let mut b = Driver::builder(FiveTuple::bidirectional());
    b.config(cfg);
    let mut slot = b.session_on_ports(Collect, [9000]);
    let mut d = b.build();
    let mut frames = handshake(40_000);
    frames.push(data(40_000, 0, b"a"));
    frames.push(data(40_000, 5, b"b")); // lone hole
    let mut events = Vec::new();
    for (ts, f) in timed(frames) {
        d.track_into(PacketView::new(&f, ts), &mut events);
    }
    // Traffic on another flow moves packet time on by 10 s.
    let other = handshake(41_000);
    d.track_into(PacketView::new(&other[0], t(11_000)), &mut events);
    let mut msgs = Vec::new();
    slot.drain(&mut msgs);
    let got: Vec<_> = msgs
        .into_iter()
        .map(|m| m.message)
        .filter(|m| !matches!(m, Piece::Tick(_)))
        .collect();
    assert_eq!(
        got,
        vec![
            Piece::Data(b"a".to_vec()),
            Piece::Gap(4),
            Piece::Data(b"b".to_vec())
        ]
    );
}

#[test]
fn anomaly_mask_bits_honoured() {
    let run = |suppress: EventMask| {
        let cfg = FlowTrackerConfig::default().with_event_filter(suppress);
        let mut b = Driver::builder(FiveTuple::bidirectional());
        b.config(cfg);
        b.emit_anomalies(true);
        let _slot = b.session_broadcast(Collect);
        let mut d = b.build();
        let mut frames = handshake(40_000);
        frames.push(data(40_000, 0, b"a"));
        frames.push(data(40_000, 5, b"b"));
        let mut events = Vec::new();
        for (ts, f) in timed(frames) {
            d.track_into(PacketView::new(&f, ts), &mut events);
        }
        d.finish_into(&mut events);
        events
            .iter()
            .filter(|e| matches!(e, Event::FlowAnomaly { .. }))
            .count()
    };
    assert!(run(EventMask::empty()) > 0);
    assert_eq!(run(EventMask::FLOW_ANOMALY), 0);
}

// ── #188: ordering and end-of-input stamps ──────────────────────

/// The packet that ends a flow carries a retransmit: its anomaly
/// comes before the flow's `Ended`.
#[test]
fn per_packet_anomalies_precede_own_ended() {
    let mut d = FlowDriver::new(
        FiveTuple::bidirectional(),
        BufferedReassemblerFactory::default(),
    )
    .with_emit_anomalies(true);
    let mut frames = handshake(40_000);
    frames.push(data(40_000, 0, b"abc"));
    frames.push(ipv4_tcp(
        M,
        M,
        C,
        S,
        40_000,
        9000,
        CISN + 4,
        SISN + 1,
        FIN | ACK,
        &[],
    ));
    frames.push(ipv4_tcp(
        M,
        M,
        S,
        C,
        9000,
        40_000,
        SISN + 1,
        CISN + 5,
        FIN | ACK,
        &[],
    ));
    // Final ACK, retransmitting "abc".
    frames.push(ipv4_tcp(
        M,
        M,
        C,
        S,
        40_000,
        9000,
        CISN + 1,
        SISN + 2,
        ACK,
        b"abc",
    ));
    let mut last = Vec::new();
    for (ts, f) in timed(frames) {
        last = d.track(PacketView::new(&f, ts)).into_vec();
    }
    let kinds: Vec<&str> = last
        .iter()
        .map(|e| match e {
            FlowEvent::FlowAnomaly { .. } => "anomaly",
            FlowEvent::Ended { .. } => "ended",
            _ => "other",
        })
        .filter(|k| *k != "other")
        .collect();
    assert_eq!(kinds, vec!["anomaly", "ended"]);
}

#[test]
fn flush_anomalies_precede_ended_and_finish_never_stamps_max() {
    let mut b = Driver::builder(FiveTuple::bidirectional());
    b.emit_anomalies(true);
    let _slot = b.session_broadcast(Collect);
    let mut d = b.build();
    let mut frames = handshake(40_000);
    frames.push(data(40_000, 0, b"a"));
    frames.push(data(40_000, 5, b"b"));
    let frames = timed(frames);
    let last_ts = frames.last().unwrap().0;
    let mut events = Vec::new();
    for (ts, f) in &frames {
        d.track_into(PacketView::new(f, *ts), &mut events);
    }
    events.clear();
    d.finish_into(&mut events);
    let gap_at = events
        .iter()
        .position(|e| {
            matches!(
                e,
                Event::FlowAnomaly {
                    kind: AnomalyKind::StreamGap { .. },
                    ..
                }
            )
        })
        .expect("gap reported");
    let end_at = events
        .iter()
        .position(|e| matches!(e, Event::Ended { .. }))
        .expect("ended");
    assert!(gap_at < end_at);
    for e in &events {
        assert_ne!(e.timestamp(), Timestamp::MAX, "{e:?}");
    }
    assert_eq!(events[gap_at].timestamp(), last_ts);
}

#[test]
fn finish_keeps_monotonic_clock_and_stamps_ticks() {
    let mut d =
        SessionDriver::new(FiveTuple::bidirectional(), Collect).with_monotonic_timestamps(true);
    let mut out = Vec::new();
    let mut frames = handshake(40_000);
    frames.push(data(40_000, 0, b"x"));
    let frames = timed(frames);
    let last_ts = frames.last().unwrap().0;
    for (ts, f) in &frames {
        d.track_into(PacketView::new(f, *ts), &mut out);
    }
    out.clear();
    d.finish_into(&mut out);
    // The parser saw "end of input"...
    let ticks: Vec<_> = out
        .iter()
        .filter_map(|e| match e {
            SessionEvent::Application {
                message: Piece::Tick(now),
                ts,
                ..
            } => Some((*now, *ts)),
            _ => None,
        })
        .collect();
    assert_eq!(
        ticks,
        vec![(Timestamp::MAX, last_ts)],
        "stamped with packet time"
    );
    // ... and the clock was not pinned at MAX.
    out.clear();
    let later = handshake(41_000);
    d.track_into(PacketView::new(&later[0], t(20_000)), &mut out);
    let started = out
        .iter()
        .find_map(|e| match e {
            SessionEvent::Started { ts, .. } => Some(*ts),
            _ => None,
        })
        .unwrap();
    assert_eq!(started, t(20_000));
}

#[test]
fn on_tick_gets_clamped_now() {
    let mut d =
        SessionDriver::new(FiveTuple::bidirectional(), Collect).with_monotonic_timestamps(true);
    let mut out = Vec::new();
    let mut frames = handshake(40_000);
    frames.push(data(40_000, 0, b"x"));
    for (ts, f) in timed(frames) {
        d.track_into(PacketView::new(&f, ts), &mut out);
    }
    out.clear();
    d.sweep_into(t(10), &mut out); // earlier than the last packet
    let ticks: Vec<_> = out
        .iter()
        .filter_map(|e| match e {
            SessionEvent::Application {
                message: Piece::Tick(now),
                ..
            } => Some(*now),
            _ => None,
        })
        .collect();
    assert_eq!(ticks, vec![t(1_003)]);
}

// ── #185: memcap ────────────────────────────────────────────────

/// Buffers everything; `release` does nothing (the trait default).
#[derive(Default)]
struct Hoarder {
    buf: Vec<u8>,
}

impl Reassembler for Hoarder {
    fn segment(&mut self, _: u32, payload: &[u8], _: Timestamp) {
        self.buf.extend_from_slice(payload);
    }
    fn current_bytes(&self) -> u64 {
        self.buf.len() as u64
    }
}

#[derive(Default)]
struct HoarderFactory;

impl<K> ReassemblerFactory<K> for HoarderFactory {
    type Reassembler = Hoarder;
    fn new_reassembler(&mut self, _: &K, _: FlowSide) -> Hoarder {
        Hoarder::default()
    }
}

#[test]
fn memcap_frees_custom_noop_release_reassembler_and_tombstones_empty_peer() {
    let mut cfg = FlowTrackerConfig::default();
    cfg.reassembly_memcap = Some(100);
    cfg.reassembly_memcap_policy = MemcapPolicy::DropFlow;
    let mut d = FlowDriver::with_config(FiveTuple::bidirectional(), HoarderFactory, cfg);
    let mut frames = handshake(40_000);
    frames.push(data(40_000, 0, &[b'x'; 200]));
    // The responder only speaks after the trip.
    frames.push(ipv4_tcp(
        M,
        M,
        S,
        C,
        9000,
        40_000,
        SISN + 1,
        CISN + 201,
        PSH | ACK,
        b"late",
    ));
    let frames = timed(frames);
    let mut key = None;
    for (ts, f) in &frames[..4] {
        let _ = d.track(PacketView::new(f, *ts));
        key = d.last_packet().map(|p| p.key);
    }
    let key = key.unwrap();
    assert_eq!(d.reassembly_memcap_bytes(), 0, "memory freed");
    assert!(d.reassembler(&key, FlowSide::Initiator).is_none());
    let (ts, f) = &frames[4];
    let _ = d.track(PacketView::new(f, *ts));
    assert!(
        d.reassembler(&key, FlowSide::Responder).is_none(),
        "DropFlow released the peer too, although it had no reassembler yet"
    );
    let ended = d.finish();
    let stats = ended
        .iter()
        .find_map(|e| match e {
            FlowEvent::Ended { stats, .. } => Some(stats.clone()),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        stats.reassembly_stop_initiator,
        Some(ReassemblyStop::Memcap)
    );
    assert_eq!(
        stats.reassembly_stop_responder,
        Some(ReassemblyStop::Memcap)
    );
}

// ── #183: discarding costs nothing ──────────────────────────────

#[test]
fn discard_stream_allocates_no_reassembler() {
    let mut d = FlowDriver::new(
        FiveTuple::bidirectional(),
        BufferedReassemblerFactory::default(),
    );
    let frames = timed(handshake(40_000));
    for (ts, f) in &frames {
        let _ = d.track(PacketView::new(f, *ts));
    }
    let key = d.last_packet().unwrap().key;
    d.discard_stream(&key);
    let f = data(40_000, 0, b"ignored");
    let _ = d.track(PacketView::new(&f, t(2_000)));
    assert!(d.reassembler(&key, FlowSide::Initiator).is_none());
    assert!(d.reassembler(&key, FlowSide::Responder).is_none());
    assert_eq!(d.reassembly_memcap_bytes(), 0);
}

/// The parser-visible order around a released tail: data, then the
/// parser close, then the end.
#[test]
fn released_tail_precedes_parser_close_and_end() {
    let seen = Arc::new(Mutex::new(Vec::<&'static str>::new()));
    let mut frames = handshake(40_000);
    frames.push(data(40_000, 0, b"a"));
    frames.push(data(40_000, 5, b"b"));
    let mut d = SessionDriver::new(FiveTuple::bidirectional(), Collect);
    let mut out = Vec::new();
    for (ts, f) in timed(frames) {
        d.track_into(PacketView::new(&f, ts), &mut out);
    }
    out.clear();
    d.finish_into(&mut out);
    for e in &out {
        seen.lock().unwrap().push(match e {
            SessionEvent::Application { .. } => "message",
            SessionEvent::ParserClosed { .. } => "parser_closed",
            SessionEvent::Closed { .. } => "closed",
            _ => "other",
        });
    }
    let seen = seen.lock().unwrap();
    let last_message = seen.iter().rposition(|k| *k == "message").unwrap();
    let closed = seen.iter().position(|k| *k == "closed").unwrap();
    assert!(last_message < closed);
    assert_eq!(seen.last(), Some(&"closed"));
}

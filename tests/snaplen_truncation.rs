//! #212 / #219: packets a capture snap length cut short.
//!
//! Before 0.26 the extractors sliced frames strictly, so every packet
//! whose IP header claimed more bytes than were captured (`tcpdump -s
//! 96`, a ring frame smaller than the packet) was skipped: no flow, no
//! byte count, and a reassembled stream that silently lost the
//! segment. Now such a packet is tracked; its captured bytes are
//! reassembled and the rest is reported as a gap right away; a cut
//! datagram is not handed to a parser.

#![cfg(all(
    feature = "extractors",
    feature = "reassembler",
    feature = "session",
    feature = "test-helpers"
))]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use flowscope::extract::FiveTuple;
use flowscope::extract::parse::test_frames::{ipv4_tcp, ipv4_udp};
use flowscope::session::{DatagramDriver, SessionDriver, SessionEvent};
use flowscope::{
    DatagramParser, EndReason, FlowSide, GapResponse, PacketView, SessionParser, TemplateFactory,
    Timestamp,
};

const SYN: u8 = 0x02;
const ACK: u8 = 0x10;
const PSH: u8 = 0x08;
const FIN: u8 = 0x01;
const M: [u8; 6] = [0; 6];
const C: [u8; 4] = [10, 0, 0, 1];
const S: [u8; 4] = [10, 0, 0, 2];
const CP: u16 = 40_000;
const SP: u16 = 9_000;
const CISN: u32 = 1000;
const SISN: u32 = 5000;
/// Ethernet + IPv4 + TCP headers (no options): what `-s 54` keeps.
const HEADERS: usize = 14 + 20 + 20;

fn ts_ms(ms: u64) -> Timestamp {
    let d = Duration::from_millis(ms);
    Timestamp::new(d.as_secs() as u32, d.subsec_nanos())
}

/// Client → server handshake, the client's `segments` (offset from
/// ISN + 1, payload), then a FIN exchange. 1 ms apart from t = 1 s.
fn flow(segments: &[(u32, Vec<u8>)]) -> Vec<(Timestamp, Vec<u8>)> {
    let mut v = vec![
        ipv4_tcp(M, M, C, S, CP, SP, CISN, 0, SYN, &[]),
        ipv4_tcp(M, M, S, C, SP, CP, SISN, CISN + 1, SYN | ACK, &[]),
        ipv4_tcp(M, M, C, S, CP, SP, CISN + 1, SISN + 1, ACK, &[]),
    ];
    let mut end = CISN + 1;
    for (off, payload) in segments {
        let seq = CISN + 1 + off;
        v.push(ipv4_tcp(
            M,
            M,
            C,
            S,
            CP,
            SP,
            seq,
            SISN + 1,
            PSH | ACK,
            payload,
        ));
        end = end.max(seq + payload.len() as u32);
    }
    v.push(ipv4_tcp(M, M, C, S, CP, SP, end, SISN + 1, FIN | ACK, &[]));
    v.push(ipv4_tcp(
        M,
        M,
        S,
        C,
        SP,
        CP,
        SISN + 1,
        end + 1,
        FIN | ACK,
        &[],
    ));
    v.push(ipv4_tcp(M, M, C, S, CP, SP, end + 1, SISN + 2, ACK, &[]));
    stamp(v)
}

fn stamp(frames: Vec<Vec<u8>>) -> Vec<(Timestamp, Vec<u8>)> {
    frames
        .into_iter()
        .enumerate()
        .map(|(i, f)| (ts_ms(1_000 + i as u64), f))
        .collect()
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

type Events = Vec<SessionEvent<flowscope::extract::FiveTupleKey, Piece>>;

fn collector() -> SessionDriver<FiveTuple, TemplateFactory<Collect>> {
    SessionDriver::new(
        FiveTuple::bidirectional(),
        TemplateFactory(Collect {
            continue_on_gap: true,
        }),
    )
}

fn pieces(out: &Events) -> Vec<Piece> {
    out.iter()
        .filter_map(|e| match e {
            SessionEvent::Application { message, .. } => Some(message.clone()),
            _ => None,
        })
        .collect()
}

fn closed(out: &Events) -> (EndReason, flowscope::FlowStats) {
    out.iter()
        .find_map(|e| match e {
            SessionEvent::Closed { reason, stats, .. } => Some((*reason, stats.clone())),
            _ => None,
        })
        .expect("the flow ends")
}

/// A segment cut after 10 of its 100 payload bytes: the 10 bytes are
/// delivered and the 90 reported as a gap together with that packet —
/// not when the next segment or a deadline comes along.
#[test]
fn truncated_segment_becomes_an_immediate_gap() {
    let mut frames = flow(&[(0, vec![b'a'; 100]), (100, b"bbbb".to_vec())]);
    // frames[3] is the 100-byte segment; keep its headers + 10 bytes.
    frames[3].1.truncate(HEADERS + 10);
    let mut d = collector();
    let mut out = Events::new();
    for (i, (t, f)) in frames.iter().enumerate() {
        d.track_into(PacketView::new(f, *t), &mut out);
        if i == 3 {
            assert_eq!(
                pieces(&out),
                vec![
                    Piece::Data(FlowSide::Initiator, vec![b'a'; 10]),
                    Piece::Gap(FlowSide::Initiator, 90),
                ],
                "the cut packet yields its bytes and its gap at once"
            );
        }
    }
    d.finish_into(&mut out);
    assert_eq!(
        pieces(&out),
        vec![
            Piece::Data(FlowSide::Initiator, vec![b'a'; 10]),
            Piece::Gap(FlowSide::Initiator, 90),
            Piece::Data(FlowSide::Initiator, b"bbbb".to_vec()),
            Piece::Fin(FlowSide::Initiator),
        ]
    );
    let (reason, stats) = closed(&out);
    assert_eq!(reason, EndReason::Fin);
    assert_eq!(stats.reassembly_gap_bytes_initiator, 90);
    assert_eq!(stats.reassembly_gaps_initiator, 1);
}

/// The snap cut can also be known only from the source
/// (`PacketView::with_wire_len`): same result.
#[test]
fn truncated_segment_with_a_reported_wire_length() {
    let mut frames = flow(&[(0, vec![b'a'; 100]), (100, b"bbbb".to_vec())]);
    let wire = frames[3].1.len();
    frames[3].1.truncate(HEADERS + 10);
    let mut d = collector();
    let mut out = Events::new();
    for (i, (t, f)) in frames.iter().enumerate() {
        let view = PacketView::new(f, *t);
        let view = if i == 3 {
            view.with_wire_len(wire)
        } else {
            view
        };
        d.track_into(view, &mut out);
    }
    d.finish_into(&mut out);
    assert_eq!(
        pieces(&out),
        vec![
            Piece::Data(FlowSide::Initiator, vec![b'a'; 10]),
            Piece::Gap(FlowSide::Initiator, 90),
            Piece::Data(FlowSide::Initiator, b"bbbb".to_vec()),
            Piece::Fin(FlowSide::Initiator),
        ]
    );
}

/// A cut segment that carries the FIN: the stream ends after the
/// segment's wire length (not its captured length), so the cut bytes
/// are one gap and nothing is left waiting.
#[test]
fn truncated_data_fin_ends_stream_at_wire_length() {
    let data_fin = {
        let mut f = ipv4_tcp(
            M,
            M,
            C,
            S,
            CP,
            SP,
            CISN + 1,
            SISN + 1,
            FIN | PSH | ACK,
            &[b'z'; 100],
        );
        f.truncate(HEADERS + 10);
        f
    };
    let frames = stamp(vec![
        ipv4_tcp(M, M, C, S, CP, SP, CISN, 0, SYN, &[]),
        ipv4_tcp(M, M, S, C, SP, CP, SISN, CISN + 1, SYN | ACK, &[]),
        ipv4_tcp(M, M, C, S, CP, SP, CISN + 1, SISN + 1, ACK, &[]),
        data_fin,
        ipv4_tcp(M, M, S, C, SP, CP, SISN + 1, CISN + 102, FIN | ACK, &[]),
        ipv4_tcp(M, M, C, S, CP, SP, CISN + 102, SISN + 2, ACK, &[]),
    ]);
    let mut d = collector();
    let mut out = Events::new();
    for (t, f) in &frames {
        d.track_into(PacketView::new(f, *t), &mut out);
    }
    d.finish_into(&mut out);
    assert_eq!(
        pieces(&out),
        vec![
            Piece::Data(FlowSide::Initiator, vec![b'z'; 10]),
            Piece::Gap(FlowSide::Initiator, 90),
            Piece::Fin(FlowSide::Initiator),
        ]
    );
    let (reason, stats) = closed(&out);
    assert_eq!(reason, EndReason::Fin, "both FINs seen");
    assert_eq!(stats.reassembly_gap_bytes_initiator, 90);
}

/// `tcpdump -s 54`: only headers. Every data segment is a gap of its
/// own size, reported with its packet — the stream never stalls
/// waiting for bytes no capture holds.
#[test]
fn header_only_capture_produces_gaps_not_stalls() {
    let mut frames = flow(&[
        (0, vec![b'a'; 100]),
        (100, vec![b'b'; 100]),
        (200, vec![b'c'; 100]),
    ]);
    for (_, f) in &mut frames {
        f.truncate(HEADERS);
    }
    let mut d = collector();
    let mut out = Events::new();
    let mut gaps_after_packet = Vec::new();
    for (t, f) in &frames {
        d.track_into(PacketView::new(f, *t), &mut out);
        gaps_after_packet.push(
            pieces(&out)
                .iter()
                .filter(|p| matches!(p, Piece::Gap(..)))
                .count(),
        );
    }
    d.finish_into(&mut out);
    assert_eq!(
        gaps_after_packet[3..6],
        [1, 2, 3],
        "one gap per data packet"
    );
    assert_eq!(
        pieces(&out),
        vec![
            Piece::Gap(FlowSide::Initiator, 100),
            Piece::Gap(FlowSide::Initiator, 100),
            Piece::Gap(FlowSide::Initiator, 100),
            Piece::Fin(FlowSide::Initiator),
        ]
    );
    let (reason, stats) = closed(&out);
    assert_eq!(reason, EndReason::Fin);
    assert_eq!(stats.reassembly_gap_bytes_initiator, 300);
}

/// Records the length of every datagram it is handed.
#[derive(Clone, Default)]
struct Lengths {
    seen: Arc<Mutex<Vec<usize>>>,
}

impl DatagramParser for Lengths {
    type Message = ();
    fn parse(&mut self, payload: &[u8], _: FlowSide, _: Timestamp, _: &mut Vec<()>) {
        self.seen.lock().unwrap().push(payload.len());
    }
}

/// A cut datagram is tracked (it is part of the flow, and counted) but
/// not parsed: the parser would read a damaged message.
#[test]
fn truncated_datagram_is_not_parsed() {
    let mut cut = ipv4_udp(C, S, 5000, 53, &[0x42; 200]);
    cut.truncate(14 + 20 + 8 + 20);
    let whole = ipv4_udp(C, S, 5000, 53, b"query");
    let parser = Lengths::default();
    let seen = parser.seen.clone();
    let mut d = DatagramDriver::new(FiveTuple::bidirectional(), TemplateFactory(parser));
    let mut out = Vec::new();
    d.track_into(PacketView::new(&cut, ts_ms(1)), &mut out);
    d.track_into(PacketView::new(&whole, ts_ms(2)), &mut out);
    d.finish_into(&mut out);
    assert_eq!(*seen.lock().unwrap(), vec![5], "only the whole datagram");
    let stats = out
        .iter()
        .find_map(|e| match e {
            SessionEvent::Closed { stats, .. } => Some(stats.clone()),
            _ => None,
        })
        .expect("the flow ends");
    assert_eq!(stats.packets_initiator, 2, "the cut datagram is tracked");
}

/// A snap cut that falls in the Ethernet padding after a complete
/// datagram cuts nothing the parser reads.
#[test]
fn snap_cut_in_trailer_padding_is_not_a_truncation() {
    let mut f = ipv4_udp(C, S, 5000, 53, b"hi");
    f.resize(60, 0); // minimum frame: 16 bytes of padding
    let parser = Lengths::default();
    let seen = parser.seen.clone();
    let mut d = DatagramDriver::new(FiveTuple::bidirectional(), TemplateFactory(parser));
    let mut out = Vec::new();
    d.track_into(
        PacketView::new(&f[..50], ts_ms(1)).with_wire_len(60),
        &mut out,
    );
    d.finish_into(&mut out);
    assert_eq!(*seen.lock().unwrap(), vec![2]);
}

/// #219: bytes count the wire length (what the snap length cut
/// included), IP octets the datagram's own length (no Ethernet header
/// or padding), and the cut packets are counted.
#[test]
fn truncated_segment_counts_wire_and_ip_bytes() {
    use flowscope::{FlowEvent, FlowTracker};
    let mut frames = flow(&[(0, vec![b'a'; 100]), (100, b"bbbb".to_vec())]);
    // The 100-byte segment (154 bytes on the wire) cut after 10.
    frames[3].1.truncate(HEADERS + 10);
    // The final ACK padded to the 60-byte Ethernet minimum.
    frames.last_mut().unwrap().1.resize(60, 0);
    let mut tracker: FlowTracker<FiveTuple> = FlowTracker::new(FiveTuple::bidirectional());
    let mut packet_lens = Vec::new();
    let mut stats = None;
    for (t, f) in &frames {
        for ev in tracker.track(PacketView::new(f, *t)) {
            match ev {
                FlowEvent::Packet { len, .. } => packet_lens.push(len),
                FlowEvent::Ended { stats: s, .. } => stats = Some(s),
                _ => {}
            }
        }
    }
    let stats = stats.expect("the flow ends with the last ACK");
    // Initiator: SYN 54, ACK 54, data 154 (cut), data 58, FIN 54, ACK 60.
    assert_eq!(stats.packets_initiator, 6, "the cut segment is counted");
    assert_eq!(stats.bytes_initiator, 54 + 54 + 154 + 58 + 54 + 60);
    // Responder: SYN-ACK 54, FIN-ACK 54.
    assert_eq!(stats.bytes_responder, 54 + 54);
    assert_eq!(packet_lens[3], 154, "Packet.len is the wire length");
    // IP octets: 40-byte headers, + payload; no Ethernet, no padding.
    assert_eq!(stats.ip_bytes_initiator, 40 + 40 + 140 + 44 + 40 + 40);
    assert_eq!(stats.ip_bytes_responder, 40 + 40);
    assert_eq!(stats.total_ip_bytes(), 344 + 80);
    assert_eq!(stats.ip_bytes_for(FlowSide::Responder), 80);
    assert_eq!(
        (
            stats.packets_truncated_initiator,
            stats.packets_truncated_responder
        ),
        (1, 0)
    );
}

/// #219: a source that knows the wire length counts it even when the
/// cut fell in the Ethernet padding (the IP datagram is complete).
#[test]
fn reported_wire_length_is_counted() {
    use flowscope::{FlowEvent, FlowTracker};
    let mut f = ipv4_udp(C, S, 5000, 53, b"hi");
    f.resize(60, 0);
    let mut tracker: FlowTracker<FiveTuple> = FlowTracker::new(FiveTuple::bidirectional());
    let mut len = None;
    for ev in tracker.track(PacketView::new(&f[..50], ts_ms(1)).with_wire_len(60)) {
        if let FlowEvent::Packet { len: l, .. } = ev {
            len = Some(l);
        }
    }
    assert_eq!(len, Some(60));
    let stats = tracker
        .finish()
        .into_iter()
        .find_map(|e| match e {
            FlowEvent::Ended { stats, .. } => Some(stats),
            _ => None,
        })
        .unwrap();
    assert_eq!(stats.bytes_initiator, 60);
    assert_eq!(stats.ip_bytes_initiator, 30);
    assert_eq!(stats.packets_truncated_initiator, 1, "the source cut it");
}

/// Bytes after a UDP datagram inside its IP payload (UDP options,
/// trailing data) are not a truncation: the datagram is parsed, as
/// before 0.26, and not counted as cut.
#[test]
fn udp_surplus_area_is_parsed() {
    let mut f = ipv4_udp(C, S, 5000, 53, &[7; 40]);
    // UDP length 38: a 30-byte datagram, 10 surplus bytes after it.
    f[14 + 20 + 4..14 + 20 + 6].copy_from_slice(&38u16.to_be_bytes());
    let parser = Lengths::default();
    let seen = parser.seen.clone();
    let mut d = DatagramDriver::new(FiveTuple::bidirectional(), TemplateFactory(parser));
    let mut out = Vec::new();
    d.track_into(PacketView::new(&f, ts_ms(1)), &mut out);
    d.finish_into(&mut out);
    assert_eq!(*seen.lock().unwrap(), vec![30]);
    let stats = out
        .iter()
        .find_map(|e| match e {
            SessionEvent::Closed { stats, .. } => Some(stats.clone()),
            _ => None,
        })
        .expect("the flow ends");
    assert_eq!(stats.packets_truncated_initiator, 0);
    assert_eq!(stats.bytes_initiator, f.len() as u64);
}

/// A frame its source reports complete (`with_wire_len` = its length)
/// whose IP header claims more bytes is not a truncated packet but a
/// lying one — receivers drop it — so it is skipped, as before 0.26,
/// instead of making the reassembler skip what the header claims.
#[test]
fn a_complete_frame_overrules_a_lying_ip_header() {
    use flowscope::{FlowEvent, FlowTracker};
    let mut f = ipv4_tcp(M, M, C, S, CP, SP, CISN + 1, SISN + 1, PSH | ACK, b"x");
    // IPv4 total length: claim 60 000 bytes.
    f[16..18].copy_from_slice(&60_000u16.to_be_bytes());
    let mut tracker: FlowTracker<FiveTuple> = FlowTracker::new(FiveTuple::bidirectional());
    let evs = tracker.track(PacketView::new(&f, ts_ms(1)).with_wire_len(f.len()));
    assert!(evs.is_empty(), "{evs:?}");
    assert_eq!(tracker.stats().packets_unmatched, 1);
    // A source that does not know trusts the header (snap length
    // unknown): the packet is tracked as cut.
    let evs = tracker.track(PacketView::new(&f, ts_ms(2)));
    assert!(evs.iter().any(|e| matches!(e, FlowEvent::Started { .. })));
}

/// A reported snap cut bounds what the IP header may claim was cut.
#[test]
fn a_reported_cut_bounds_the_header_claim() {
    use flowscope::{FlowEvent, FlowTracker};
    let mut f = ipv4_tcp(
        M,
        M,
        C,
        S,
        CP,
        SP,
        CISN + 1,
        SISN + 1,
        PSH | ACK,
        &[b'x'; 100],
    );
    // The header claims 10 000 more bytes than the 100-byte payload.
    f[16..18].copy_from_slice(&(20u16 + 20 + 10_100).to_be_bytes());
    f.truncate(HEADERS + 60); // the source cut 40 bytes
    let mut tracker: FlowTracker<FiveTuple> = FlowTracker::new(FiveTuple::bidirectional());
    let mut len = None;
    for ev in tracker.track(PacketView::new(&f, ts_ms(1)).with_snap_cut(40)) {
        if let FlowEvent::Packet { len: l, .. } = ev {
            len = Some(l);
        }
    }
    assert_eq!(len, Some(f.len() + 40), "the cut the source reported");
}

// ── Malformed complete packets stay skipped (as in 0.25) ──────────

/// An insertion attempt: a segment whose IPv4 total length is 0 (less
/// than its own header) is dropped by the receiver, so it must not
/// take the place of the real bytes in the reassembled stream.
#[test]
fn ipv4_total_len_below_header_is_not_inserted() {
    let mut frames = flow(&[(0, b"GOOD".to_vec())]);
    let mut evil = ipv4_tcp(M, M, C, S, CP, SP, CISN + 1, SISN + 1, PSH | ACK, b"EVIL");
    evil[16..18].copy_from_slice(&0u16.to_be_bytes());
    frames.insert(3, (ts_ms(1_002), evil));
    let mut d = collector();
    let mut out = Events::new();
    for (t, f) in &frames {
        d.track_into(PacketView::new(f, *t).with_wire_len(f.len()), &mut out);
    }
    d.finish_into(&mut out);
    let data: Vec<u8> = pieces(&out)
        .into_iter()
        .filter_map(|p| match p {
            Piece::Data(FlowSide::Initiator, b) => Some(b),
            _ => None,
        })
        .flatten()
        .collect();
    assert_eq!(data, b"GOOD");
}

/// A complete datagram whose UDP length claims more than its IP payload
/// (or less than its own header) is malformed: receivers drop it, so
/// datagram parsers must not see it (forged DNS answers).
#[test]
fn udp_length_beyond_the_ip_payload_is_not_parsed() {
    for udp_len in [900u16, 5] {
        let mut f = ipv4_udp(S, C, 53, 5000, &[0x42; 40]);
        f[14 + 20 + 4..14 + 20 + 6].copy_from_slice(&udp_len.to_be_bytes());
        let parser = Lengths::default();
        let seen = parser.seen.clone();
        let mut d = DatagramDriver::new(FiveTuple::bidirectional(), TemplateFactory(parser));
        let mut out = Vec::new();
        d.track_into(
            PacketView::new(&f, ts_ms(1)).with_wire_len(f.len()),
            &mut out,
        );
        d.finish_into(&mut out);
        assert!(
            seen.lock().unwrap().is_empty(),
            "UDP length {udp_len}: {:?}",
            seen.lock().unwrap()
        );
    }
}

/// IP octets never exceed the wire length: a forged total length on a
/// cut frame (the source reported 1514 bytes on the wire, 96 captured)
/// cannot inflate them past what the source says was there.
#[test]
fn ip_bytes_are_bounded_by_the_wire_length() {
    use flowscope::{FlowEvent, FlowTracker};
    let mut f = ipv4_tcp(
        M,
        M,
        C,
        S,
        CP,
        SP,
        CISN + 1,
        SISN + 1,
        PSH | ACK,
        &[b'x'; 1460],
    );
    f[16..18].copy_from_slice(&65_535u16.to_be_bytes());
    f.truncate(96);
    let mut tracker: FlowTracker<FiveTuple> = FlowTracker::new(FiveTuple::bidirectional());
    tracker.track(PacketView::new(&f, ts_ms(1)).with_wire_len(1514));
    let stats = tracker
        .finish()
        .into_iter()
        .find_map(|e| match e {
            FlowEvent::Ended { stats, .. } => Some(stats),
            _ => None,
        })
        .expect("Ended");
    assert_eq!(stats.bytes_initiator, 1514);
    assert!(
        stats.ip_bytes_initiator <= stats.bytes_initiator,
        "ip_bytes {} > bytes {}",
        stats.ip_bytes_initiator,
        stats.bytes_initiator
    );
}

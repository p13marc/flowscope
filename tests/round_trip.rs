//! Cross-source round-trip CI fixture for flowscope.
//!
//! Synthesises wire bytes via `test_frames`, writes them to an
//! in-memory pcap, reads them back via `PcapFlowSource`, drives a
//! passthrough plan-121 typed `Driver<E>`, and asserts the bytes
//! round-trip verbatim. Catches integration regressions across the
//! synthesize → pcap → tracker → reassembler → session-driver seam.
//!
//! Originally specified by plan 52 (now retired; see
//! the `plan 52:` commits in `git log` for context).

#![cfg(all(
    feature = "pcap",
    feature = "session",
    feature = "reassembler",
    feature = "extractors",
    feature = "test-helpers"
))]

use std::{io::Cursor, time::Duration};

use flowscope::{
    driver::{Driver, Event, SlotMessage},
    extract::{parse::test_frames::ipv4_tcp, FiveTuple, FiveTupleKey},
    pcap::PcapFlowSource,
    FlowSide, SessionParser, Timestamp,
};
use pcap_file::{
    pcap::{PcapHeader, PcapPacket, PcapWriter},
    DataLink,
};

/// Passthrough parser: yields one Vec<u8> per fed chunk, tagged with
/// the side. The full byte stream is recovered by concatenating the
/// payloads in event-order.
#[derive(Default, Clone)]
struct PassthroughParser;

impl SessionParser for PassthroughParser {
    type Message = (FlowSide, Vec<u8>);
    fn feed_initiator(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<Self::Message>) {
        out.push((FlowSide::Initiator, bytes.to_vec()));
    }
    fn feed_responder(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<Self::Message>) {
        out.push((FlowSide::Responder, bytes.to_vec()));
    }
}

/// Write an in-memory pcap containing the frames given. Returns the
/// pcap bytes.
fn write_pcap(frames: &[(Duration, Vec<u8>)]) -> Vec<u8> {
    let header = PcapHeader {
        version_major: 2,
        version_minor: 4,
        ts_correction: 0,
        ts_accuracy: 0,
        snaplen: 65535,
        datalink: DataLink::ETHERNET,
        ts_resolution: pcap_file::TsResolution::MicroSecond,
        endianness: pcap_file::Endianness::native(),
    };
    let mut out: Vec<u8> = Vec::new();
    {
        let mut w = PcapWriter::with_header(&mut out, header).expect("writer");
        for (ts, data) in frames {
            w.write_packet(&PcapPacket {
                timestamp: *ts,
                orig_len: data.len() as u32,
                data: data.as_slice().into(),
            })
            .expect("write_packet");
        }
    }
    out
}

/// Drive a passthrough session-stream over the given pcap bytes and
/// return the per-side byte concatenations.
fn round_trip_via_pcap(frames: Vec<(Duration, Vec<u8>)>) -> (Vec<u8>, Vec<u8>) {
    let pcap_bytes = write_pcap(&frames);

    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut slot = builder.session_broadcast(PassthroughParser);
    let mut driver = builder.build();

    let mut init = Vec::new();
    let mut resp = Vec::new();
    let cursor = Cursor::new(pcap_bytes);

    let mut events: Vec<Event<FiveTupleKey>> = Vec::new();
    let mut msgs: Vec<SlotMessage<(FlowSide, Vec<u8>), FiveTupleKey>> = Vec::new();

    for view in PcapFlowSource::from_reader(cursor)
        .expect("open pcap")
        .views()
    {
        let view = view.expect("packet");
        events.clear();
        driver.track_into(&view, &mut events);
        msgs.clear();
        slot.drain(&mut msgs);
        for m in msgs.drain(..) {
            let (side, bytes) = m.message;
            match side {
                FlowSide::Initiator => init.extend_from_slice(&bytes),
                FlowSide::Responder => resp.extend_from_slice(&bytes),
            }
        }
    }
    (init, resp)
}

/// Build a deterministic 3WHS + data-segments + RST sequence given
/// per-direction payload chunks. Returns the frames with monotonically
/// increasing timestamps starting at 1 second so saturating_sub
/// stays well-defined.
fn build_session(payloads: &[(&[u8], &[u8])]) -> Vec<(Duration, Vec<u8>)> {
    let mac = [0u8; 6];
    let ip_a = [10, 0, 0, 1];
    let ip_b = [10, 0, 0, 2];
    let port_a: u16 = 1234;
    let port_b: u16 = 80;

    let mut frames = Vec::new();
    let mut t = Duration::from_secs(1);
    let tick = |t: &mut Duration| {
        *t += Duration::from_millis(1);
        *t
    };

    // 3WHS
    frames.push((
        tick(&mut t),
        ipv4_tcp(mac, mac, ip_a, ip_b, port_a, port_b, 1000, 0, 0x02, b""),
    ));
    frames.push((
        tick(&mut t),
        ipv4_tcp(mac, mac, ip_b, ip_a, port_b, port_a, 5000, 1001, 0x12, b""),
    ));
    frames.push((
        tick(&mut t),
        ipv4_tcp(mac, mac, ip_a, ip_b, port_a, port_b, 1001, 5001, 0x10, b""),
    ));

    // Data segments. seqs advance with the cumulative bytes sent
    // per side.
    let mut init_seq = 1001u32;
    let mut resp_seq = 5001u32;
    for (init_chunk, resp_chunk) in payloads {
        if !init_chunk.is_empty() {
            frames.push((
                tick(&mut t),
                ipv4_tcp(
                    mac, mac, ip_a, ip_b, port_a, port_b, init_seq, resp_seq, 0x18, init_chunk,
                ),
            ));
            init_seq = init_seq.wrapping_add(init_chunk.len() as u32);
        }
        if !resp_chunk.is_empty() {
            frames.push((
                tick(&mut t),
                ipv4_tcp(
                    mac, mac, ip_b, ip_a, port_b, port_a, resp_seq, init_seq, 0x18, resp_chunk,
                ),
            ));
            resp_seq = resp_seq.wrapping_add(resp_chunk.len() as u32);
        }
    }

    // RST to close the flow.
    frames.push((
        tick(&mut t),
        ipv4_tcp(
            mac, mac, ip_a, ip_b, port_a, port_b, init_seq, resp_seq, 0x04, b"",
        ),
    ));
    frames
}

#[test]
fn passthrough_single_segment_round_trip() {
    let init = b"GET /test HTTP/1.0\r\n\r\n".to_vec();
    let resp = b"HTTP/1.0 200 OK\r\n\r\nbody".to_vec();
    let frames = build_session(&[(init.as_slice(), resp.as_slice())]);
    let (init_seen, resp_seen) = round_trip_via_pcap(frames);
    assert_eq!(init_seen, init);
    assert_eq!(resp_seen, resp);
}

#[test]
fn passthrough_chunked_round_trip() {
    // 5 segments of varying size in-order; verifies reassembler
    // concatenation order.
    let payloads: &[(&[u8], &[u8])] = &[
        (b"chunk1-", b""),
        (b"chunk2-", b""),
        (b"chunk3-end", b"resp-"),
        (b"", b"payload-"),
        (b"", b"end"),
    ];
    let frames = build_session(payloads);
    let (init, resp) = round_trip_via_pcap(frames);
    assert_eq!(init, b"chunk1-chunk2-chunk3-end".to_vec());
    assert_eq!(resp, b"resp-payload-end".to_vec());
}

#[test]
fn passthrough_interleaved_round_trip() {
    let payloads: &[(&[u8], &[u8])] = &[
        (b"i1", b""),
        (b"", b"r1"),
        (b"i2", b""),
        (b"", b"r2"),
        (b"i3", b""),
        (b"", b"r3"),
    ];
    let frames = build_session(payloads);
    let (init, resp) = round_trip_via_pcap(frames);
    assert_eq!(init, b"i1i2i3".to_vec());
    assert_eq!(resp, b"r1r2r3".to_vec());
}

mod proptest_round_trip {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Random bidirectional session round-trip. Catches edge
        /// cases the three hand-written variants miss (single-byte
        /// segments, near-MTU sizes, asymmetric volumes).
        #[test]
        fn random_bidirectional_session(
            init_chunks in proptest::collection::vec(
                proptest::collection::vec(any::<u8>(), 0..256), 0..8),
            resp_chunks in proptest::collection::vec(
                proptest::collection::vec(any::<u8>(), 0..256), 0..8),
        ) {
            let n = init_chunks.len().max(resp_chunks.len());
            let mut payloads: Vec<(&[u8], &[u8])> = Vec::with_capacity(n);
            for i in 0..n {
                let ic: &[u8] = init_chunks.get(i).map(Vec::as_slice).unwrap_or(b"");
                let rc: &[u8] = resp_chunks.get(i).map(Vec::as_slice).unwrap_or(b"");
                payloads.push((ic, rc));
            }
            let frames = build_session(&payloads);
            let (init, resp) = round_trip_via_pcap(frames);
            let init_expected: Vec<u8> =
                init_chunks.iter().flatten().copied().collect();
            let resp_expected: Vec<u8> =
                resp_chunks.iter().flatten().copied().collect();
            prop_assert_eq!(init, init_expected);
            prop_assert_eq!(resp, resp_expected);
        }
    }
}

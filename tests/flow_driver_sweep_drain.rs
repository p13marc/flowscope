//! `FlowDriver::sweep_pending_drain` hands over what a sweep released:
//! data parked behind a lost segment reaches the caller at the sweep
//! that skips the hole, not at the side's next packet.

#![cfg(all(
    feature = "extractors",
    feature = "reassembler",
    feature = "test-helpers"
))]

use flowscope::extract::FiveTuple;
use flowscope::extract::parse::test_frames::ipv4_tcp;
use flowscope::{
    Chunk, FlowDriver, FlowEvent, FlowSide, PacketView, SegmentBufferReassemblerFactory,
    StreamChunks, Timestamp,
};

#[test]
fn sweep_releases_data_behind_an_expired_hole() {
    let (c, s, m) = ([10, 0, 0, 1], [10, 0, 0, 2], [0u8; 6]);
    let mut d = FlowDriver::new(
        FiveTuple::bidirectional(),
        SegmentBufferReassemblerFactory::default(),
    );
    let t = |ms: u32| Timestamp::new(1 + ms / 1000, (ms % 1000) * 1_000_000);
    let frames = [
        ipv4_tcp(m, m, c, s, 40000, 80, 100, 0, 0x02, b""),
        ipv4_tcp(m, m, s, c, 80, 40000, 900, 101, 0x12, b""),
        ipv4_tcp(m, m, c, s, 40000, 80, 101, 901, 0x10, b""),
        // 101..105 ("lost") never arrives; two later segments wait.
        ipv4_tcp(m, m, c, s, 40000, 80, 105, 901, 0x18, b"bbbb"),
        ipv4_tcp(m, m, c, s, 40000, 80, 109, 901, 0x18, b"cccc"),
    ];
    let mut out = StreamChunks::new();
    for (i, f) in frames.iter().enumerate() {
        let mut evs = d.track_pending(PacketView::new(f, t(i as u32)));
        let key = d.last_packet().unwrap().key;
        out.clear();
        d.drain_stream(&key, FlowSide::Initiator, &mut out);
        assert!(out.data().is_empty(), "nothing in order yet");
        d.finalize(&mut evs);
    }

    let mut released = Vec::new();
    let mut buf = StreamChunks::new();
    let mut evs = d.sweep_pending_drain(t(10_000), &mut buf, |key, side, chunks| {
        let parts: Vec<String> = chunks
            .iter()
            .map(|c| match c {
                Chunk::Data(b) => String::from_utf8_lossy(b).into_owned(),
                Chunk::Gap(n) => format!("<gap {n}>"),
            })
            .collect();
        released.push((*key, side, parts.concat()));
    });
    assert_eq!(released.len(), 1, "{released:?}");
    assert_eq!(released[0].1, FlowSide::Initiator);
    assert_eq!(released[0].2, "<gap 4>bbbbcccc");
    assert!(
        !evs.iter().any(|e| matches!(e, FlowEvent::Ended { .. })),
        "the flow is not idle yet"
    );
    d.finalize(&mut evs);

    // A quiet second sweep has nothing more to hand over.
    let mut again = 0;
    let mut evs = d.sweep_pending_drain(t(10_500), &mut buf, |_, _, _| again += 1);
    d.finalize(&mut evs);
    assert_eq!(again, 0);
}

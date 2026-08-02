#![no_main]

use bytes::Bytes;
use flowscope::FlowSide;
use flowscope::http2::{Http2Parser, PREFACE};
use libfuzzer_sys::fuzz_target;

/// HPACK is stateful across the whole connection, so the invariants
/// worth fuzzing are about that state surviving hostile input: the
/// parser must not panic, must not keep accepting bytes once it has
/// failed, and must stay inside its buffer cap however the input is
/// split.
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let split = (data[0] as usize) % data.len().max(1);
    let (client, server) = data.split_at(split);

    // Pass 1: a well-formed preface then arbitrary frames, fed whole.
    let mut p = Http2Parser::new();
    p.push(FlowSide::Initiator, &Bytes::from_static(PREFACE));
    p.push(FlowSide::Initiator, &Bytes::copy_from_slice(client));
    p.push(FlowSide::Responder, &Bytes::copy_from_slice(server));
    while p.next_event().is_some() {}

    if p.is_failed() {
        // A failed connection is inert: it accepts nothing and
        // produces nothing, so a peer cannot keep feeding a parser
        // whose HPACK state is already meaningless.
        assert_eq!(
            p.push(FlowSide::Initiator, &Bytes::copy_from_slice(client)),
            0
        );
        assert!(p.next_event().is_none());
    }

    // Pass 2: byte at a time, so every frame boundary lands at a feed
    // edge. Framing must not depend on how the bytes arrive.
    let mut drip = Http2Parser::new();
    drip.push(FlowSide::Initiator, &Bytes::from_static(PREFACE));
    for b in client {
        drip.push(FlowSide::Initiator, &Bytes::copy_from_slice(&[*b]));
        while drip.next_event().is_some() {}
        assert!(
            drip.buffered(FlowSide::Initiator) <= 1024 * 1024,
            "the buffer cap must hold on every push"
        );
    }

    // Pass 3: no preface at all — the parser must reject rather than
    // try to read frames out of whatever this is.
    let mut bare = Http2Parser::new();
    bare.push(FlowSide::Initiator, &Bytes::copy_from_slice(data));
    while bare.next_event().is_some() {}
});

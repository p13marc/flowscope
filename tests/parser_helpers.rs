//! Plan 106 — parser ergonomics: coverage for
//! [`flowscope::AccumulatingSessionParser`],
//! [`flowscope::BufferedFrameDrain`], and
//! [`flowscope::PerDatagramParser`].

#![cfg(feature = "session")]

use flowscope::{
    AccumulatingSessionParser, BufferedFrameDrain, DatagramParser, FlowSide, FrameDrainError,
    PerDatagramParser, SessionParser, Timestamp,
};

/// Toy line-based protocol: each message is a `\n`-terminated
/// UTF-8 string (the prefix without the `\n` becomes the message).
fn parse_one_line(buf: &[u8]) -> Option<(String, usize)> {
    let nl = buf.iter().position(|&b| b == b'\n')?;
    let s = String::from_utf8_lossy(&buf[..nl]).into_owned();
    Some((s, nl + 1))
}

// ── BufferedFrameDrain ─────────────────────────────────────────────

#[test]
fn drain_emits_complete_messages() {
    let mut drain: BufferedFrameDrain<String> = BufferedFrameDrain::new();
    drain.extend(b"hello\nworld\n").unwrap();
    drain.drain_with(parse_one_line);
    let out = drain.take_messages();
    assert_eq!(out, vec!["hello".to_string(), "world".to_string()]);
    assert_eq!(drain.buffered_len(), 0);
}

#[test]
fn drain_retains_partial_message() {
    let mut drain: BufferedFrameDrain<String> = BufferedFrameDrain::new();
    drain.extend(b"hello\nwo").unwrap();
    drain.drain_with(parse_one_line);
    assert_eq!(drain.take_messages(), vec!["hello".to_string()]);
    // Continue: feeding the rest emits the second message.
    drain.extend(b"rld\n").unwrap();
    drain.drain_with(parse_one_line);
    assert_eq!(drain.take_messages(), vec!["world".to_string()]);
}

#[test]
fn extend_past_max_buffer_poisons() {
    let mut drain: BufferedFrameDrain<String> = BufferedFrameDrain::with_max_buffer(4);
    let err = drain.extend(b"hello world").unwrap_err();
    assert_eq!(err, FrameDrainError::BufferFull);
    assert!(drain.is_poisoned());
    // Second extend after poison is a no-op (returns same err).
    let err2 = drain.extend(b"more").unwrap_err();
    assert_eq!(err2, FrameDrainError::BufferFull);
}

#[test]
fn zero_byte_advance_poisons() {
    let mut drain: BufferedFrameDrain<&'static str> = BufferedFrameDrain::new();
    drain.extend(b"abc").unwrap();
    // Pathological closure that returns Some(_, 0) → poison.
    drain.drain_with(|_| Some(("zero", 0)));
    assert!(drain.is_poisoned());
    assert_eq!(
        drain.poison_reason(),
        Some(&FrameDrainError::ZeroByteAdvance)
    );
    // One message was still recorded before the poison flag tripped.
    assert_eq!(drain.take_messages(), vec!["zero"]);
}

// ── AccumulatingSessionParser ──────────────────────────────────────

#[test]
fn accumulating_parser_emits_per_side() {
    let mut parser =
        AccumulatingSessionParser::new(flowscope::ParserKind::Other("line"), parse_one_line);
    let mut msgs = Vec::new();
    parser.feed_initiator(b"GET /\nPOST /\n", Timestamp::default(), &mut msgs);
    assert_eq!(msgs, vec!["GET /".to_string(), "POST /".to_string()]);
    msgs.clear();
    parser.feed_responder(b"200 OK\n", Timestamp::default(), &mut msgs);
    assert_eq!(msgs, vec!["200 OK".to_string()]);
}

#[test]
fn accumulating_parser_buffers_partial_messages() {
    let mut parser =
        AccumulatingSessionParser::new(flowscope::ParserKind::Other("line"), parse_one_line);
    let mut msgs = Vec::new();
    parser.feed_initiator(b"GET /", Timestamp::default(), &mut msgs);
    assert!(msgs.is_empty());
    parser.feed_initiator(b" HTTP/1.1\n", Timestamp::default(), &mut msgs);
    assert_eq!(msgs, vec!["GET / HTTP/1.1".to_string()]);
}

#[test]
fn accumulating_parser_poisons_on_overflow() {
    let mut parser = AccumulatingSessionParser::with_max_buffer(
        flowscope::ParserKind::Other("line"),
        parse_one_line,
        4,
    );
    let mut sink = Vec::new();
    parser.feed_initiator(b"hello world\n", Timestamp::default(), &mut sink);
    assert!(parser.is_poisoned());
    assert!(parser.poison_reason().is_some());
}

#[test]
fn accumulating_parser_kind_label_is_threaded_through() {
    let parser =
        AccumulatingSessionParser::new(flowscope::ParserKind::Other("my-protocol"), parse_one_line);
    assert_eq!(parser.parser_kind().as_str(), "my-protocol");
}

#[test]
fn accumulating_parser_clones_with_fresh_state() {
    let mut a = AccumulatingSessionParser::with_max_buffer(
        flowscope::ParserKind::Other("line"),
        parse_one_line,
        32,
    );
    let mut sink = Vec::new();
    a.feed_initiator(b"hello\n", Timestamp::default(), &mut sink);
    let mut b = a.clone();
    // Clone has its own buffer — feeding to b doesn't see "hello".
    let mut msgs = Vec::new();
    b.feed_initiator(b"world\n", Timestamp::default(), &mut msgs);
    assert_eq!(msgs, vec!["world".to_string()]);
    assert!(!b.is_poisoned());
}

// ── PerDatagramParser ──────────────────────────────────────────────

#[test]
fn per_datagram_parser_emits_one_per_packet() {
    let mut parser = PerDatagramParser::new(flowscope::ParserKind::Other("len"), |b: &[u8]| {
        if b.is_empty() { None } else { Some(b.len()) }
    });
    let mut msgs = Vec::new();
    parser.parse(
        b"hello",
        FlowSide::Initiator,
        Timestamp::default(),
        &mut msgs,
    );
    assert_eq!(msgs, vec![5]);
    msgs.clear();
    parser.parse(b"", FlowSide::Initiator, Timestamp::default(), &mut msgs);
    assert!(msgs.is_empty());
}

#[test]
fn per_datagram_parser_threads_kind_label() {
    let parser = PerDatagramParser::new(flowscope::ParserKind::Other("len"), |_b: &[u8]| Some(()));
    assert_eq!(parser.parser_kind().as_str(), "len");
}

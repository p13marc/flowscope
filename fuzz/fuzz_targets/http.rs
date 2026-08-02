#![no_main]

use flowscope::Timestamp;
use flowscope::http::{HttpConfig, HttpMessage, HttpParser};
use flowscope::session::SessionParser;
use libfuzzer_sys::fuzz_target;

// Split the input at a fuzzer-chosen offset so the request /
// response framing crosses a feed boundary — exercises the
// chunked-body and Content-Length partial-buffering paths.
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let split = (data[0] as usize) % data.len().max(1);
    let (req, resp) = data.split_at(split);

    // Pass 1: passive-telemetry parser (flag off — default).
    let mut parser = HttpParser::default();
    let mut out = Vec::new();
    parser.feed_initiator(req, Timestamp::default(), &mut out);
    parser.feed_responder(resp, Timestamp::default(), &mut out);

    // Pass 2: inline-streaming parser. Same bytes, byte-at-a-time on
    // the initiator side so header/body boundaries land at every
    // offset. Invariant: the parser never panics, and inline mode
    // never emits a full `Request` (only `RequestHead`) — the body is
    // never buffered into a message.
    let mut cfg = HttpConfig::default();
    cfg.inline_streaming = true;
    let mut inline = HttpParser::with_config(cfg);
    let mut msgs = Vec::new();
    for b in req {
        inline.feed_initiator(std::slice::from_ref(b), Timestamp::default(), &mut msgs);
    }
    inline.feed_responder(resp, Timestamp::default(), &mut msgs);
    assert!(
        !msgs.iter().any(|m| matches!(m, HttpMessage::Request(_))),
        "inline mode must not emit a full Request"
    );
});

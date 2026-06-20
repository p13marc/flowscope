#![no_main]

use flowscope::Timestamp;
use flowscope::http::HttpParser;
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
    let mut parser = HttpParser::default();
    let mut out = Vec::new();
    parser.feed_initiator(req, Timestamp::default(), &mut out);
    parser.feed_responder(resp, Timestamp::default(), &mut out);
});

#![no_main]

use flowscope::Timestamp;
use flowscope::dns::DnsTcpParser;
use flowscope::session::SessionParser;
use libfuzzer_sys::fuzz_target;

// Split the input into two halves at a fuzzer-chosen offset so
// we exercise the RFC-1035 2-byte length framing across feed
// boundaries — the most likely place for state-machine bugs.
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let split = (data[0] as usize) % data.len().max(1);
    let (a, b) = data.split_at(split);
    let mut parser = DnsTcpParser::default();
    let mut out = Vec::new();
    parser.feed_initiator(a, Timestamp::default(), &mut out);
    parser.feed_responder(b, Timestamp::default(), &mut out);
});

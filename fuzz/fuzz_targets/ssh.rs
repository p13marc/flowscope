#![no_main]

use flowscope::ssh::SshParser;
use flowscope::session::SessionParser;
use flowscope::Timestamp;
use libfuzzer_sys::fuzz_target;

// Split at a fuzzer-chosen offset so the banner / binary-packet
// state machine sees content across feed boundaries.
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let split = (data[0] as usize) % data.len().max(1);
    let (init, resp) = data.split_at(split);
    let mut parser = SshParser::new();
    let mut out = Vec::new();
    parser.feed_initiator(init, Timestamp::default(), &mut out);
    parser.feed_responder(resp, Timestamp::default(), &mut out);
});

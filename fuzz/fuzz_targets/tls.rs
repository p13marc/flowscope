#![no_main]

use flowscope::Timestamp;
use flowscope::session::SessionParser;
use flowscope::tls::TlsParser;
use libfuzzer_sys::fuzz_target;

// Split at a fuzzer-chosen offset and feed across the boundary
// so record-framing assembly is exercised.
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let split = (data[0] as usize) % data.len().max(1);
    let (ch, sh) = data.split_at(split);
    let mut parser = TlsParser::default();
    let mut out = Vec::new();
    parser.feed_initiator(ch, Timestamp::default(), &mut out);
    parser.feed_responder(sh, Timestamp::default(), &mut out);
});

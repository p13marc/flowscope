#![no_main]

use flowscope::Timestamp;
use flowscope::session::SessionParser;
use flowscope::tls::TlsHandshakeParser;
use libfuzzer_sys::fuzz_target;

// The handshake aggregator wraps TlsParser + correlates
// ClientHello + ServerHello + Alert. State-machine bugs there
// won't be caught by the per-message TLS fuzz target.
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let split = (data[0] as usize) % data.len().max(1);
    let (ch, sh) = data.split_at(split);
    let mut parser = TlsHandshakeParser::default();
    let mut out = Vec::new();
    parser.feed_initiator(ch, Timestamp::default(), &mut out);
    parser.feed_responder(sh, Timestamp::default(), &mut out);
    parser.fin_initiator(&mut out);
    parser.fin_responder(&mut out);
});

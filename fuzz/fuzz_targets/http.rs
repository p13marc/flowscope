#![no_main]

use flowscope::Timestamp;
use flowscope::http::{HttpMessage, HttpParser};
use flowscope::session::SessionParser;
use libfuzzer_sys::fuzz_target;

/// Bodies decoded from whatever messages a pass produced.
fn bodies(msgs: &[HttpMessage]) -> Vec<Vec<u8>> {
    msgs.iter()
        .map(|m| match m {
            HttpMessage::Request(r) => r.body.to_vec(),
            HttpMessage::Response(r) => r.body.to_vec(),
            _ => Vec::new(),
        })
        .collect()
}

// Split the input at a fuzzer-chosen offset so request / response
// framing crosses a feed boundary — exercises the chunked-body and
// Content-Length partial-buffering paths.
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let split = (data[0] as usize) % data.len().max(1);
    let (req, resp) = data.split_at(split);

    // Pass 1: one feed per direction.
    let mut whole = HttpParser::default();
    let mut one_shot = Vec::new();
    whole.feed_initiator(req, Timestamp::default(), &mut one_shot);
    whole.feed_responder(resp, Timestamp::default(), &mut one_shot);

    // Pass 2: byte-at-a-time on both directions, so every header,
    // chunk-size, and body boundary lands at a feed edge. Splitting
    // the input differently must not change what the engine frames.
    let mut drip = HttpParser::default();
    let mut dripped = Vec::new();
    for b in req {
        drip.feed_initiator(std::slice::from_ref(b), Timestamp::default(), &mut dripped);
    }
    for b in resp {
        drip.feed_responder(std::slice::from_ref(b), Timestamp::default(), &mut dripped);
    }
    assert_eq!(
        bodies(&one_shot),
        bodies(&dripped),
        "framing must not depend on feed boundaries"
    );

    // Pass 3: end of stream. A FIN must never panic, and must never
    // report the parser as poisoned — a close on an idle keep-alive
    // connection is normal, not a framing failure.
    let mut sink = Vec::new();
    drip.fin_initiator(&mut sink);
    drip.fin_responder(&mut sink);
    assert!(
        !drip.is_poisoned(),
        "the telemetry front-end never poisons a flow"
    );
});

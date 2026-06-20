#![no_main]

use flowscope::Timestamp;
use flowscope::event::FlowSide;
use flowscope::icmp::IcmpParser;
use flowscope::session::DatagramParser;
use libfuzzer_sys::fuzz_target;

// ICMP parser dispatches on the IP version of the carrier; the
// raw bytes determine which code path runs (no caller-supplied
// version selector).
fuzz_target!(|data: &[u8]| {
    let mut parser = IcmpParser::new();
    let mut out = Vec::new();
    parser.parse(data, FlowSide::Initiator, Timestamp::default(), &mut out);
});

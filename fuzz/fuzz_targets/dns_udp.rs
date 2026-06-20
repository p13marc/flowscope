#![no_main]

use flowscope::Timestamp;
use flowscope::dns::DnsUdpParser;
use flowscope::event::FlowSide;
use flowscope::session::DatagramParser;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let mut parser = DnsUdpParser::default();
    let mut out = Vec::new();
    parser.parse(data, FlowSide::Initiator, Timestamp::default(), &mut out);
});

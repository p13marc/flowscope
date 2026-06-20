#![no_main]

use flowscope::ndp;
use libfuzzer_sys::fuzz_target;

// NDP NS / NA option-walker is the main attack surface — the
// fuzzer needs to be able to drive any ICMPv6 type byte, so we
// take the type from the first input byte and feed the rest as
// the message body.
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let (ty, body) = data.split_first().unwrap();
    let _ = ndp::parse(*ty, body);
    let _ = ndp::parse_icmpv6(data);
});

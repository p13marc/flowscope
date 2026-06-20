#![no_main]

use flowscope::cdp;
use libfuzzer_sys::fuzz_target;

// CDP TLV walker + address-block walker are the principal
// attack surface — anyone on the L2 segment can craft frames
// to 01:00:0c:cc:cc:cc.
fuzz_target!(|data: &[u8]| {
    let _ = cdp::parse(data);
    let _ = cdp::parse_frame(data);
});

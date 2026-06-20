#![no_main]

use flowscope::dhcp;
use libfuzzer_sys::fuzz_target;

// Drives the BOOTP header + option-walker against arbitrary
// bytes. The option walker is the principal attack surface;
// the BOOTP fixed header has only fixed-offset reads.
fuzz_target!(|data: &[u8]| {
    let _ = dhcp::parse(data);
});

#![no_main]

use flowscope::tftp;
use libfuzzer_sys::fuzz_target;

// String walker + opcode dispatch is the principal attack
// surface — drive it with arbitrary bytes and also probe the
// derived predicate path.
fuzz_target!(|data: &[u8]| {
    if let Ok(m) = tftp::parse(data) {
        let _ = m.is_device_config_transfer();
    }
});

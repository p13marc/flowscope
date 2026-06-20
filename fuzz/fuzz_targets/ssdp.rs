#![no_main]

use flowscope::ssdp;
use libfuzzer_sys::fuzz_target;

// Header walker over text input is the principal attack
// surface — drive it with arbitrary bytes.
fuzz_target!(|data: &[u8]| {
    if let Some(m) = ssdp::parse(data) {
        let _ = m.is_alive();
        let _ = m.is_byebye();
    }
});

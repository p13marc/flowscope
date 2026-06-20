#![no_main]

use flowscope::ntp;
use libfuzzer_sys::fuzz_target;

// Fixed-shape header — fuzz the field-decoder + the
// `is_amplification_risk` predicate path.
fuzz_target!(|data: &[u8]| {
    if let Some(m) = ntp::parse(data) {
        let _ = m.is_amplification_risk();
        let _ = m.ref_id_as_ipv4();
        let _ = m.ref_id_as_str();
        let _ = m.transmit_timestamp.to_unix_f64();
    }
});

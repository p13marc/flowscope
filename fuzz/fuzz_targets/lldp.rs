#![no_main]

use flowscope::lldp;
use libfuzzer_sys::fuzz_target;

// LLDP TLV walker is the principal attack surface — anyone on
// the L2 segment can craft arbitrary LLDPDUs. Drive both
// entries: the raw LLDPDU and the full-frame path (which
// includes the dst-MAC validation + VLAN-tag stripping).
fuzz_target!(|data: &[u8]| {
    let _ = lldp::parse(data);
    let _ = lldp::parse_frame(data);
});

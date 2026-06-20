#![no_main]

use flowscope::layers::Layers;
use libfuzzer_sys::fuzz_target;

// The per-packet layered view: etherparse-based eth/ip/transport
// decode + tunnel walk + MPLS inner-IP re-parse + IPv6 ext
// chain. Widest input surface in the crate.
//
// The fuzzer's first byte chooses the parse entry — Ethernet
// or raw IP — since both shapes need coverage and the bytes
// after are otherwise identical.
fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let (mode, frame) = data.split_first().unwrap();
    let layers = if mode & 1 == 0 {
        Layers::parse_ethernet(frame)
    } else {
        Layers::parse_ip(frame)
    };
    if let Ok(layers) = layers {
        let _ = layers.depth();
        let _ = layers.has_tunnel();
        let _ = layers.truncated();
        let _ = layers.has_ipv6_fragment();
        if let Some(ip6) = layers.ipv6() {
            let _ = ip6.extensions();
        }
    }
});

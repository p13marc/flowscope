//! The prefix-safety property for [`classify_first_bytes`].
//!
//! A router acts on this decision, so the dangerous failure is not
//! "did not recognise it" — it is "recognised it as the wrong thing
//! because the peek was short". The properties below pin that down:
//! a prefix must either wait or agree with the full answer, and a
//! decision must never change once made.

use flowscope::classify::{Classify, HTTP2_PREFACE, WireProtocol, classify_first_bytes};
use proptest::prelude::*;

/// Byte strings that look like plausible connection openings, mixing
/// real protocol prefixes with arbitrary noise.
fn opening() -> impl Strategy<Value = Vec<u8>> {
    let known: Vec<Vec<u8>> = vec![
        b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n".to_vec(),
        b"POST /a HTTP/1.1\r\n\r\n".to_vec(),
        b"CONNECT example.com:443 HTTP/1.1\r\n\r\n".to_vec(),
        b"OPTIONS * HTTP/1.1\r\n\r\n".to_vec(),
        HTTP2_PREFACE.to_vec(),
        b"SSH-2.0-OpenSSH_9.6\r\n".to_vec(),
        b"SSH-1.99-Cisco-1.25\r\n".to_vec(),
        vec![0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc],
        b"HELO mail.example.com\r\n".to_vec(),
        b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09".to_vec(),
    ];
    prop_oneof![
        proptest::sample::select(known),
        proptest::collection::vec(any::<u8>(), 0..40),
        // Deliberately adversarial: a real prefix with junk after it.
        (
            proptest::sample::select(vec![
                b"PRI * HTTP/2.0\r\n".to_vec(),
                b"SSH-".to_vec(),
                b"CONNEC".to_vec(),
                vec![0x16, 0x03],
            ]),
            proptest::collection::vec(any::<u8>(), 0..20)
        )
            .prop_map(|(mut head, tail)| {
                head.extend(tail);
                head
            }),
    ]
}

proptest! {
    /// Every prefix either waits or gives the same answer as the
    /// whole input. This is the property a router depends on.
    #[test]
    fn a_prefix_never_decides_differently(bytes in opening()) {
        let Classify::Decided(full) = classify_first_bytes(&bytes) else {
            // The whole input is still undecided; nothing to compare.
            return Ok(());
        };
        for n in 0..bytes.len() {
            if let Classify::Decided(partial) = classify_first_bytes(&bytes[..n]) {
                prop_assert_eq!(
                    partial,
                    full,
                    "prefix of length {} decided {:?} but the full input is {:?}",
                    n,
                    partial,
                    full
                );
            }
        }
    }

    /// A decision is final: once the classifier commits, feeding more
    /// bytes cannot change its mind.
    #[test]
    fn a_decision_is_stable_under_more_bytes(
        bytes in opening(),
        extra in proptest::collection::vec(any::<u8>(), 0..32),
    ) {
        let Classify::Decided(before) = classify_first_bytes(&bytes) else {
            return Ok(());
        };
        // `Raw` is the "nothing matched" answer; appending bytes to a
        // buffer that already ruled everything out cannot revive a
        // match, so this holds for every variant including Raw.
        let mut longer = bytes.clone();
        longer.extend(&extra);
        prop_assert_eq!(classify_first_bytes(&longer), Classify::Decided(before));
    }

    /// Never panics, whatever arrives.
    #[test]
    fn never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = classify_first_bytes(&bytes);
    }

    /// The h2 preface is never mistaken for HTTP/1, at any prefix
    /// length. `PRI ` is a plausible method token, so this is the
    /// specific confusion worth pinning.
    #[test]
    fn h2_preface_is_never_read_as_http1(n in 1usize..=HTTP2_PREFACE.len()) {
        if let Classify::Decided(p) = classify_first_bytes(&HTTP2_PREFACE[..n]) {
            prop_assert_eq!(p, WireProtocol::Http2Preface);
        }
    }
}

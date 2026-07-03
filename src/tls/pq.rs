//! Post-quantum hybrid key-exchange group recognition (issue #135).
//!
//! Modern browsers negotiate a *hybrid* key exchange that combines
//! a classical curve (X25519 / P-256) with a post-quantum KEM
//! (ML-KEM, formerly Kyber). The PQ public value is ~1.1 KiB, which
//! pushes the ClientHello past a single TCP segment / QUIC Initial —
//! the motivating case for ClientHello reassembly. Recognising the
//! group codepoint turns "the CH is suspiciously large" into a
//! first-class, named signal.

/// `true` if `group` is a known post-quantum **hybrid**
/// key-exchange named group (IANA TLS Supported Groups).
///
/// Covers the deployed families as of 2026:
///
/// | Codepoint | Group | Notes |
/// |---|---|---|
/// | `0x11ec` | `X25519MLKEM768` | Chrome 131+ / Firefox default since late 2024 (final ML-KEM codepoint) |
/// | `0x11eb` | `SecP256r1MLKEM768` | P-256 hybrid |
/// | `0x11ed` | `SecP384r1MLKEM1024` | P-384 hybrid |
/// | `0x6399` | `X25519Kyber768Draft00` | pre-standard Chrome / Cloudflare rollout |
/// | `0x639a` | `SecP256r1Kyber768Draft00` | pre-standard P-256 hybrid |
/// | `0xfe30`–`0xfe3f` | OQS experimental hybrids | liboqs interop range |
///
/// Pure-PQ (non-hybrid) groups are intentionally excluded — no
/// browser ships them and their presence is a different signal.
pub fn is_pq_hybrid_group(group: u16) -> bool {
    matches!(
        group,
        0x11ec // X25519MLKEM768
        | 0x11eb // SecP256r1MLKEM768
        | 0x11ed // SecP384r1MLKEM1024
        | 0x6399 // X25519Kyber768Draft00
        | 0x639a // SecP256r1Kyber768Draft00
    ) || (0xfe30..=0xfe3f).contains(&group) // OQS experimental hybrids
}

/// Human-readable name for a known PQ hybrid group, or `None` if
/// `group` isn't a recognised PQ hybrid. Useful for logs / metric
/// labels.
pub fn pq_hybrid_group_name(group: u16) -> Option<&'static str> {
    Some(match group {
        0x11ec => "X25519MLKEM768",
        0x11eb => "SecP256r1MLKEM768",
        0x11ed => "SecP384r1MLKEM1024",
        0x6399 => "X25519Kyber768Draft00",
        0x639a => "SecP256r1Kyber768Draft00",
        g if (0xfe30..=0xfe3f).contains(&g) => "OQS-experimental-hybrid",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_mlkem_and_kyber() {
        assert!(is_pq_hybrid_group(0x11ec)); // X25519MLKEM768
        assert!(is_pq_hybrid_group(0x6399)); // X25519Kyber768Draft00
        assert!(is_pq_hybrid_group(0xfe31)); // OQS range
        assert_eq!(pq_hybrid_group_name(0x11ec), Some("X25519MLKEM768"));
    }

    #[test]
    fn rejects_classical_groups() {
        assert!(!is_pq_hybrid_group(0x001d)); // x25519
        assert!(!is_pq_hybrid_group(0x0017)); // secp256r1
        assert!(!is_pq_hybrid_group(0x0100)); // ffdhe2048
        assert_eq!(pq_hybrid_group_name(0x001d), None);
    }
}

//! `flowscope::detect` — lightweight detection primitives.
//!
//! A small, deliberately minimal toolkit of the half-dozen
//! detection primitives every detector example reinvents:
//!
//! - [`shannon_entropy`] — DNS tunnel detection, encoded-payload
//!   spotting.
//! - [`is_high_entropy`] — entropy-with-threshold convenience.
//! - [`ngram_distribution`] — frequency distribution for further
//!   analysis, with built-in [`NgramDist::mode`] /
//!   [`NgramDist::entropy`] /
//!   [`NgramDist::distinct`] queries.
//! - [`is_base64ish`] — base64-shaped string detection.
//! - [`is_hex_string`] — hex-shaped string detection.
//! - [`hamming_distance`] — fixed-length byte comparison.
//!
//! The module is deliberately small. Detection logic compounds
//! quickly; we ship the building blocks, not the whole tower.
//! Additions beyond these six require a consumer ask — file an
//! issue with the use case if you find yourself wanting more.
//!
//! New in 0.10.0 (plan 102 sub-C).
//!
//! ```
//! use flowscope::detect::{shannon_entropy, is_high_entropy, is_hex_string};
//!
//! // Empty / uniform byte streams have low entropy.
//! assert_eq!(shannon_entropy(b""), 0.0);
//! assert_eq!(shannon_entropy(b"AAAA"), 0.0);
//!
//! // Random / encrypted streams have high entropy.
//! let random: [u8; 256] = std::array::from_fn(|i| i as u8);
//! assert!(is_high_entropy(&random, 7.0));
//!
//! assert!(is_hex_string("deadbeefcafebabe"));
//! assert!(!is_hex_string("not hex"));
//! ```

pub mod signatures;

use std::collections::HashMap;

/// Shannon entropy in bits per byte. Returns `0.0` for empty
/// input. Range: `[0.0, 8.0]`.
///
/// A uniformly distributed byte stream returns 8.0 (max). A
/// stream of all-one-byte returns 0.0. Real text typically falls
/// in `[3.0, 5.0]`; compressed or encrypted streams cluster near
/// 7.5–8.0; base64 strings hover around 5.0–6.0.
pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut h = 0.0;
    for &c in &counts {
        if c > 0 {
            let p = c as f64 / len;
            h -= p * p.log2();
        }
    }
    h
}

/// `true` iff [`shannon_entropy`] over `bytes` is `>= threshold`.
/// Convenience over the common pattern.
pub fn is_high_entropy(bytes: &[u8], threshold: f64) -> bool {
    shannon_entropy(bytes) >= threshold
}

/// `true` iff every char in `s` is in the base64 alphabet
/// (`A-Z a-z 0-9 + / =`) AND `s.len() >= 16`. The length floor
/// guards against trivial short matches like `"abc"`.
pub fn is_base64ish(s: &str) -> bool {
    s.len() >= 16
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')
}

/// `true` iff every char in `s` is `[0-9a-fA-F]` AND
/// `s.len() >= 16`.
pub fn is_hex_string(s: &str) -> bool {
    s.len() >= 16 && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Hamming distance between two equal-length byte slices. Returns
/// `None` if the lengths differ. `O(n)`.
pub fn hamming_distance(a: &[u8], b: &[u8]) -> Option<usize> {
    if a.len() != b.len() {
        return None;
    }
    Some(a.iter().zip(b.iter()).filter(|(x, y)| x != y).count())
}

/// N-gram distribution over the input bytes.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct NgramDist {
    /// N-gram width.
    pub n: usize,
    /// Total n-grams emitted (i.e. `bytes.len().saturating_sub(n - 1)`
    /// when `n > 0`).
    pub samples: u64,
    /// Per-n-gram observation count.
    pub counts: HashMap<Vec<u8>, u64>,
}

impl NgramDist {
    /// The most-common n-gram + its count. `None` if no samples.
    pub fn mode(&self) -> Option<(&Vec<u8>, u64)> {
        self.counts.iter().max_by_key(|(_, c)| **c).map(|(k, v)| (k, *v))
    }

    /// Entropy of the n-gram distribution in bits per n-gram.
    /// `0.0` if no samples.
    pub fn entropy(&self) -> f64 {
        if self.samples == 0 {
            return 0.0;
        }
        let total = self.samples as f64;
        let mut h = 0.0;
        for &c in self.counts.values() {
            if c > 0 {
                let p = c as f64 / total;
                h -= p * p.log2();
            }
        }
        h
    }

    /// Number of distinct n-grams observed.
    pub fn distinct(&self) -> usize {
        self.counts.len()
    }
}

/// N-gram distribution of `bytes`. Returns an empty distribution
/// if `n == 0` or `bytes.len() < n`.
pub fn ngram_distribution(bytes: &[u8], n: usize) -> NgramDist {
    let mut counts: HashMap<Vec<u8>, u64> = HashMap::new();
    if n == 0 || bytes.len() < n {
        return NgramDist {
            n,
            samples: 0,
            counts,
        };
    }
    let mut samples = 0u64;
    for window in bytes.windows(n) {
        *counts.entry(window.to_vec()).or_insert(0) += 1;
        samples += 1;
    }
    NgramDist {
        n,
        samples,
        counts,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shannon_empty_is_zero() {
        assert_eq!(shannon_entropy(b""), 0.0);
    }

    #[test]
    fn shannon_uniform_is_zero() {
        assert_eq!(shannon_entropy(b"AAAA"), 0.0);
        assert_eq!(shannon_entropy(&[7u8; 100]), 0.0);
    }

    #[test]
    fn shannon_four_distinct_chars_is_two_bits() {
        // 4 distinct equiprobable chars → log2(4) = 2.0 bits/byte.
        let h = shannon_entropy(b"abcd");
        assert!((h - 2.0).abs() < 1e-9, "got {h}");
    }

    #[test]
    fn shannon_full_range_is_eight_bits() {
        let bytes: Vec<u8> = (0..=255).collect();
        let h = shannon_entropy(&bytes);
        assert!((h - 8.0).abs() < 1e-9, "got {h}");
    }

    #[test]
    fn is_high_entropy_matches_threshold() {
        let bytes: Vec<u8> = (0..=255).collect();
        assert!(is_high_entropy(&bytes, 7.0));
        assert!(!is_high_entropy(b"AAAA", 1.0));
    }

    #[test]
    fn is_base64ish_recognizes_base64_strings() {
        assert!(is_base64ish("dGhpcyBpcyBhIHRlc3Q="));
        assert!(is_base64ish("AAAA0000+/+/===="));
        // Too short.
        assert!(!is_base64ish("AAAA="));
        // Contains a forbidden char.
        assert!(!is_base64ish("AAAA0000+/+/===_"));
    }

    #[test]
    fn is_hex_string_recognizes_hex_strings() {
        assert!(is_hex_string("deadbeefcafebabe"));
        assert!(is_hex_string("DEADBEEFCAFEBABE"));
        assert!(is_hex_string("0123456789abcdef"));
        // Too short.
        assert!(!is_hex_string("deadbeef"));
        // Has a non-hex char.
        assert!(!is_hex_string("deadbeefcafe babe"));
    }

    #[test]
    fn hamming_returns_none_on_length_mismatch() {
        assert_eq!(hamming_distance(b"abc", b"abcd"), None);
    }

    #[test]
    fn hamming_counts_differing_bytes() {
        assert_eq!(hamming_distance(b"foo", b"foo"), Some(0));
        assert_eq!(hamming_distance(b"foo", b"fob"), Some(1));
        assert_eq!(hamming_distance(b"abc", b"xyz"), Some(3));
    }

    #[test]
    fn ngram_distribution_counts_windows() {
        let d = ngram_distribution(b"aaab", 2);
        assert_eq!(d.n, 2);
        assert_eq!(d.samples, 3);
        assert_eq!(d.counts[&b"aa".to_vec()], 2);
        assert_eq!(d.counts[&b"ab".to_vec()], 1);
        assert_eq!(d.distinct(), 2);
    }

    #[test]
    fn ngram_mode_returns_most_common() {
        let d = ngram_distribution(b"aaab", 2);
        let (gram, count) = d.mode().unwrap();
        assert_eq!(gram, &b"aa".to_vec());
        assert_eq!(count, 2);
    }

    #[test]
    fn ngram_distribution_empty_when_n_too_large() {
        let d = ngram_distribution(b"ab", 5);
        assert_eq!(d.samples, 0);
        assert!(d.counts.is_empty());
        assert_eq!(d.entropy(), 0.0);
        assert!(d.mode().is_none());
    }

    #[test]
    fn ngram_entropy_zero_for_uniform_pattern() {
        // All identical bigrams → entropy 0.
        let d = ngram_distribution(b"aaaaaa", 2);
        assert_eq!(d.entropy(), 0.0);
    }

    #[test]
    fn ngram_entropy_positive_for_mixed_pattern() {
        let d = ngram_distribution(b"abcdef", 2);
        assert!(d.entropy() > 0.0);
    }
}

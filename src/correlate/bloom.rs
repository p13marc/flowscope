//! [`BloomFilter`] — probabilistic "seen-before" membership.
//!
//! Fixed-memory set membership with a one-sided error: a `false`
//! from [`BloomFilter::contains`] is definitive ("never seen"), a
//! `true` may be a false positive at the configured rate. The
//! complement of [`crate::correlate::HyperLogLog`] (which counts
//! distinct items but can't answer "have I seen *this* one") and
//! of [`crate::correlate::KeyIndexed`] (which stores values but
//! grows with cardinality).
//!
//! Operational uses: first-contact detection ("first time this
//! src→dst pair appeared"), alert de-duplication, and cheap
//! pre-filtering before an expensive exact lookup.
//!
//! ## Algorithm
//!
//! Bloom (CACM 1970). A bit array of `m` bits and `k` hash
//! functions; `insert` sets `k` bits, `contains` checks them. For
//! `n` expected items at false-positive rate `p`:
//! `m = ceil(-n·ln p / (ln 2)²)`, `k = round((m/n)·ln 2)`.
//!
//! `k` hash positions come from one 64-bit hash split into two
//! 32-bit halves combined via Kirsch-Mitzenmacher double hashing
//! (`g_i = h1 + i·h2`).
//!
//! ## Mergeability
//!
//! [`BloomFilter`] implements [`Mergeable`](crate::correlate::Mergeable)
//! via bitwise OR — the canonical Bloom union (filters must share
//! `m`, `k`, **and** hasher state). Like the other sketches, pass
//! a deterministic hasher builder to every shard.
//!
//! Issue #75.

use std::hash::{BuildHasher, Hash};

/// Probabilistic set-membership filter.
#[derive(Debug, Clone)]
pub struct BloomFilter<S = std::hash::RandomState> {
    /// Bit storage, `ceil(m / 64)` words.
    words: Vec<u64>,
    /// Number of bits `m`.
    bits: usize,
    /// Number of hash functions `k`.
    hashes: usize,
    hasher_builder: S,
}

impl BloomFilter<std::hash::RandomState> {
    /// Size a filter for `expected_items` at false-positive rate
    /// `fp_rate` (clamped to `(0, 1)`).
    ///
    /// E.g. `with_capacity(1_000_000, 0.01)` → ~1.2 MB, k = 7.
    pub fn with_capacity(expected_items: usize, fp_rate: f64) -> Self {
        Self::with_capacity_and_hasher(expected_items, fp_rate, std::hash::RandomState::new())
    }
}

impl<S: BuildHasher> BloomFilter<S> {
    /// [`Self::with_capacity`] with a caller-supplied hasher
    /// builder (use a deterministic one for sharded
    /// [`Mergeable`](crate::correlate::Mergeable) use).
    pub fn with_capacity_and_hasher(
        expected_items: usize,
        fp_rate: f64,
        hasher_builder: S,
    ) -> Self {
        let n = expected_items.max(1) as f64;
        let p = fp_rate.clamp(f64::MIN_POSITIVE, 1.0 - f64::EPSILON);
        let ln2 = std::f64::consts::LN_2;
        let bits = (-n * p.ln() / (ln2 * ln2)).ceil() as usize;
        let bits = bits.max(64);
        let hashes = (((bits as f64 / n) * ln2).round() as usize).clamp(1, 64);
        let words = bits.div_ceil(64);
        Self {
            words: vec![0u64; words],
            bits,
            hashes,
            hasher_builder,
        }
    }

    /// Number of bits `m`.
    pub fn bit_len(&self) -> usize {
        self.bits
    }

    /// Number of hash functions `k`.
    pub fn hash_count(&self) -> usize {
        self.hashes
    }

    fn h1_h2(&self, item: &impl Hash) -> (u32, u32) {
        let h = self.hasher_builder.hash_one(item);
        let h1 = (h >> 32) as u32;
        let h2 = (h as u32) | 1;
        (h1, h2)
    }

    /// Insert `item`. Returns `true` if it was (probably) **new**
    /// — i.e. at least one of its bits was previously unset.
    /// A `false` means the item was almost certainly already
    /// present (subject to the configured false-positive rate).
    pub fn insert(&mut self, item: impl Hash) -> bool {
        let (h1, h2) = self.h1_h2(&item);
        let mut newly = false;
        for i in 0..self.hashes {
            let bit = (h1.wrapping_add((i as u32).wrapping_mul(h2)) as usize) % self.bits;
            let word = bit / 64;
            let mask = 1u64 << (bit % 64);
            if self.words[word] & mask == 0 {
                newly = true;
                self.words[word] |= mask;
            }
        }
        newly
    }

    /// `true` if `item` may have been inserted (subject to the
    /// false-positive rate); `false` is definitive.
    pub fn contains(&self, item: &impl Hash) -> bool {
        let (h1, h2) = self.h1_h2(item);
        for i in 0..self.hashes {
            let bit = (h1.wrapping_add((i as u32).wrapping_mul(h2)) as usize) % self.bits;
            let word = bit / 64;
            let mask = 1u64 << (bit % 64);
            if self.words[word] & mask == 0 {
                return false;
            }
        }
        true
    }

    /// Reset every bit.
    pub fn clear(&mut self) {
        for w in &mut self.words {
            *w = 0;
        }
    }

    /// `true` if no bits are set (nothing inserted).
    pub fn is_empty(&self) -> bool {
        self.words.iter().all(|&w| w == 0)
    }

    /// Fraction of bits set — a rough fill / saturation gauge.
    /// As this approaches 0.5+ the false-positive rate climbs
    /// above the configured target (the filter is over capacity).
    pub fn saturation(&self) -> f64 {
        let set: u32 = self.words.iter().map(|w| w.count_ones()).sum();
        set as f64 / self.bits as f64
    }
}

impl<S: BuildHasher> crate::correlate::Mergeable for BloomFilter<S> {
    /// Bitwise OR — the canonical Bloom union.
    ///
    /// **Panics** if `m` or `k` differ. Hasher state must also
    /// match across shards (documented contract, unchecked).
    fn merge(&mut self, other: Self) {
        assert_eq!(
            (self.bits, self.hashes),
            (other.bits, other.hashes),
            "BloomFilter::merge requires matching bit length and hash count",
        );
        for (a, b) in self.words.iter_mut().zip(other.words) {
            *a |= b;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::correlate::Mergeable;
    use std::hash::BuildHasherDefault;

    type FixedBloom = BloomFilter<BuildHasherDefault<std::collections::hash_map::DefaultHasher>>;

    fn new_fixed(n: usize, p: f64) -> FixedBloom {
        BloomFilter::with_capacity_and_hasher(n, p, BuildHasherDefault::default())
    }

    #[test]
    fn no_false_negatives() {
        let mut b = new_fixed(10_000, 0.01);
        for i in 0..10_000u64 {
            b.insert(i);
        }
        for i in 0..10_000u64 {
            assert!(b.contains(&i), "false negative for {i}");
        }
    }

    #[test]
    fn false_positive_rate_near_target() {
        let mut b = new_fixed(10_000, 0.01);
        for i in 0..10_000u64 {
            b.insert(i);
        }
        let mut fp = 0;
        let trials = 100_000u64;
        for i in 1_000_000..1_000_000 + trials {
            if b.contains(&i) {
                fp += 1;
            }
        }
        let rate = fp as f64 / trials as f64;
        assert!(rate < 0.03, "fp rate {rate} too high (target 0.01)");
    }

    #[test]
    fn insert_reports_newness() {
        let mut b = new_fixed(1000, 0.01);
        assert!(b.insert("first"));
        assert!(!b.insert("first")); // already present
        assert!(b.insert("second"));
    }

    #[test]
    fn merge_is_union() {
        let mut a = new_fixed(10_000, 0.01);
        let mut b = new_fixed(10_000, 0.01);
        for i in 0..5000u64 {
            a.insert(i);
        }
        for i in 5000..10_000u64 {
            b.insert(i);
        }
        a.merge(b);
        for i in 0..10_000u64 {
            assert!(a.contains(&i), "merged filter missing {i}");
        }
    }

    #[test]
    #[should_panic(expected = "matching bit length")]
    fn merge_panics_on_mismatch() {
        let mut a = new_fixed(1000, 0.01);
        let b = new_fixed(5000, 0.01);
        a.merge(b);
    }

    #[test]
    fn clear_resets() {
        let mut b = new_fixed(1000, 0.01);
        b.insert("x");
        assert!(!b.is_empty());
        b.clear();
        assert!(b.is_empty());
        assert!(!b.contains(&"x"));
    }
}

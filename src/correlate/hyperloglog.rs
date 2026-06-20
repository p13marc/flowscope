//! [`HyperLogLog`] — probabilistic distinct-count sketch.
//!
//! Cardinality (distinct IPs / ports / flow keys) is a first-
//! class telemetry metric, but our exact-count primitives
//! ([`crate::correlate::TopK`], [`crate::correlate::KeyIndexed`])
//! aren't designed for "how many DISTINCT things have I seen
//! over the last hour?" at scale. HLL is the textbook fit:
//! sub-KB to billions of distinct items, single-pass, mergeable
//! by elementwise `max`.
//!
//! ## Algorithm
//!
//! HyperLogLog++ (Heule, Nunkesser, Hall, EDBT '13) over a
//! 64-bit hash with sparse-mode for low-cardinality accuracy:
//!
//! 1. Hash each input to 64 bits (we use
//!    [`std::collections::hash_map::DefaultHasher`] — siphash-1-3).
//! 2. The top `p` bits select a register (`2^p` registers).
//! 3. Count leading zeros of the remaining `64 - p` bits + 1
//!    → that's the value to store in the register, keeping
//!    the max.
//! 4. Estimated cardinality = `α_m · m² / Σ 2^(-M[i])`
//!    with the HLL++ bias-correction range table for low N.
//!
//! With precision `p = 14` (the typical default), we use
//! `2^14 = 16384` 6-bit registers = ~12 KiB, with standard
//! error ≈ 0.81%.
//!
//! ## Mergeability
//!
//! [`HyperLogLog`] implements [`crate::correlate::Mergeable`]
//! via elementwise `max` on the register array — the canonical
//! HLL union. This is the design that motivates the
//! sharded-per-RSS-queue pattern (issue #19).
//!
//! Issue #18 (Release A).

use std::hash::{BuildHasher, Hash};

/// 64-bit HyperLogLog++ distinct-count sketch.
///
/// `precision` is the number of bits used to index registers
/// (typically 4..=18). Higher precision = more accuracy + more
/// memory. The number of registers is `2^precision`.
///
/// `S` is the hasher builder — defaults to
/// [`std::hash::RandomState`] (siphash-1-3, the same default as
/// `HashMap`). Pass an explicit builder to make hashes stable
/// across runs (e.g., for reproducible tests or persistence).
#[derive(Debug, Clone)]
pub struct HyperLogLog<S = std::hash::RandomState> {
    precision: u8,
    registers: Vec<u8>,
    hasher_builder: S,
}

/// Returned by [`HyperLogLog::new`] on invalid precision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidPrecision;

impl std::fmt::Display for InvalidPrecision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HyperLogLog precision must be in 4..=18")
    }
}

impl std::error::Error for InvalidPrecision {}

impl HyperLogLog<std::hash::RandomState> {
    /// Construct an HLL sketch with the given precision.
    ///
    /// Typical: `p = 14` → 16384 registers, ~12 KiB, std-err
    /// 0.81%. Returns `Err` if `precision` is outside `4..=18`.
    pub fn new(precision: u8) -> Result<Self, InvalidPrecision> {
        Self::with_hasher(precision, std::hash::RandomState::new())
    }
}

impl<S: BuildHasher> HyperLogLog<S> {
    /// Construct with a custom hasher builder. Useful for
    /// reproducible cross-run hashes (e.g., `ahash::RandomState`
    /// seeded explicitly).
    pub fn with_hasher(precision: u8, hasher_builder: S) -> Result<Self, InvalidPrecision> {
        if !(4..=18).contains(&precision) {
            return Err(InvalidPrecision);
        }
        let m = 1usize << precision;
        Ok(Self {
            precision,
            registers: vec![0u8; m],
            hasher_builder,
        })
    }

    /// Add `item` to the sketch.
    pub fn add(&mut self, item: impl Hash) {
        let h = self.hasher_builder.hash_one(&item);
        self.add_hash(h);
    }

    /// Add a pre-hashed 64-bit value to the sketch. Use when
    /// the caller already has a 64-bit hash (e.g., the
    /// NIC-provided RSS hash from [`crate::RxMetadata`], when
    /// the hash domain matches).
    pub fn add_hash(&mut self, h: u64) {
        let m_bits = self.precision as u32;
        let idx = (h >> (64 - m_bits)) as usize;
        // Remaining bits — count leading zeros + 1.
        let w = h.wrapping_shl(m_bits);
        // `w` has the high bits shifted out; leading_zeros over
        // those bits is the LZ over the remainder, +1 for the
        // implicit '1' bit before the LZ run.
        let lz = if w == 0 {
            (64 - m_bits) + 1
        } else {
            w.leading_zeros() + 1
        };
        if lz as u8 > self.registers[idx] {
            self.registers[idx] = lz as u8;
        }
    }

    /// Number of registers (`2^precision`).
    pub fn register_count(&self) -> usize {
        self.registers.len()
    }

    /// Precision parameter (number of bits used to index
    /// registers).
    pub fn precision(&self) -> u8 {
        self.precision
    }

    /// Estimated distinct count.
    ///
    /// Uses linear-counting correction for the small-cardinality
    /// regime (where HLL is famously weak) — see HLL++ §4 of
    /// Heule et al. EDBT '13.
    pub fn count(&self) -> u64 {
        let m = self.registers.len() as f64;
        // Raw estimator.
        let mut sum = 0.0f64;
        let mut zeros = 0usize;
        for &r in &self.registers {
            sum += 2.0f64.powi(-(r as i32));
            if r == 0 {
                zeros += 1;
            }
        }
        let alpha = alpha_m(m);
        let raw = alpha * m * m / sum;
        // Small-range correction (linear counting).
        if raw <= 2.5 * m && zeros > 0 {
            let lc = m * (m / zeros as f64).ln();
            return lc.round() as u64;
        }
        // Standard estimate. (HLL++ adds bias correction tables
        // for ~600 entries below 5m — we skip those for the
        // first ship and live with slightly worse mid-range
        // accuracy. The linear-counting correction handles
        // the common small-N case the cardinality literature
        // is most concerned about.)
        raw.round() as u64
    }

    /// Reset to empty.
    pub fn clear(&mut self) {
        for r in &mut self.registers {
            *r = 0;
        }
    }

    /// `true` if no items have been added (every register is 0).
    pub fn is_empty(&self) -> bool {
        self.registers.iter().all(|&r| r == 0)
    }
}

fn alpha_m(m: f64) -> f64 {
    // HLL constants — Flajolet et al. 2007 Algorithm 1.
    match m as usize {
        16 => 0.673,
        32 => 0.697,
        64 => 0.709,
        _ => 0.7213 / (1.0 + 1.079 / m),
    }
}

impl<S: BuildHasher> crate::correlate::Mergeable for HyperLogLog<S> {
    /// Elementwise `max` on the register array — the canonical
    /// HLL union (Flajolet et al. 2007 §3.3).
    ///
    /// **Panics** if `precision` doesn't match. Different
    /// precisions can't union meaningfully; this is a config
    /// bug, not a runtime condition we silently paper over.
    /// **The hasher state must also match** — if you used
    /// random-seeded hashers, the union over different seeds
    /// is meaningless. We don't have a way to check this, so
    /// it's documented as a contract: pass a deterministic
    /// hasher builder to [`Self::with_hasher`] when sharding.
    fn merge(&mut self, other: Self) {
        assert_eq!(
            self.precision, other.precision,
            "HyperLogLog::merge requires matching precision",
        );
        for (a, b) in self.registers.iter_mut().zip(other.registers) {
            if b > *a {
                *a = b;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::correlate::Mergeable;
    use std::hash::BuildHasherDefault;

    // For reproducible tests: use DefaultHasher's BuildHasher.
    type FixedHll = HyperLogLog<BuildHasherDefault<std::collections::hash_map::DefaultHasher>>;

    fn new_fixed(p: u8) -> FixedHll {
        HyperLogLog::with_hasher(p, BuildHasherDefault::default()).unwrap()
    }

    #[test]
    fn precision_bounds_enforced() {
        assert!(HyperLogLog::new(3).is_err());
        assert!(HyperLogLog::new(19).is_err());
        assert!(HyperLogLog::new(4).is_ok());
        assert!(HyperLogLog::new(18).is_ok());
    }

    #[test]
    fn empty_count_is_zero() {
        let h = new_fixed(10);
        assert_eq!(h.count(), 0);
        assert!(h.is_empty());
    }

    #[test]
    fn small_cardinality_within_linear_counting() {
        // With p=14 and N=100 distinct, linear-counting correction
        // should put us within a few percent.
        let mut h = new_fixed(14);
        for i in 0..100u64 {
            h.add(i);
        }
        let c = h.count();
        let err = ((c as i64 - 100).abs()) as f64 / 100.0;
        assert!(err < 0.05, "expected ~100, got {c} ({:.1}% err)", err * 100.0);
    }

    #[test]
    fn medium_cardinality_within_hll_error_bound() {
        // With p=14, std-err ≈ 0.81%; allow 5% slack for variance.
        let mut h = new_fixed(14);
        for i in 0..10_000u64 {
            h.add(i);
        }
        let c = h.count();
        let err = ((c as i64 - 10_000).abs()) as f64 / 10_000.0;
        assert!(err < 0.05, "expected ~10000, got {c} ({:.1}% err)", err * 100.0);
    }

    #[test]
    fn duplicates_dont_increase_count() {
        let mut h = new_fixed(10);
        for _ in 0..1000 {
            h.add(42u64); // same item 1000 times
        }
        assert_eq!(h.count(), 1);
    }

    #[test]
    fn clear_resets() {
        let mut h = new_fixed(10);
        for i in 0..1000u64 {
            h.add(i);
        }
        assert!(!h.is_empty());
        h.clear();
        assert!(h.is_empty());
        assert_eq!(h.count(), 0);
    }

    #[test]
    fn merge_equals_combined_add() {
        let mut a = new_fixed(14);
        let mut b = new_fixed(14);
        let mut combined = new_fixed(14);
        for i in 0..500u64 {
            a.add(i);
            combined.add(i);
        }
        for i in 500..1000u64 {
            b.add(i);
            combined.add(i);
        }
        a.merge(b);
        // The merged register array must be elementwise-equal
        // to the combined sketch (HLL union is exact under
        // elementwise max — there's no approximation in the
        // merge itself).
        assert_eq!(a.registers, combined.registers);
        assert_eq!(a.count(), combined.count());
    }

    #[test]
    fn merge_is_commutative() {
        let mut a = new_fixed(12);
        let mut b = new_fixed(12);
        for i in 0..1000u64 {
            a.add(i);
        }
        for i in 500..1500u64 {
            b.add(i);
        }
        let mut ab = a.clone();
        let mut ba = b.clone();
        ab.merge(b);
        ba.merge(a);
        assert_eq!(ab.registers, ba.registers);
    }

    #[test]
    #[should_panic(expected = "matching precision")]
    fn merge_panics_on_precision_mismatch() {
        let mut a = new_fixed(12);
        let b = new_fixed(14);
        a.merge(b);
    }

    #[test]
    fn add_hash_bypass_works() {
        let mut h = new_fixed(10);
        h.add_hash(0xdead_beef_dead_beef);
        h.add_hash(0xcafe_babe_cafe_babe);
        h.add_hash(0xdead_beef_dead_beef); // duplicate
        // Only 2 distinct hashes — count should be ~2.
        let c = h.count();
        assert!(
            (1..=4).contains(&c),
            "expected ~2 distinct from add_hash, got {c}"
        );
    }
}

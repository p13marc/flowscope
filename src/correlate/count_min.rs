//! [`CountMinSketch`] — sublinear frequency / heavy-hitter sketch.
//!
//! Where [`crate::correlate::TopK`] tracks the *identity* of the
//! heaviest keys (Misra-Gries), Count-Min answers the dual
//! question: "given this key, roughly how many times have I seen
//! it?" in fixed memory, single-pass, with a one-sided error
//! (it never under-counts).
//!
//! ## Algorithm
//!
//! Cormode & Muthukrishnan (J. Algorithms 2005). A `depth × width`
//! grid of `u32` counters with `depth` pairwise-independent hash
//! functions (one per row). `add(k, n)` increments
//! `grid[row][h_row(k) % width]` by `n` in every row;
//! `estimate(k)` is the **minimum** counter across rows — the
//! tightest over-estimate.
//!
//! Sizing: [`CountMinSketch::with_error`] picks
//! `width = ceil(e / ε)` and `depth = ceil(ln(1 / δ))`, giving an
//! over-estimate bounded by `ε · N` (N = total count) with
//! probability `1 − δ`.
//!
//! ## Hashing
//!
//! One 64-bit hash per item, split into two 32-bit halves and
//! combined via Kirsch-Mitzenmacher double hashing
//! (`g_i = h1 + i·h2`) to synthesise the `depth` row indices —
//! the standard trick that avoids `depth` independent hash
//! computations.
//!
//! `S` is the hasher builder, defaulting to
//! [`std::hash::RandomState`] like [`crate::correlate::HyperLogLog`].
//! **For [`Mergeable`](crate::correlate::Mergeable) sharded use you
//! MUST pass a deterministic builder** (e.g. a fixed-seed
//! `ahash::RandomState`) to every shard — merging grids hashed
//! under different seeds is meaningless.
//!
//! Issue #75.

use std::hash::{BuildHasher, Hash};

/// Count-Min frequency sketch.
///
/// Memory is `depth × width × 4` bytes, fixed at construction.
#[derive(Debug, Clone)]
pub struct CountMinSketch<S = std::hash::RandomState> {
    depth: usize,
    width: usize,
    /// Row-major `depth × width` grid of saturating counters.
    grid: Vec<u32>,
    hasher_builder: S,
}

impl CountMinSketch<std::hash::RandomState> {
    /// Construct a sketch sized for relative error `epsilon` with
    /// failure probability `delta`.
    ///
    /// `width = ceil(e / epsilon)`, `depth = ceil(ln(1 / delta))`.
    /// E.g. `with_error(0.001, 0.001)` → width 2719, depth 7
    /// (~76 KiB). Both inputs are clamped to `(0, 1)`; out-of-range
    /// values are treated as the nearest valid bound.
    pub fn with_error(epsilon: f64, delta: f64) -> Self {
        Self::with_error_and_hasher(epsilon, delta, std::hash::RandomState::new())
    }

    /// Construct from explicit grid dimensions.
    pub fn with_dimensions(depth: usize, width: usize) -> Self {
        Self::with_dimensions_and_hasher(depth, width, std::hash::RandomState::new())
    }
}

impl<S: BuildHasher> CountMinSketch<S> {
    /// [`Self::with_error`] with a caller-supplied hasher builder
    /// (use a deterministic one for sharded [`Mergeable`] use).
    pub fn with_error_and_hasher(epsilon: f64, delta: f64, hasher_builder: S) -> Self {
        let epsilon = epsilon.clamp(f64::MIN_POSITIVE, 1.0 - f64::EPSILON);
        let delta = delta.clamp(f64::MIN_POSITIVE, 1.0 - f64::EPSILON);
        let width = (std::f64::consts::E / epsilon).ceil() as usize;
        let depth = (1.0 / delta).ln().ceil() as usize;
        Self::with_dimensions_and_hasher(depth.max(1), width.max(1), hasher_builder)
    }

    /// [`Self::with_dimensions`] with a caller-supplied hasher.
    pub fn with_dimensions_and_hasher(depth: usize, width: usize, hasher_builder: S) -> Self {
        let depth = depth.max(1);
        let width = width.max(1);
        Self {
            depth,
            width,
            grid: vec![0u32; depth * width],
            hasher_builder,
        }
    }

    /// Number of rows.
    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Number of columns.
    pub fn width(&self) -> usize {
        self.width
    }

    fn h1_h2(&self, item: &impl Hash) -> (u32, u32) {
        let h = self.hasher_builder.hash_one(item);
        let h1 = (h >> 32) as u32;
        // Force `h2` odd so the double-hashing probe sequence
        // covers all residues mod a power-of-two-ish width.
        let h2 = (h as u32) | 1;
        (h1, h2)
    }

    /// Add `count` occurrences of `item`. Counters saturate at
    /// `u32::MAX` rather than wrapping.
    pub fn add(&mut self, item: impl Hash, count: u32) {
        let (h1, h2) = self.h1_h2(&item);
        for row in 0..self.depth {
            let col = (h1.wrapping_add((row as u32).wrapping_mul(h2)) as usize) % self.width;
            let cell = &mut self.grid[row * self.width + col];
            *cell = cell.saturating_add(count);
        }
    }

    /// Add a single occurrence of `item`.
    pub fn increment(&mut self, item: impl Hash) {
        self.add(item, 1);
    }

    /// Estimated occurrence count for `item` — the minimum counter
    /// across rows. Never under-estimates; over-estimates by at
    /// most `ε · N` with probability `1 − δ`.
    pub fn estimate(&self, item: &impl Hash) -> u32 {
        let (h1, h2) = self.h1_h2(item);
        let mut min = u32::MAX;
        for row in 0..self.depth {
            let col = (h1.wrapping_add((row as u32).wrapping_mul(h2)) as usize) % self.width;
            min = min.min(self.grid[row * self.width + col]);
        }
        min
    }

    /// Reset every counter to zero.
    pub fn clear(&mut self) {
        for c in &mut self.grid {
            *c = 0;
        }
    }

    /// `true` if no items have been added.
    pub fn is_empty(&self) -> bool {
        self.grid.iter().all(|&c| c == 0)
    }
}

impl<S: BuildHasher> crate::correlate::Mergeable for CountMinSketch<S> {
    /// Cellwise saturating add — the canonical Count-Min union.
    ///
    /// **Panics** if the grid dimensions differ. Different
    /// dimensions can't union; this is a config bug. As with
    /// [`HyperLogLog`](crate::correlate::HyperLogLog), the hasher
    /// state must also match across shards — pass a deterministic
    /// builder.
    fn merge(&mut self, other: Self) {
        assert_eq!(
            (self.depth, self.width),
            (other.depth, other.width),
            "CountMinSketch::merge requires matching dimensions",
        );
        for (a, b) in self.grid.iter_mut().zip(other.grid) {
            *a = a.saturating_add(b);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::correlate::Mergeable;
    use std::hash::BuildHasherDefault;

    type FixedCms = CountMinSketch<BuildHasherDefault<std::collections::hash_map::DefaultHasher>>;

    fn new_fixed(eps: f64, delta: f64) -> FixedCms {
        CountMinSketch::with_error_and_hasher(eps, delta, BuildHasherDefault::default())
    }

    #[test]
    fn never_underestimates() {
        let mut c = new_fixed(0.001, 0.001);
        for i in 0..1000u64 {
            c.add(i, (i % 7) as u32 + 1);
        }
        for i in 0..1000u64 {
            let truth = (i % 7) as u32 + 1;
            assert!(
                c.estimate(&i) >= truth,
                "count-min under-estimated key {i}: {} < {truth}",
                c.estimate(&i)
            );
        }
    }

    #[test]
    fn estimate_close_for_heavy_hitter() {
        let mut c = new_fixed(0.0005, 0.001);
        for _ in 0..100_000 {
            c.increment("hot");
        }
        for i in 0..5_000u64 {
            c.increment(i); // light background noise
        }
        let est = c.estimate(&"hot");
        assert!(est >= 100_000);
        // Over-estimate bounded by ε·N; allow generous slack.
        assert!(est < 110_000, "heavy hitter over-estimated: {est}");
    }

    #[test]
    fn unseen_key_estimates_low() {
        let mut c = new_fixed(0.001, 0.001);
        for i in 0..100u64 {
            c.add(i, 1);
        }
        // A never-added key may collide but should be small.
        assert!(c.estimate(&999_999u64) <= 1);
    }

    #[test]
    fn saturates_instead_of_wrapping() {
        let mut c = new_fixed(0.1, 0.1);
        c.add("x", u32::MAX);
        c.add("x", 100);
        assert_eq!(c.estimate(&"x"), u32::MAX);
    }

    #[test]
    fn merge_equals_combined_add() {
        let mut a = new_fixed(0.001, 0.001);
        let mut b = new_fixed(0.001, 0.001);
        let mut combined = new_fixed(0.001, 0.001);
        for i in 0..500u64 {
            a.add(i, 2);
            combined.add(i, 2);
        }
        for i in 0..500u64 {
            b.add(i, 3);
            combined.add(i, 3);
        }
        a.merge(b);
        assert_eq!(a.grid, combined.grid);
    }

    #[test]
    #[should_panic(expected = "matching dimensions")]
    fn merge_panics_on_dimension_mismatch() {
        let mut a: FixedCms =
            CountMinSketch::with_dimensions_and_hasher(4, 100, BuildHasherDefault::default());
        let b: FixedCms =
            CountMinSketch::with_dimensions_and_hasher(5, 100, BuildHasherDefault::default());
        a.merge(b);
    }

    #[test]
    fn clear_resets() {
        let mut c = new_fixed(0.01, 0.01);
        c.add("a", 5);
        assert!(!c.is_empty());
        c.clear();
        assert!(c.is_empty());
        assert_eq!(c.estimate(&"a"), 0);
    }
}

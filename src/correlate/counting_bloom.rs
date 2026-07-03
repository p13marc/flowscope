//! [`CountingBloomFilter`] — delete-capable probabilistic set
//! membership.

use std::hash::{BuildHasher, Hash};

/// Cell width: 4 bits, packed 16 per `u64` word.
const CELL_BITS: u32 = 4;
const CELLS_PER_WORD: usize = 16;
const CELL_MAX: u64 = 0xF;

/// Delete-capable probabilistic set-membership filter — a
/// counting Bloom filter (Fan et al., "Summary Cache", 1998).
///
/// The [`BloomFilter`](crate::correlate::BloomFilter) sibling
/// for churn-heavy seen-sets: where a plain Bloom filter can
/// never forget an item, this one backs each position with a
/// 4-bit saturating counter so [`remove`](Self::remove) works.
/// The price is 4× the memory of a plain Bloom filter at the
/// same false-positive rate.
///
/// Same one-sided error contract: a `false` from
/// [`contains`](Self::contains) is definitive ("not present"),
/// a `true` may be a false positive at the configured rate.
///
/// ## Overflow safety
///
/// A cell that reaches 15 **saturates stickily**: it is never
/// incremented further and never decremented, so a burst of
/// hash collisions can inflate a cell but a later `remove` can
/// never push a still-present item's cell to zero — deletes
/// never create false *negatives*. At the design load the
/// probability of any cell reaching 15 is ~10⁻¹⁵ (Fan et al.
/// §4.3), so sticky cells are vanishingly rare in practice.
///
/// [`remove`](Self::remove) only decrements when **all** of the
/// item's cells are non-zero — removing a never-inserted item
/// is a no-op returning `false`, and cannot corrupt other
/// items' cells.
///
/// ## Mergeability
///
/// Implements [`Mergeable`](crate::correlate::Mergeable) via
/// cellwise **saturating** addition (associative — `min(15,
/// a+b)` folds in any order). Filters must share cell count,
/// hash count, and hasher state; pass a deterministic hasher
/// builder to every shard.
///
/// Issue #134 (0.21).
#[derive(Debug, Clone)]
pub struct CountingBloomFilter<S = std::hash::RandomState> {
    /// Packed 4-bit cells, 16 per word; `ceil(cells / 16)` words.
    words: Vec<u64>,
    /// Number of cells `m`.
    cells: usize,
    /// Number of hash functions `k`.
    hashes: usize,
    hasher_builder: S,
}

impl CountingBloomFilter<std::hash::RandomState> {
    /// Size a filter for `expected_items` at false-positive rate
    /// `fp_rate` (clamped to `(0, 1)`).
    ///
    /// Same sizing math as
    /// [`BloomFilter::with_capacity`](crate::correlate::BloomFilter::with_capacity),
    /// but each position costs 4 bits instead of 1 — e.g.
    /// `with_capacity(1_000_000, 0.01)` → ~4.8 MB, k = 7.
    pub fn with_capacity(expected_items: usize, fp_rate: f64) -> Self {
        Self::with_capacity_and_hasher(expected_items, fp_rate, std::hash::RandomState::new())
    }
}

impl<S: BuildHasher> CountingBloomFilter<S> {
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
        let cells = (-n * p.ln() / (ln2 * ln2)).ceil() as usize;
        let cells = cells.max(64);
        let hashes = (((cells as f64 / n) * ln2).round() as usize).clamp(1, 64);
        let words = cells.div_ceil(CELLS_PER_WORD);
        Self {
            words: vec![0u64; words],
            cells,
            hashes,
            hasher_builder,
        }
    }

    /// Number of counter cells `m`.
    pub fn cell_len(&self) -> usize {
        self.cells
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

    fn cell_index(&self, h1: u32, h2: u32, i: usize) -> usize {
        (h1.wrapping_add((i as u32).wrapping_mul(h2)) as usize) % self.cells
    }

    fn cell_get(&self, cell: usize) -> u64 {
        let word = cell / CELLS_PER_WORD;
        let shift = (cell % CELLS_PER_WORD) as u32 * CELL_BITS;
        (self.words[word] >> shift) & CELL_MAX
    }

    fn cell_set(&mut self, cell: usize, value: u64) {
        let word = cell / CELLS_PER_WORD;
        let shift = (cell % CELLS_PER_WORD) as u32 * CELL_BITS;
        self.words[word] =
            (self.words[word] & !(CELL_MAX << shift)) | ((value & CELL_MAX) << shift);
    }

    /// Insert `item`. Returns `true` if it was (probably) **new**
    /// — i.e. at least one of its cells was previously zero. A
    /// `false` means the item was almost certainly already present
    /// (subject to the configured false-positive rate).
    ///
    /// Cells at 15 stay at 15 (sticky saturation — see the type
    /// docs).
    pub fn insert(&mut self, item: impl Hash) -> bool {
        let (h1, h2) = self.h1_h2(&item);
        let mut newly = false;
        for i in 0..self.hashes {
            let cell = self.cell_index(h1, h2, i);
            let v = self.cell_get(cell);
            if v == 0 {
                newly = true;
            }
            if v < CELL_MAX {
                self.cell_set(cell, v + 1);
            }
        }
        newly
    }

    /// Remove one prior insertion of `item`. Returns `true` when a
    /// removal was performed.
    ///
    /// Returns `false` — and decrements **nothing** — when any of
    /// the item's cells is zero (the item was definitively never
    /// inserted, or already fully removed). Saturated cells (15)
    /// are skipped during decrement (sticky — see the type docs).
    pub fn remove(&mut self, item: &impl Hash) -> bool {
        let (h1, h2) = self.h1_h2(item);
        // Pass 1: the item must currently be "contained" — every
        // cell non-zero — or we'd corrupt other items' counters.
        for i in 0..self.hashes {
            if self.cell_get(self.cell_index(h1, h2, i)) == 0 {
                return false;
            }
        }
        // Pass 2: decrement (skipping sticky saturated cells).
        for i in 0..self.hashes {
            let cell = self.cell_index(h1, h2, i);
            let v = self.cell_get(cell);
            if v < CELL_MAX {
                self.cell_set(cell, v - 1);
            }
        }
        true
    }

    /// `true` if `item` may be present (subject to the
    /// false-positive rate); `false` is definitive.
    pub fn contains(&self, item: &impl Hash) -> bool {
        let (h1, h2) = self.h1_h2(item);
        for i in 0..self.hashes {
            if self.cell_get(self.cell_index(h1, h2, i)) == 0 {
                return false;
            }
        }
        true
    }

    /// Reset every cell.
    pub fn clear(&mut self) {
        for w in &mut self.words {
            *w = 0;
        }
    }

    /// `true` if no cells are set (nothing currently inserted).
    pub fn is_empty(&self) -> bool {
        self.words.iter().all(|&w| w == 0)
    }

    /// Fraction of cells non-zero — a rough fill / saturation
    /// gauge, parallel to
    /// [`BloomFilter::saturation`](crate::correlate::BloomFilter::saturation).
    /// As this approaches 0.5+ the false-positive rate climbs
    /// above the configured target.
    pub fn saturation(&self) -> f64 {
        let mut set = 0usize;
        for cell in 0..self.cells {
            if self.cell_get(cell) != 0 {
                set += 1;
            }
        }
        set as f64 / self.cells as f64
    }
}

impl<S: BuildHasher> crate::correlate::Mergeable for CountingBloomFilter<S> {
    /// Cellwise saturating addition — the counting-Bloom union.
    /// Saturating add (`min(15, a + b)`) is associative and
    /// commutative, so shard folds converge in any order.
    ///
    /// **Panics** if cell count or hash count differ. Hasher
    /// *state* equality can't be checked — as with the other
    /// sketches, pass the same deterministic builder to every
    /// shard (documented contract).
    fn merge(&mut self, other: Self) {
        assert_eq!(
            (self.cells, self.hashes),
            (other.cells, other.hashes),
            "CountingBloomFilter::merge requires matching cell count and hash count",
        );
        for cell in 0..self.cells {
            let word = cell / CELLS_PER_WORD;
            let shift = (cell % CELLS_PER_WORD) as u32 * CELL_BITS;
            let a = (self.words[word] >> shift) & CELL_MAX;
            let b = (other.words[word] >> shift) & CELL_MAX;
            let merged = (a + b).min(CELL_MAX);
            self.words[word] = (self.words[word] & !(CELL_MAX << shift)) | (merged << shift);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::hash::{BuildHasherDefault, DefaultHasher};

    use super::*;
    use crate::correlate::Mergeable;

    /// Deterministic hasher for reproducible tests (same trick as
    /// bloom.rs / count_min.rs tests).
    type FixedHasher = BuildHasherDefault<DefaultHasher>;

    fn fixed(expected: usize, fp: f64) -> CountingBloomFilter<FixedHasher> {
        CountingBloomFilter::with_capacity_and_hasher(expected, fp, FixedHasher::default())
    }

    #[test]
    fn no_false_negatives() {
        let mut f = fixed(10_000, 0.01);
        for i in 0..10_000u32 {
            f.insert(i);
        }
        for i in 0..10_000u32 {
            assert!(f.contains(&i), "inserted item {i} must be contained");
        }
    }

    #[test]
    fn insert_remove_round_trip() {
        let mut f = fixed(1_000, 0.01);
        for i in 0..100u32 {
            f.insert(i);
        }
        assert!(f.remove(&42u32));
        assert!(!f.contains(&42u32), "removed item is gone");
        // Every other item unaffected.
        for i in (0..100u32).filter(|i| *i != 42) {
            assert!(f.contains(&i), "item {i} unaffected by remove");
        }
    }

    #[test]
    fn remove_of_absent_item_is_noop() {
        let mut f = fixed(1_000, 0.01);
        f.insert(1u32);
        assert!(!f.remove(&999_999u32), "absent item reports false");
        assert!(f.contains(&1u32), "present item not corrupted");
    }

    #[test]
    fn double_insert_needs_double_remove() {
        let mut f = fixed(1_000, 0.01);
        f.insert(7u32);
        f.insert(7u32);
        assert!(f.remove(&7u32));
        assert!(f.contains(&7u32), "one of two insertions remains");
        assert!(f.remove(&7u32));
        assert!(!f.contains(&7u32));
    }

    #[test]
    fn saturated_cells_are_sticky() {
        let mut f = fixed(1_000, 0.01);
        // 20 inserts of the same item saturate its cells at 15.
        for _ in 0..20 {
            f.insert(3u32);
        }
        // 20 removes: sticky cells never decrement, so the item
        // stays contained — overflow can inflate, never falsely
        // clear.
        for _ in 0..20 {
            f.remove(&3u32);
        }
        assert!(f.contains(&3u32), "sticky saturation never clears");
    }

    #[test]
    fn insert_returns_probably_new() {
        let mut f = fixed(1_000, 0.01);
        assert!(f.insert(1u32), "first insert is new");
        assert!(!f.insert(1u32), "second insert of same item is not");
    }

    #[test]
    fn fp_rate_within_expectations() {
        let mut f = fixed(10_000, 0.01);
        for i in 0..10_000u32 {
            f.insert(i);
        }
        let mut fps = 0usize;
        for i in 10_000..20_000u32 {
            if f.contains(&i) {
                fps += 1;
            }
        }
        // 1% target; allow generous 3x headroom for hash variance.
        assert!(fps < 300, "false positives {fps} exceed 3x target");
    }

    #[test]
    fn clear_and_is_empty() {
        let mut f = fixed(100, 0.01);
        assert!(f.is_empty());
        f.insert(1u32);
        assert!(!f.is_empty());
        assert!(f.saturation() > 0.0);
        f.clear();
        assert!(f.is_empty());
        assert_eq!(f.saturation(), 0.0);
    }

    #[test]
    fn merge_unions_counts() {
        let mut a = fixed(1_000, 0.01);
        let mut b = fixed(1_000, 0.01);
        a.insert(1u32);
        b.insert(2u32);
        b.insert(1u32);
        a.merge(b);
        assert!(a.contains(&1u32));
        assert!(a.contains(&2u32));
        // Key 1 was inserted once per shard: one remove leaves it
        // present, the second clears it — counts really added.
        assert!(a.remove(&1u32));
        assert!(a.contains(&1u32));
        assert!(a.remove(&1u32));
        assert!(!a.contains(&1u32));
    }

    #[test]
    fn merge_is_commutative() {
        let mk = |items: &[u32]| {
            let mut f = fixed(1_000, 0.01);
            for i in items {
                f.insert(*i);
            }
            f
        };
        let mut ab = mk(&[1, 2, 3]);
        ab.merge(mk(&[3, 4]));
        let mut ba = mk(&[3, 4]);
        ba.merge(mk(&[1, 2, 3]));
        assert_eq!(ab.words, ba.words, "cellwise saturating add commutes");
    }

    #[test]
    #[should_panic(expected = "matching cell count and hash count")]
    fn merge_panics_on_size_mismatch() {
        let mut a = fixed(1_000, 0.01);
        let b = fixed(50_000, 0.01);
        a.merge(b);
    }
}

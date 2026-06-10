//! [`TopK`] — bounded top-K counter (Misra-Gries / Space-Saving).

use std::collections::HashMap;
use std::hash::Hash;

/// Bounded "top K by count" tracker.
///
/// Exact when fewer than `k` distinct keys have been observed.
/// Above that, applies the **Misra-Gries** algorithm: when a new
/// distinct key arrives and the table is full, every counter is
/// decremented by one and any counter that hits 0 is evicted to
/// make room.
///
/// Worst-case overestimate for any key (real or estimated) is
/// bounded by the minimum retained count.
pub struct TopK<K: Hash + Eq + Clone> {
    k: usize,
    counts: HashMap<K, u64>,
}

impl<K: Hash + Eq + Clone> TopK<K> {
    pub fn new(k: usize) -> Self {
        assert!(k > 0, "k must be > 0");
        Self {
            k,
            counts: HashMap::new(),
        }
    }

    /// Convenience constructor with `k = usize::MAX` — every
    /// observed key is retained, no Misra-Gries eviction ever
    /// fires. Useful for offline / bounded-input contexts where
    /// memory pressure isn't a concern.
    ///
    /// Prefer [`Self::new`] with an explicit cap when memory
    /// pressure matters. New in 0.12.0 (plan 130).
    pub fn new_unbounded() -> Self {
        Self::new(usize::MAX)
    }

    /// Observe `key` once.
    pub fn observe(&mut self, key: K) {
        self.observe_n(key, 1);
    }

    /// Observe `key` with weight `count` (≥ 1).
    pub fn observe_n(&mut self, key: K, count: u64) {
        if count == 0 {
            return;
        }
        if let Some(c) = self.counts.get_mut(&key) {
            *c += count;
            return;
        }
        if self.counts.len() < self.k {
            self.counts.insert(key, count);
            return;
        }
        // Table is full: decrement every counter by `count`,
        // evict any that hit 0.
        let mut to_evict: Vec<K> = Vec::new();
        for (k, c) in self.counts.iter_mut() {
            if *c <= count {
                to_evict.push(k.clone());
            } else {
                *c -= count;
            }
        }
        for k in to_evict {
            self.counts.remove(&k);
        }
        // If we made room, insert with the residual count.
        if self.counts.len() < self.k {
            self.counts.insert(key, count);
        }
    }

    /// Top entries sorted by count descending.
    pub fn top(&self) -> Vec<(&K, u64)> {
        let mut v: Vec<(&K, u64)> = self.counts.iter().map(|(k, c)| (k, *c)).collect();
        v.sort_by_key(|b| std::cmp::Reverse(b.1));
        v
    }

    /// Estimated count for `key`. Returns `0` for keys not in the
    /// table — note that an evicted key may have been observed
    /// many times; the table can't distinguish "never seen" from
    /// "evicted".
    pub fn estimate(&self, key: &K) -> u64 {
        self.counts.get(key).copied().unwrap_or(0)
    }

    pub fn clear(&mut self) {
        self.counts.clear();
    }

    pub fn len(&self) -> usize {
        self.counts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.counts.is_empty()
    }
}

impl<K: Hash + Eq + Clone + std::fmt::Debug> std::fmt::Debug for TopK<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TopK")
            .field("k", &self.k)
            .field("counts", &self.counts)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_counts_when_under_capacity() {
        let mut t: TopK<u32> = TopK::new(4);
        for &k in &[1, 1, 2, 3, 3, 3] {
            t.observe(k);
        }
        assert_eq!(t.estimate(&1), 2);
        assert_eq!(t.estimate(&2), 1);
        assert_eq!(t.estimate(&3), 3);
    }

    #[test]
    fn top_returns_descending() {
        let mut t: TopK<u32> = TopK::new(4);
        for &k in &[1, 1, 2, 3, 3, 3] {
            t.observe(k);
        }
        let top = t.top();
        assert_eq!(top.len(), 3);
        assert_eq!(*top[0].0, 3);
        assert_eq!(*top[1].0, 1);
        assert_eq!(*top[2].0, 2);
    }

    #[test]
    fn over_capacity_keeps_heaviest_hitters() {
        let mut t: TopK<u32> = TopK::new(2);
        // 3 distinct keys with 1, 2, 3 occurrences.
        t.observe_n(1, 1);
        t.observe_n(2, 2);
        t.observe_n(3, 3);
        let top = t.top();
        // Misra-Gries: 1 is evicted via decrement, 3 dominates.
        assert!(top.iter().any(|(k, _)| **k == 3));
    }

    #[test]
    fn clear_resets_state() {
        let mut t: TopK<u32> = TopK::new(2);
        t.observe(1);
        t.clear();
        assert!(t.is_empty());
        assert_eq!(t.estimate(&1), 0);
    }

    #[test]
    fn observe_n_zero_is_noop() {
        let mut t: TopK<u32> = TopK::new(2);
        t.observe_n(1, 0);
        assert!(t.is_empty());
    }

    #[test]
    fn new_unbounded_never_evicts() {
        let mut t: TopK<u32> = TopK::new_unbounded();
        for i in 0..1000 {
            t.observe(i);
        }
        // Every key kept with exact count 1 — no Misra-Gries
        // eviction.
        for i in 0..1000 {
            assert_eq!(t.estimate(&i), 1);
        }
    }
}

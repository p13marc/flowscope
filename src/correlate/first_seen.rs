//! [`FirstSeen`] — bounded TTL'd "have I seen this before?" set.

use std::{
    hash::{BuildHasher, Hash, RandomState},
    num::NonZeroUsize,
    time::Duration,
};

use lru::LruCache;

use crate::Timestamp;

#[derive(Debug, Clone, Copy)]
struct Seen {
    first_seen: Timestamp,
    last_seen: Timestamp,
}

/// Bounded first-seen / newly-observed set: answers "is this the
/// first time I've seen key `K` (within the TTL)?" in O(1),
/// with LRU-bounded memory.
///
/// The exact-answer sibling of
/// [`BloomFilter`](crate::correlate::BloomFilter) /
/// [`CountingBloomFilter`](crate::correlate::CountingBloomFilter)
/// (which are probabilistic and can't expire), and the
/// set-shaped cousin of
/// [`KeyIndexed`](crate::correlate::KeyIndexed) (which stores
/// values). Purpose-built for newly-observed-domain /
/// first-contact detectors (issue #132).
///
/// # TTL semantics — refreshed on observe
///
/// A key's TTL runs from its **last** sighting, not its first:
/// a key observed continuously is never "new" again, while a
/// key silent for longer than `ttl` becomes "new" once more
/// (and its `first_seen` resets to that sighting). This is the
/// newly-observed-domain semantic — contrast
/// [`KeyIndexed`](crate::correlate::KeyIndexed), whose TTL runs
/// from insertion.
///
/// # Bounding caveat
///
/// The LRU bound makes the error one-sided in the safe
/// direction for detectors: evicting a live key under
/// cardinality pressure can only cause a **false "new"** on its
/// next sighting — never a false "seen before". Size the
/// capacity for the working set; at extreme scale put a
/// [`CountingBloomFilter`](crate::correlate::CountingBloomFilter)
/// in front as a probabilistic pre-filter.
///
/// Issue #134 (0.21).
#[derive(Debug)]
pub struct FirstSeen<K: Hash + Eq, S: BuildHasher = RandomState> {
    ttl: Duration,
    inner: LruCache<K, Seen, S>,
}

impl<K: Hash + Eq> FirstSeen<K> {
    /// New set with the given TTL and LRU capacity (clamped to
    /// ≥ 1).
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        Self::with_hasher(ttl, capacity, RandomState::new())
    }

    /// Unbounded variant — TTL (via [`Self::evict_expired`]) is
    /// the only bound. Uses `lru::LruCache::unbounded()` under
    /// the hood so no capacity allocation is attempted (a
    /// `new(ttl, usize::MAX)` would overflow hashbrown — same
    /// gotcha [`KeyIndexed::new_unbounded`](crate::correlate::KeyIndexed::new_unbounded)
    /// documents).
    pub fn new_unbounded(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: LruCache::unbounded_with_hasher(RandomState::new()),
        }
    }
}

impl<K: Hash + Eq, S: BuildHasher> FirstSeen<K, S> {
    /// [`Self::new`] with an explicit hasher builder.
    pub fn with_hasher(ttl: Duration, capacity: usize, hasher_builder: S) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).unwrap();
        Self {
            ttl,
            inner: LruCache::with_hasher(cap, hasher_builder),
        }
    }

    fn expired(&self, seen: &Seen, now: Timestamp) -> bool {
        now.saturating_sub(seen.last_seen) > self.ttl
    }

    /// Observe `key` at `now`. Returns `true` when this is a
    /// **new** sighting — first ever, expired (silent longer than
    /// the TTL), or evicted under LRU pressure — and `false` for
    /// a live repeat. Repeats refresh `last_seen` (and bump LRU
    /// recency); new sightings (re)set `first_seen = now`.
    pub fn observe(&mut self, key: K, now: Timestamp) -> bool {
        if let Some(seen) = self.inner.get_mut(&key) {
            if now.saturating_sub(seen.last_seen) > self.ttl {
                seen.first_seen = now;
                seen.last_seen = now;
                true
            } else {
                seen.last_seen = now;
                false
            }
        } else {
            self.inner.put(
                key,
                Seen {
                    first_seen: now,
                    last_seen: now,
                },
            );
            true
        }
    }

    /// `true` if `key` has a live (unexpired) sighting. Peek-based
    /// — does **not** refresh the TTL or bump LRU recency (mirror
    /// of [`KeyIndexed::peek`](crate::correlate::KeyIndexed::peek)).
    pub fn seen(&self, key: &K, now: Timestamp) -> bool {
        self.inner
            .peek(key)
            .is_some_and(|seen| !self.expired(seen, now))
    }

    /// When `key`'s current live streak started, or `None` if the
    /// key is absent/expired. Peek-based.
    pub fn first_seen(&self, key: &K, now: Timestamp) -> Option<Timestamp> {
        self.inner
            .peek(key)
            .filter(|seen| !self.expired(seen, now))
            .map(|seen| seen.first_seen)
    }

    /// Drop `key`, returning its `first_seen` if it was present
    /// (expired or not).
    pub fn remove(&mut self, key: &K) -> Option<Timestamp> {
        self.inner.pop(key).map(|seen| seen.first_seen)
    }

    /// Reclaim entries whose TTL has lapsed relative to `now`.
    /// Expired entries are already invisible to [`Self::seen`] /
    /// [`Self::first_seen`]; this frees their memory.
    pub fn evict_expired(&mut self, now: Timestamp)
    where
        K: Clone,
    {
        let expired: Vec<K> = self
            .inner
            .iter()
            .filter(|(_, seen)| self.expired(seen, now))
            .map(|(k, _)| k.clone())
            .collect();
        for k in expired {
            self.inner.pop(&k);
        }
    }

    /// Entries currently stored (including expired-but-unswept).
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl<K: Hash + Eq, S: BuildHasher> crate::correlate::Mergeable for FirstSeen<K, S> {
    /// Set union keeping the **earliest** `first_seen` and
    /// **latest** `last_seen` per key — a min/max lattice fold,
    /// so the merge is commutative and associative. Keys present
    /// on one side only are inserted as-is. LRU recency order
    /// after a merge is arbitrary (merging happens off the hot
    /// path, per the [`Mergeable`](crate::correlate::Mergeable)
    /// contract).
    ///
    /// **Panics** if `ttl` or capacity differ — shards running
    /// with different expiry/bounding is a config bug.
    fn merge(&mut self, other: Self) {
        assert_eq!(
            self.ttl, other.ttl,
            "FirstSeen::merge requires matching ttl",
        );
        assert_eq!(
            self.inner.cap(),
            other.inner.cap(),
            "FirstSeen::merge requires matching capacity",
        );
        let mut other = other;
        while let Some((k, seen_other)) = other.inner.pop_lru() {
            match self.inner.get_mut(&k) {
                Some(seen_self) => {
                    if seen_other.first_seen < seen_self.first_seen {
                        seen_self.first_seen = seen_other.first_seen;
                    }
                    if seen_other.last_seen > seen_self.last_seen {
                        seen_self.last_seen = seen_other.last_seen;
                    }
                }
                None => {
                    self.inner.put(k, seen_other);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(secs: u32) -> Timestamp {
        Timestamp::new(secs, 0)
    }

    #[test]
    fn first_observe_is_new_second_is_not() {
        let mut f: FirstSeen<u32> = FirstSeen::new(Duration::from_secs(10), 16);
        assert!(f.observe(1, ts(0)));
        assert!(!f.observe(1, ts(1)));
        assert!(f.seen(&1, ts(2)));
    }

    #[test]
    fn ttl_expiry_makes_key_new_again_and_resets_first_seen() {
        let mut f: FirstSeen<u32> = FirstSeen::new(Duration::from_secs(10), 16);
        f.observe(1, ts(0));
        assert!(!f.seen(&1, ts(20)), "expired key is not seen");
        assert!(f.observe(1, ts(20)), "expired key is new again");
        assert_eq!(f.first_seen(&1, ts(21)), Some(ts(20)), "streak restarted");
    }

    #[test]
    fn continuous_sightings_refresh_ttl() {
        // ttl 8s; observed at t = 0, 5, 10 — each within 8s of the
        // previous, so the key never expires despite the streak
        // being longer than one TTL.
        let mut f: FirstSeen<u32> = FirstSeen::new(Duration::from_secs(8), 16);
        assert!(f.observe(1, ts(0)));
        assert!(!f.observe(1, ts(5)));
        assert!(!f.observe(1, ts(10)));
        assert_eq!(f.first_seen(&1, ts(10)), Some(ts(0)), "streak preserved");
    }

    #[test]
    fn seen_does_not_bump_lru_recency() {
        let mut f: FirstSeen<u32> = FirstSeen::new(Duration::from_secs(100), 2);
        f.observe(1, ts(0));
        f.observe(2, ts(1));
        // Peek at 1 — must NOT protect it from eviction.
        assert!(f.seen(&1, ts(2)));
        f.observe(3, ts(3)); // evicts LRU = key 1
        assert!(!f.seen(&1, ts(4)), "peek didn't protect key 1");
        assert!(f.seen(&2, ts(4)));
        assert!(f.seen(&3, ts(4)));
    }

    #[test]
    fn lru_eviction_causes_false_new_never_false_seen() {
        let mut f: FirstSeen<u32> = FirstSeen::new(Duration::from_secs(100), 2);
        f.observe(1, ts(0));
        f.observe(2, ts(1));
        f.observe(3, ts(2)); // evicts key 1
        assert!(f.observe(1, ts(3)), "evicted live key re-reports new");
    }

    #[test]
    fn evict_expired_reclaims_memory() {
        let mut f: FirstSeen<u32> = FirstSeen::new(Duration::from_secs(10), 16);
        f.observe(1, ts(0));
        f.observe(2, ts(15));
        assert_eq!(f.len(), 2);
        f.evict_expired(ts(15));
        assert_eq!(f.len(), 1, "key 1 expired and reclaimed");
        assert!(f.seen(&2, ts(15)));
    }

    #[test]
    fn remove_returns_first_seen() {
        let mut f: FirstSeen<u32> = FirstSeen::new(Duration::from_secs(10), 16);
        f.observe(1, ts(3));
        assert_eq!(f.remove(&1), Some(ts(3)));
        assert_eq!(f.remove(&1), None);
        assert!(f.is_empty());
    }

    #[test]
    fn unbounded_construction_works() {
        let mut f: FirstSeen<u64> = FirstSeen::new_unbounded(Duration::from_secs(1));
        for i in 0..10_000u64 {
            assert!(f.observe(i, ts(0)));
        }
        assert_eq!(f.len(), 10_000);
    }
}

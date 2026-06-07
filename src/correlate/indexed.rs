//! [`KeyIndexed`] — TTL'd LRU cache with packet-clock eviction.

use std::hash::Hash;
use std::num::NonZeroUsize;
use std::time::Duration;

use lru::LruCache;

use crate::Timestamp;

/// TTL'd LRU cache with packet-clock-driven eviction.
///
/// Stores `(V, insertion_ts)` per key. `get(&K, now)` returns
/// the value if the entry is still within TTL, else `None`.
/// Lazily evicts expired entries on `evict_expired(now)` calls.
///
/// Useful for DNS query/response correlation
/// (`KeyIndexed<TransactionId, Question>`), ICMP error tying
/// back to the original flow, and any other "request observed →
/// match response within N seconds" pattern.
#[derive(Debug)]
pub struct KeyIndexed<K, V>
where
    K: Hash + Eq,
{
    ttl: Duration,
    inner: LruCache<K, (V, Timestamp)>,
}

impl<K, V> KeyIndexed<K, V>
where
    K: Hash + Eq,
{
    /// Construct with `ttl` (per-entry lifetime) and `capacity`
    /// (LRU cap — when full, oldest entries are evicted to make
    /// room).
    ///
    /// `capacity` must be > 0.
    pub fn new(ttl: Duration, capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).unwrap();
        Self {
            ttl,
            inner: LruCache::new(cap),
        }
    }

    /// Insert / replace `key → value`. Records `ts` as the
    /// insertion timestamp for TTL accounting.
    pub fn insert(&mut self, key: K, value: V, ts: Timestamp) {
        self.inner.put(key, (value, ts));
    }

    /// Get the value for `key`, if the entry has not exceeded
    /// `ttl` relative to `now`. Bumps LRU recency on hit.
    ///
    /// Returns `None` if absent or expired. Expired entries
    /// remain in the cache until [`Self::evict_expired`] runs
    /// — they're just hidden from `get`.
    pub fn get(&mut self, key: &K, now: Timestamp) -> Option<&V> {
        let entry = self.inner.get(key)?;
        let inserted = entry.1;
        if now
            .to_duration()
            .saturating_sub(inserted.to_duration())
            > self.ttl
        {
            return None;
        }
        Some(&entry.0)
    }

    /// Read-only get — does NOT bump LRU recency. Use when the
    /// outer scope holds `&self` rather than `&mut self`, or when
    /// the access is incidental (logging / metrics) and shouldn't
    /// influence eviction order.
    ///
    /// Same TTL semantics as [`Self::get`]: returns `None` if the
    /// entry is absent or has aged past `ttl` relative to `now`.
    ///
    /// New in 0.10.0.
    pub fn peek(&self, key: &K, now: Timestamp) -> Option<&V> {
        let entry = self.inner.peek(key)?;
        let inserted = entry.1;
        if now
            .to_duration()
            .saturating_sub(inserted.to_duration())
            > self.ttl
        {
            return None;
        }
        Some(&entry.0)
    }

    /// Take the value out of the cache, if any.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.inner.pop(key).map(|(v, _)| v)
    }

    /// Number of entries currently held (may include expired
    /// entries until next `evict_expired`).
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl<K, V> KeyIndexed<K, V>
where
    K: Hash + Eq + Clone,
{
    /// Drop every entry whose age (relative to `now`) exceeds
    /// `ttl`. Safe to call frequently; bounded by the number of
    /// expired entries. Requires `K: Clone` because we collect
    /// keys before removing.
    pub fn evict_expired(&mut self, now: Timestamp) {
        let now_dur = now.to_duration();
        let expired: Vec<K> = self
            .inner
            .iter()
            .filter(|(_, (_, ts))| now_dur.saturating_sub(ts.to_duration()) > self.ttl)
            .map(|(k, _)| k.clone())
            .collect();
        for k in expired {
            self.inner.pop(&k);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_within_ttl() {
        let mut q: KeyIndexed<u16, String> = KeyIndexed::new(Duration::from_secs(5), 16);
        q.insert(42, "ok".into(), Timestamp::new(0, 0));
        assert_eq!(q.get(&42, Timestamp::new(3, 0)).map(|s| s.as_str()), Some("ok"));
    }

    #[test]
    fn get_past_ttl_returns_none() {
        let mut q: KeyIndexed<u16, String> = KeyIndexed::new(Duration::from_secs(5), 16);
        q.insert(42, "ok".into(), Timestamp::new(0, 0));
        assert!(q.get(&42, Timestamp::new(10, 0)).is_none());
    }

    #[test]
    fn evict_expired_drops_old_entries() {
        let mut q: KeyIndexed<u16, String> = KeyIndexed::new(Duration::from_secs(5), 16);
        q.insert(1, "a".into(), Timestamp::new(0, 0));
        q.insert(2, "b".into(), Timestamp::new(10, 0));
        q.evict_expired(Timestamp::new(20, 0));
        assert!(q.get(&1, Timestamp::new(20, 0)).is_none());
        // 2 is also past 5s TTL; both should be gone.
        assert!(q.get(&2, Timestamp::new(20, 0)).is_none());
    }

    #[test]
    fn remove_pops_value() {
        let mut q: KeyIndexed<u16, String> = KeyIndexed::new(Duration::from_secs(5), 16);
        q.insert(7, "seven".into(), Timestamp::new(0, 0));
        assert_eq!(q.remove(&7), Some("seven".to_string()));
        assert!(q.get(&7, Timestamp::new(1, 0)).is_none());
    }

    #[test]
    fn lru_evicts_when_capacity_exceeded() {
        let mut q: KeyIndexed<u16, String> = KeyIndexed::new(Duration::from_secs(60), 2);
        q.insert(1, "a".into(), Timestamp::new(0, 0));
        q.insert(2, "b".into(), Timestamp::new(0, 0));
        q.insert(3, "c".into(), Timestamp::new(0, 0));
        // Capacity 2: oldest (1) evicted by lru on the third insert.
        assert!(q.get(&1, Timestamp::new(1, 0)).is_none());
        assert!(q.get(&2, Timestamp::new(1, 0)).is_some());
        assert!(q.get(&3, Timestamp::new(1, 0)).is_some());
    }
}

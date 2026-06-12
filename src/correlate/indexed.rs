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

    /// Unbounded LRU capacity convenience constructor.
    /// Uses `lru::LruCache::unbounded()` under the hood so no
    /// pre-allocation happens — entries are added as needed.
    /// Prefer [`Self::new`] with an explicit cap when memory
    /// pressure matters.
    ///
    /// New in 0.12.0; backing fixed to `lru::unbounded()` in
    /// 0.13 (plan 154 follow-up — `new(ttl, usize::MAX)` caused
    /// hashbrown capacity overflow on insert).
    pub fn new_unbounded(ttl: Duration) -> Self {
        Self {
            ttl,
            inner: LruCache::unbounded(),
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
        if now.to_duration().saturating_sub(inserted.to_duration()) > self.ttl {
            return None;
        }
        Some(&entry.0)
    }

    /// Get the value for `key` with mutable access, if the
    /// entry has not exceeded `ttl` relative to `now`. Bumps
    /// LRU recency on hit.
    ///
    /// Mirror of [`Self::get`] returning `&mut V`. Useful for
    /// callers wanting to mutate the cached value in place
    /// without a `remove` + `insert` dance.
    ///
    /// Plan 154 (0.13).
    pub fn get_mut(&mut self, key: &K, now: Timestamp) -> Option<&mut V> {
        let entry = self.inner.get_mut(key)?;
        let inserted = entry.1;
        if now.to_duration().saturating_sub(inserted.to_duration()) > self.ttl {
            return None;
        }
        Some(&mut entry.0)
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
        if now.to_duration().saturating_sub(inserted.to_duration()) > self.ttl {
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
    ///
    /// Inspecting variant: [`Self::drain_expired`] returns the
    /// expired entries as owned `(K, V)` pairs instead of
    /// discarding them.
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

    /// Drain entries whose TTL has elapsed at `now` and return
    /// them as owned `(K, V)` pairs in arbitrary order. Non-
    /// expired entries stay in the index.
    ///
    /// Companion to [`Self::evict_expired`] — use this when the
    /// caller needs to *inspect* expired entries (e.g. "DNS
    /// resolved but no connection followed", "ICMP didn't
    /// explain a flow death" patterns).
    ///
    /// Allocation: the underlying [`lru::LruCache`] exposes no
    /// `drain()`, so this method must collect expired keys
    /// into an intermediate `Vec` before popping. The resulting
    /// `Vec<(K, V)>` is the only externally-visible allocation.
    /// For amortized-allocation hot loops, use
    /// [`Self::drain_expired_into`] with a reusable buffer.
    ///
    /// Plan 160 (0.14).
    pub fn drain_expired(&mut self, now: Timestamp) -> Vec<(K, V)> {
        let mut out = Vec::new();
        self.drain_expired_into(now, &mut out);
        out
    }

    /// Append every entry whose TTL has elapsed at `now` to
    /// `out` (as owned `(K, V)` pairs) and return the number
    /// appended. Non-expired entries stay in the index.
    ///
    /// Mirrors the `track_into` / `drain_n` idiom (plans 119 +
    /// 149): preallocate `out` once, reuse it in the hot loop.
    ///
    /// Plan 160 (0.14).
    pub fn drain_expired_into(&mut self, now: Timestamp, out: &mut Vec<(K, V)>) -> usize {
        let start = out.len();
        let now_dur = now.to_duration();
        let expired_keys: Vec<K> = self
            .inner
            .iter()
            .filter(|(_, (_, ts))| now_dur.saturating_sub(ts.to_duration()) > self.ttl)
            .map(|(k, _)| k.clone())
            .collect();
        for k in expired_keys {
            if let Some((v, _ts)) = self.inner.pop(&k) {
                out.push((k, v));
            }
        }
        out.len() - start
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_within_ttl() {
        let mut q: KeyIndexed<u16, String> = KeyIndexed::new(Duration::from_secs(5), 16);
        q.insert(42, "ok".into(), Timestamp::new(0, 0));
        assert_eq!(
            q.get(&42, Timestamp::new(3, 0)).map(|s| s.as_str()),
            Some("ok")
        );
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

    // ── Plan 160 (0.14) — drain_expired tests ────────────────

    #[test]
    fn drain_expired_returns_empty_on_no_expiry() {
        let mut q: KeyIndexed<u16, String> = KeyIndexed::new(Duration::from_secs(60), 16);
        q.insert(1, "a".into(), Timestamp::new(0, 0));
        let drained = q.drain_expired(Timestamp::new(5, 0));
        assert!(drained.is_empty());
        assert!(q.get(&1, Timestamp::new(5, 0)).is_some());
    }

    #[test]
    fn drain_expired_returns_owned_pairs_on_full_expiry() {
        let mut q: KeyIndexed<u16, String> = KeyIndexed::new(Duration::from_secs(5), 16);
        q.insert(1, "a".into(), Timestamp::new(0, 0));
        q.insert(2, "b".into(), Timestamp::new(0, 0));
        let mut drained = q.drain_expired(Timestamp::new(20, 0));
        drained.sort_by_key(|(k, _)| *k);
        assert_eq!(drained, vec![(1, "a".into()), (2, "b".into())]);
        assert!(q.is_empty());
    }

    #[test]
    fn drain_expired_returns_partial_on_mixed_expiry() {
        let mut q: KeyIndexed<u16, String> = KeyIndexed::new(Duration::from_secs(5), 16);
        q.insert(1, "old".into(), Timestamp::new(0, 0));
        q.insert(2, "new".into(), Timestamp::new(15, 0));
        let drained = q.drain_expired(Timestamp::new(20, 0));
        assert_eq!(drained, vec![(1, "old".into())]);
        // The non-expired entry is still there.
        assert!(q.get(&2, Timestamp::new(20, 0)).is_some());
        assert_eq!(q.len(), 1);
    }

    #[test]
    fn drain_expired_after_drain_returns_empty() {
        let mut q: KeyIndexed<u16, String> = KeyIndexed::new(Duration::from_secs(5), 16);
        q.insert(1, "a".into(), Timestamp::new(0, 0));
        let first = q.drain_expired(Timestamp::new(20, 0));
        assert_eq!(first.len(), 1);
        let second = q.drain_expired(Timestamp::new(30, 0));
        assert!(second.is_empty(), "idempotent on second call");
    }

    #[test]
    fn drain_expired_into_appends_to_existing_vec() {
        let mut q: KeyIndexed<u16, String> = KeyIndexed::new(Duration::from_secs(5), 16);
        q.insert(1, "a".into(), Timestamp::new(0, 0));
        let mut out: Vec<(u16, String)> = vec![(99, "preexisting".into())];
        let appended = q.drain_expired_into(Timestamp::new(20, 0), &mut out);
        assert_eq!(appended, 1);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0], (99, "preexisting".into()));
        assert_eq!(out[1], (1, "a".into()));
    }

    #[test]
    fn drain_expired_into_returns_correct_count() {
        let mut q: KeyIndexed<u16, String> = KeyIndexed::new(Duration::from_secs(5), 16);
        q.insert(1, "a".into(), Timestamp::new(0, 0));
        q.insert(2, "b".into(), Timestamp::new(0, 0));
        q.insert(3, "c".into(), Timestamp::new(0, 0));
        let mut out = Vec::new();
        let n = q.drain_expired_into(Timestamp::new(20, 0), &mut out);
        assert_eq!(n, 3);
        assert_eq!(out.len(), 3);
    }

    #[test]
    fn drain_expired_leaves_non_expired_entries_intact() {
        let mut q: KeyIndexed<u16, String> = KeyIndexed::new(Duration::from_secs(5), 16);
        q.insert(1, "expired".into(), Timestamp::new(0, 0));
        q.insert(2, "fresh".into(), Timestamp::new(18, 0));
        let _ = q.drain_expired(Timestamp::new(20, 0));
        // Fresh entry's TTL is 18 → 20+5 = still valid at 20.
        assert!(q.get(&2, Timestamp::new(20, 0)).is_some());
        // And we can still drain it after another evict.
        let drained = q.drain_expired(Timestamp::new(40, 0));
        assert_eq!(drained, vec![(2, "fresh".into())]);
    }

    #[test]
    fn drain_expired_with_empty_cache_returns_empty() {
        let mut q: KeyIndexed<u16, String> = KeyIndexed::new(Duration::from_secs(5), 16);
        let drained = q.drain_expired(Timestamp::new(100, 0));
        assert!(drained.is_empty());
    }
}

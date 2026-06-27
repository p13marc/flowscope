//! [`BitStore`] — host/IP-pair/flow-keyed named bits + values with
//! per-entry TTL, modelled on Suricata's `xbits` / `hostbits`.
//!
//! The cross-flow stateful-analysis primitive that the existing
//! `correlate` reducers ([`RollingRate`](crate::correlate::RollingRate),
//! [`TopK`](crate::correlate::TopK),
//! [`WelfordStats`](crate::correlate::WelfordStats),
//! [`KeyIndexed`](crate::correlate::KeyIndexed)) don't cover: a
//! **namespace of named flags + small values per key**, each with
//! its own expiry. The canonical use is "set a `scanner` bit on
//! host X for 1h when the port-scan detector fires; later flows
//! from X check `is_set(X, "scanner")`."
//!
//! `KeyIndexed` stores *one* value per key; `BitStore` stores a
//! `name → (value, deadline)` map per key — that's the difference
//! that made it worth a new type rather than a wrapper.
//!
//! Names are `&'static str` (like
//! [`crate::well_known::LabelTable`]); for runtime-derived names
//! use `Box::leak`. Memory is bounded by [`BitStore::with_capacity`]
//! (new keys past the cap are dropped) and by calling
//! [`BitStore::expire`] to sweep elapsed entries.
//!
//! Tracker-clock aware: all `now` values are packet timestamps, so
//! live and offline pipelines behave identically.
//!
//! Issue #74 (child of #67).

use std::collections::HashMap;
use std::hash::Hash;
use std::time::Duration;

use crate::Timestamp;

/// Per-key namespace of named (value, deadline) entries with TTL.
#[derive(Debug, Clone)]
pub struct BitStore<K> {
    max_keys: usize,
    map: HashMap<K, HashMap<&'static str, Bit>>,
}

#[derive(Debug, Clone, Copy)]
struct Bit {
    value: u64,
    /// Absolute deadline as a duration since the epoch used by
    /// [`Timestamp::to_duration`].
    deadline: Duration,
}

impl<K: Hash + Eq> Default for BitStore<K> {
    fn default() -> Self {
        Self::unbounded()
    }
}

impl<K: Hash + Eq> BitStore<K> {
    /// Bounded to `max_keys` distinct keys. Setting a bit on a new
    /// key past the cap is dropped (returns `false`); updating an
    /// existing key always works.
    pub fn with_capacity(max_keys: usize) -> Self {
        Self {
            max_keys,
            map: HashMap::new(),
        }
    }

    /// Unbounded (cap = `usize::MAX`). Prefer [`Self::with_capacity`]
    /// in production and call [`Self::expire`] regularly.
    pub fn unbounded() -> Self {
        Self::with_capacity(usize::MAX)
    }

    /// Set `name = value` on `key`, expiring `ttl` after `now`.
    /// Returns `false` only if the key is new and the store is at
    /// capacity. Re-setting an existing name refreshes its value
    /// and deadline.
    pub fn set(&mut self, key: K, name: &'static str, value: u64, ttl: Duration, now: Timestamp) {
        let _ = self.set_checked(key, name, value, ttl, now);
    }

    /// Like [`Self::set`] but reports whether it was stored (`false`
    /// = dropped because a new key hit the capacity bound).
    pub fn set_checked(
        &mut self,
        key: K,
        name: &'static str,
        value: u64,
        ttl: Duration,
        now: Timestamp,
    ) -> bool {
        let deadline = now.to_duration().saturating_add(ttl);
        let bit = Bit { value, deadline };
        if let Some(entry) = self.map.get_mut(&key) {
            entry.insert(name, bit);
            return true;
        }
        if self.map.len() >= self.max_keys {
            return false;
        }
        let mut entry = HashMap::new();
        entry.insert(name, bit);
        self.map.insert(key, entry);
        true
    }

    /// Set a flag (`value = 1`) — the common xbits/hostbits case.
    pub fn set_flag(&mut self, key: K, name: &'static str, ttl: Duration, now: Timestamp) {
        self.set(key, name, 1, ttl, now);
    }

    /// Current value of `name` on `key`, or `None` if absent or
    /// expired at `now`. (Expired entries linger until
    /// [`Self::expire`] runs but are not returned.)
    pub fn get(&self, key: &K, name: &'static str, now: Timestamp) -> Option<u64> {
        let bit = self.map.get(key)?.get(name)?;
        if now.to_duration() >= bit.deadline {
            None
        } else {
            Some(bit.value)
        }
    }

    /// `true` if `name` is set and unexpired on `key`.
    pub fn is_set(&self, key: &K, name: &'static str, now: Timestamp) -> bool {
        self.get(key, name, now).is_some()
    }

    /// Remove `name` from `key` (e.g. Suricata `xbits unset`).
    /// Returns the value it held, if any. Drops the key if it
    /// becomes empty.
    pub fn unset(&mut self, key: &K, name: &'static str) -> Option<u64> {
        let entry = self.map.get_mut(key)?;
        let removed = entry.remove(name).map(|b| b.value);
        if entry.is_empty() {
            self.map.remove(key);
        }
        removed
    }

    /// Number of keys currently tracked (may include keys whose
    /// bits are all expired until [`Self::expire`] runs).
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// `true` if no keys are tracked.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Drop every expired bit (and any key left with no live bits).
    /// Safe to call frequently. Requires `K: Clone` to collect the
    /// keys to remove.
    pub fn expire(&mut self, now: Timestamp)
    where
        K: Clone,
    {
        let cutoff = now.to_duration();
        let mut empty_keys: Vec<K> = Vec::new();
        for (k, entry) in self.map.iter_mut() {
            entry.retain(|_, b| cutoff < b.deadline);
            if entry.is_empty() {
                empty_keys.push(k.clone());
            }
        }
        for k in empty_keys {
            self.map.remove(&k);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: u32) -> Timestamp {
        Timestamp::new(s, 0)
    }

    #[test]
    fn set_get_and_expiry() {
        let mut b: BitStore<u32> = BitStore::unbounded();
        b.set_flag(7, "scanner", Duration::from_secs(60), t(0));
        assert!(b.is_set(&7, "scanner", t(30)));
        assert_eq!(b.get(&7, "scanner", t(30)), Some(1));
        // Past TTL → not returned.
        assert!(!b.is_set(&7, "scanner", t(61)));
        assert!(b.get(&7, "scanner", t(61)).is_none());
    }

    #[test]
    fn values_and_namespaces_are_independent() {
        let mut b: BitStore<u32> = BitStore::unbounded();
        b.set(7, "score", 42, Duration::from_secs(10), t(0));
        b.set(7, "tries", 3, Duration::from_secs(10), t(0));
        assert_eq!(b.get(&7, "score", t(1)), Some(42));
        assert_eq!(b.get(&7, "tries", t(1)), Some(3));
        assert!(b.get(&8, "score", t(1)).is_none());
    }

    #[test]
    fn reset_refreshes_value_and_deadline() {
        let mut b: BitStore<u32> = BitStore::unbounded();
        b.set(1, "x", 1, Duration::from_secs(10), t(0));
        b.set(1, "x", 2, Duration::from_secs(10), t(8)); // refresh
        assert_eq!(b.get(&1, "x", t(15)), Some(2)); // still alive (deadline 18)
    }

    #[test]
    fn unset_removes_and_drops_empty_key() {
        let mut b: BitStore<u32> = BitStore::unbounded();
        b.set_flag(1, "x", Duration::from_secs(10), t(0));
        assert_eq!(b.unset(&1, "x"), Some(1));
        assert!(b.is_empty());
        assert_eq!(b.unset(&1, "x"), None);
    }

    #[test]
    fn expire_sweeps_dead_entries_and_keys() {
        let mut b: BitStore<u32> = BitStore::unbounded();
        b.set_flag(1, "a", Duration::from_secs(10), t(0));
        b.set_flag(1, "b", Duration::from_secs(100), t(0));
        b.set_flag(2, "a", Duration::from_secs(10), t(0));
        b.expire(t(50));
        // key 1 keeps "b"; key 2 fully expired → removed.
        assert_eq!(b.len(), 1);
        assert!(b.is_set(&1, "b", t(50)));
        assert!(!b.is_set(&1, "a", t(50)));
        assert!(b.get(&2, "a", t(50)).is_none());
    }

    #[test]
    fn capacity_bounds_new_keys() {
        let mut b: BitStore<u32> = BitStore::with_capacity(1);
        assert!(b.set_checked(1, "x", 1, Duration::from_secs(10), t(0)));
        assert!(!b.set_checked(2, "x", 1, Duration::from_secs(10), t(0))); // full
        // Existing key still updatable at capacity.
        assert!(b.set_checked(1, "y", 1, Duration::from_secs(10), t(0)));
        assert_eq!(b.len(), 1);
    }
}

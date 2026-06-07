//! [`TimeBucketedSet`] — TTL'd set keyed by `K` with value set
//! `V`. Cardinality + "entries above threshold" queries over a
//! sliding window.

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hash;
use std::time::Duration;

use crate::Timestamp;

/// Per-key set of `V` values over a sliding time window.
///
/// Useful for "distinct values seen per key within W" patterns
/// like port-scan detection (distinct destination ports per
/// source) or DNS-tunnel detection (distinct labels per source).
///
/// Like [`super::TimeBucketedCounter`], samples are bucketed at
/// `bucket_width` resolution; `cardinality(K, now)` counts the
/// distinct `V` for `K` over the buckets in `[now - window, now]`.
#[derive(Debug)]
pub struct TimeBucketedSet<K, V> {
    window: Duration,
    bucket_width: Duration,
    capacity: usize,
    buckets: VecDeque<(Timestamp, HashMap<K, HashSet<V>>)>,
}

impl<K, V> TimeBucketedSet<K, V>
where
    K: Hash + Eq + Clone,
    V: Hash + Eq + Clone,
{
    pub fn new(window: Duration, bucket_width: Duration, capacity: usize) -> Self {
        assert!(!bucket_width.is_zero(), "bucket_width must be > 0");
        Self {
            window,
            bucket_width,
            capacity,
            buckets: VecDeque::new(),
        }
    }

    /// Add `value` to the set for `key` at `now`.
    pub fn insert(&mut self, key: K, value: V, now: Timestamp) {
        self.evict_expired(now);
        let bucket_start = self.bucket_start_for(now);
        if let Some((ts, last)) = self.buckets.back_mut()
            && *ts == bucket_start
        {
            last.entry(key).or_default().insert(value);
            return;
        }
        let mut counts: HashMap<K, HashSet<V>> = HashMap::new();
        counts.entry(key).or_default().insert(value);
        self.buckets.push_back((bucket_start, counts));
    }

    /// Cardinality (distinct values) for `key` over the active
    /// window.
    pub fn cardinality(&self, key: &K, now: Timestamp) -> usize {
        let cutoff = self.cutoff_for(now);
        let mut seen: HashSet<&V> = HashSet::new();
        for (ts, by_key) in &self.buckets {
            if *ts < cutoff {
                continue;
            }
            if let Some(set) = by_key.get(key) {
                for v in set {
                    seen.insert(v);
                }
            }
        }
        seen.len()
    }

    /// Iterate `(key, cardinality)` pairs whose cardinality is
    /// `>= threshold`.
    pub fn entries_above(
        &self,
        threshold: usize,
        now: Timestamp,
    ) -> impl Iterator<Item = (K, usize)> {
        let cutoff = self.cutoff_for(now);
        let mut totals: HashMap<K, HashSet<V>> = HashMap::new();
        for (ts, by_key) in &self.buckets {
            if *ts < cutoff {
                continue;
            }
            for (k, set) in by_key {
                let dst = totals.entry(k.clone()).or_default();
                for v in set {
                    dst.insert(v.clone());
                }
            }
        }
        totals
            .into_iter()
            .map(|(k, set)| (k, set.len()))
            .filter(move |(_, n)| *n >= threshold)
    }

    /// Drop buckets older than `now - window`.
    pub fn evict_expired(&mut self, now: Timestamp) {
        let cutoff = self.cutoff_for(now);
        while let Some((ts, _)) = self.buckets.front() {
            if *ts < cutoff {
                self.buckets.pop_front();
            } else {
                break;
            }
        }
        // Soft capacity cap on the oldest bucket.
        let total_keys: usize = self.buckets.iter().map(|(_, m)| m.len()).sum();
        if total_keys > self.capacity
            && let Some((_, oldest)) = self.buckets.front_mut()
        {
            let drop_n = total_keys.saturating_sub(self.capacity);
            let mut entries: Vec<(K, HashSet<V>)> = oldest.drain().collect();
            entries.sort_by_key(|(_, set)| set.len());
            for (k, set) in entries.into_iter().skip(drop_n) {
                oldest.insert(k, set);
            }
        }
    }

    pub fn len(&self) -> usize {
        self.buckets.iter().map(|(_, m)| m.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty() || self.buckets.iter().all(|(_, m)| m.is_empty())
    }

    fn bucket_start_for(&self, ts: Timestamp) -> Timestamp {
        let nanos = ts.to_duration().as_nanos();
        let bw = self.bucket_width.as_nanos();
        let start_nanos = (nanos / bw) * bw;
        let start_dur = Duration::from_nanos(start_nanos as u64);
        Timestamp::new(start_dur.as_secs() as u32, start_dur.subsec_nanos())
    }

    fn cutoff_for(&self, now: Timestamp) -> Timestamp {
        let now_dur = now.to_duration();
        let cutoff_dur = now_dur.saturating_sub(self.window);
        Timestamp::new(cutoff_dur.as_secs() as u32, cutoff_dur.subsec_nanos())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cardinality_counts_distinct_values() {
        let mut s: TimeBucketedSet<u32, u16> =
            TimeBucketedSet::new(Duration::from_secs(60), Duration::from_secs(10), 1024);
        s.insert(1, 80, Timestamp::new(0, 0));
        s.insert(1, 80, Timestamp::new(1, 0));
        s.insert(1, 443, Timestamp::new(2, 0));
        s.insert(1, 22, Timestamp::new(3, 0));
        assert_eq!(s.cardinality(&1, Timestamp::new(5, 0)), 3);
    }

    #[test]
    fn cardinality_respects_window() {
        let mut s: TimeBucketedSet<u32, u16> =
            TimeBucketedSet::new(Duration::from_secs(10), Duration::from_secs(1), 1024);
        s.insert(1, 80, Timestamp::new(0, 0));
        s.insert(1, 443, Timestamp::new(50, 0));
        assert_eq!(s.cardinality(&1, Timestamp::new(50, 0)), 1);
    }

    #[test]
    fn entries_above_filters() {
        let mut s: TimeBucketedSet<u32, u16> =
            TimeBucketedSet::new(Duration::from_secs(60), Duration::from_secs(10), 1024);
        for p in [80, 443, 22, 25, 53] {
            s.insert(1, p, Timestamp::new(0, 0));
        }
        s.insert(2, 80, Timestamp::new(0, 0));
        let big: Vec<u32> = s.entries_above(3, Timestamp::new(5, 0)).map(|(k, _)| k).collect();
        assert_eq!(big, vec![1]);
    }

    #[test]
    fn evict_expired_drops_old_buckets() {
        let mut s: TimeBucketedSet<u32, u16> =
            TimeBucketedSet::new(Duration::from_secs(10), Duration::from_secs(1), 1024);
        s.insert(1, 80, Timestamp::new(0, 0));
        s.evict_expired(Timestamp::new(100, 0));
        assert!(s.is_empty());
    }
}

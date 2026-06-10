//! [`TimeBucketedCounter`] — windowed per-key event counter.
//!
//! Divides the observation window into `bucket_width`-sized
//! intervals. Each bucket holds a `HashMap<K, u64>` of event
//! counts. `count(&K, now)` sums across the buckets within
//! `[now - window, now]`.
//!
//! Older buckets are dropped lazily by `evict_expired(now)` —
//! consumers call this periodically (typically from `on_tick`).

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::time::Duration;

use crate::Timestamp;

/// Per-key event counter over a sliding time window.
///
/// The window is divided into fixed-width buckets; counts are
/// summed across buckets for queries. Lazily evicts buckets
/// older than `now - window` on demand.
#[derive(Debug)]
pub struct TimeBucketedCounter<K> {
    window: Duration,
    bucket_width: Duration,
    capacity: usize,
    /// Oldest-first deque of buckets. Each bucket is
    /// `(bucket_start_ts, counts)`.
    buckets: VecDeque<(Timestamp, HashMap<K, u64>)>,
}

impl<K> TimeBucketedCounter<K>
where
    K: Hash + Eq + Clone,
{
    /// Construct a new counter.
    ///
    /// `window` = total observation period; `bucket_width` =
    /// resolution; `capacity` = max distinct keys held across
    /// all buckets (best-effort, enforced by per-bucket cap).
    ///
    /// `bucket_width` must be ≥ 1 ns; `window` should be
    /// ≥ `bucket_width`.
    pub fn new(window: Duration, bucket_width: Duration, capacity: usize) -> Self {
        assert!(!bucket_width.is_zero(), "bucket_width must be > 0");
        Self {
            window,
            bucket_width,
            capacity,
            buckets: VecDeque::new(),
        }
    }

    /// Unbounded capacity convenience constructor — equivalent
    /// to `Self::new(window, bucket_width, usize::MAX)`. Prefer
    /// [`Self::new`] with an explicit cap when memory pressure
    /// matters; this avoids the cap arithmetic in code paths
    /// that don't need it. New in 0.12.0.
    pub fn new_unbounded(window: Duration, bucket_width: Duration) -> Self {
        Self::new(window, bucket_width, usize::MAX)
    }

    /// Increment the counter for `key` at `now`.
    pub fn bump(&mut self, key: K, now: Timestamp) {
        self.evict_expired(now);
        let bucket_start = self.bucket_start_for(now);

        // Find or create the bucket for this timestamp.
        // Buckets are oldest-first; we usually append.
        if let Some((ts, last)) = self.buckets.back_mut()
            && *ts == bucket_start
        {
            *last.entry(key).or_insert(0) += 1;
            return;
        }

        // Otherwise insert a new bucket (at the back).
        let mut counts = HashMap::new();
        counts.insert(key, 1);
        self.buckets.push_back((bucket_start, counts));
    }

    /// Sum counts for `key` across buckets within
    /// `[now - window, now]`. Buckets older than the window are
    /// excluded.
    pub fn count(&self, key: &K, now: Timestamp) -> u64 {
        let cutoff = self.cutoff_for(now);
        self.buckets
            .iter()
            .filter(|(ts, _)| *ts >= cutoff)
            .filter_map(|(_, counts)| counts.get(key).copied())
            .sum()
    }

    /// Iterate keys whose summed count is `>= threshold` over
    /// the active window.
    pub fn entries_above(
        &self,
        threshold: u64,
        now: Timestamp,
    ) -> impl Iterator<Item = (&K, u64)> + '_ {
        // Build a map of key → summed count by walking the
        // active buckets.
        let cutoff = self.cutoff_for(now);
        let mut totals: HashMap<&K, u64> = HashMap::new();
        for (ts, counts) in &self.buckets {
            if *ts < cutoff {
                continue;
            }
            for (k, c) in counts {
                *totals.entry(k).or_insert(0) += *c;
            }
        }
        totals.into_iter().filter(move |(_, c)| *c >= threshold)
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
        // Enforce capacity ceiling — drop the smallest-count
        // entries from the oldest bucket(s) if we're over.
        // Best-effort; this is a soft cap, not a hard one.
        let total_keys: usize = self.buckets.iter().map(|(_, m)| m.len()).sum();
        if total_keys > self.capacity
            && let Some((_, oldest)) = self.buckets.front_mut()
        {
            // Drop the lowest-frequency keys until under cap.
            let drop_n = total_keys.saturating_sub(self.capacity);
            let mut entries: Vec<(K, u64)> = oldest.drain().collect();
            entries.sort_by_key(|(_, c)| *c);
            for (k, c) in entries.into_iter().skip(drop_n) {
                oldest.insert(k, c);
            }
        }
    }

    /// Current number of distinct keys held across all live
    /// buckets (approximate; double-counts a key that appears
    /// in multiple buckets).
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
    fn count_sums_across_buckets() {
        let mut c: TimeBucketedCounter<u32> =
            TimeBucketedCounter::new(Duration::from_secs(60), Duration::from_secs(10), 1024);
        c.bump(1, Timestamp::new(0, 0));
        c.bump(1, Timestamp::new(15, 0));
        c.bump(1, Timestamp::new(30, 0));
        assert_eq!(c.count(&1, Timestamp::new(35, 0)), 3);
    }

    #[test]
    fn old_buckets_evicted() {
        let mut c: TimeBucketedCounter<u32> =
            TimeBucketedCounter::new(Duration::from_secs(60), Duration::from_secs(10), 1024);
        c.bump(1, Timestamp::new(0, 0));
        c.bump(1, Timestamp::new(120, 0)); // far past window
        // First bucket should be gone after eviction.
        assert_eq!(c.count(&1, Timestamp::new(120, 0)), 1);
    }

    #[test]
    fn entries_above_threshold() {
        let mut c: TimeBucketedCounter<u32> =
            TimeBucketedCounter::new(Duration::from_secs(60), Duration::from_secs(10), 1024);
        for _ in 0..5 {
            c.bump(1, Timestamp::new(0, 0));
        }
        for _ in 0..2 {
            c.bump(2, Timestamp::new(0, 0));
        }
        let now = Timestamp::new(5, 0);
        let big: Vec<_> = c.entries_above(3, now).map(|(k, _)| *k).collect();
        assert_eq!(big, vec![1]);
    }

    #[test]
    fn count_excludes_buckets_older_than_window() {
        let mut c: TimeBucketedCounter<u32> =
            TimeBucketedCounter::new(Duration::from_secs(10), Duration::from_secs(1), 1024);
        c.bump(1, Timestamp::new(0, 0));
        // Now well past the window — bucket at t=0 is excluded.
        assert_eq!(c.count(&1, Timestamp::new(60, 0)), 0);
    }
}

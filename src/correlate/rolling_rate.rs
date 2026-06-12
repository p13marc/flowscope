//! [`RollingRate<K, V>`] — per-key per-second rate over a
//! rolling window.
//!
//! Sibling to [`crate::correlate::TimeBucketedCounter<K>`]:
//! - `TimeBucketedCounter::bump(k, now)` adds **1** per call.
//! - `RollingRate::record(k, v, now)` adds **caller-supplied
//!   `V`** per call.
//! - `TimeBucketedCounter::count(k, now)` returns the raw
//!   `u64` sum over the window.
//! - `RollingRate::rate(k, now)` returns the **per-second
//!   `f64` rate** (sum / window_secs).
//!
//! Use `RollingRate<&'static str, u64>` for bandwidth
//! (bytes/sec), `RollingRate<&'static str, u64>` with
//! `record(k, 1, now)` for request-rate, or
//! `RollingRate<K, f64>` for latency-sum-per-sec.
//!
//! Plan 164 (0.14).

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::ops::AddAssign;
use std::time::Duration;

use crate::Timestamp;

/// Value types usable with [`RollingRate<K, V>`].
///
/// Sealed-style numeric trait: must support zero
/// initialisation, copy, accumulation, and a documented
/// `as f64` conversion. Implemented for the common
/// `u64` / `u32` / `i64` / `i32` / `f64` / `f32` value
/// types.
///
/// Custom newtype wrappers can implement this trait to plug
/// into `RollingRate` with semantic distinction (e.g. a
/// `Bytes(u64)` newtype that prevents accidental
/// `RollingRate<…, Bytes>` ↔ `RollingRate<…, RequestCount>`
/// crossover).
///
/// `as f64` precision: above `2^53` `u64` / `i64` values
/// lose precision in the cast. In practice this means ~9 PB
/// of accumulated bytes per window, which is implausible.
///
/// Plan 164 (0.14).
pub trait RateValue: Default + Copy + AddAssign + 'static {
    /// Convert to `f64` for the per-second rate arithmetic.
    fn as_f64(self) -> f64;
}

macro_rules! impl_rate_value {
    ($($t:ty),+) => {
        $(
            impl RateValue for $t {
                #[inline]
                fn as_f64(self) -> f64 { self as f64 }
            }
        )+
    };
}

impl_rate_value!(u64, u32, i64, i32, f64, f32);

/// Per-key rolling rate over a sliding time window.
///
/// See the module-level documentation
/// (`flowscope::correlate::rolling_rate`) for the design
/// shape — sibling to [`super::TimeBucketedCounter`] but
/// generic over the value type `V`.
#[derive(Debug)]
pub struct RollingRate<K, V>
where
    K: Hash + Eq,
    V: RateValue,
{
    window: Duration,
    bucket_width: Duration,
    /// Oldest-first deque of buckets — each is
    /// `(bucket_start_ts, per_key_sums)`. Same shape as
    /// [`crate::correlate::TimeBucketedCounter`].
    buckets: VecDeque<(Timestamp, HashMap<K, V>)>,
}

impl<K, V> RollingRate<K, V>
where
    K: Hash + Eq + Clone,
    V: RateValue,
{
    /// Unbounded `RollingRate` with the given `window` and
    /// `bucket_width`. Common values: `window = 60s`,
    /// `bucket_width = 1s` (matches Prometheus' `rate(…)`
    /// default).
    ///
    /// `bucket_width` must be > 0 and `window` should be
    /// `>= bucket_width`.
    pub fn new_unbounded(window: Duration, bucket_width: Duration) -> Self {
        assert!(!bucket_width.is_zero(), "bucket_width must be > 0");
        assert!(window >= bucket_width, "window must be >= bucket_width");
        Self {
            window,
            bucket_width,
            buckets: VecDeque::new(),
        }
    }

    /// Add `v` to the current bucket for `k` at `now`.
    ///
    /// **Zero-allocation** when `now` falls in the same
    /// bucket as the previous `record` call and `k` already
    /// exists in that bucket — the same trick
    /// [`crate::correlate::TimeBucketedCounter`] uses.
    pub fn record(&mut self, k: K, v: V, now: Timestamp) {
        self.evict_expired(now);
        let bucket_start = self.bucket_start_for(now);

        if let Some((ts, last)) = self.buckets.back_mut()
            && *ts == bucket_start
        {
            *last.entry(k).or_default() += v;
            return;
        }

        let mut bucket = HashMap::new();
        bucket.insert(k, v);
        self.buckets.push_back((bucket_start, bucket));
    }

    /// `sum(V over last window) / window_secs` — per-second
    /// rate for `k`. Returns `0.0` if `k` has no samples in
    /// the window.
    pub fn rate(&self, k: &K, now: Timestamp) -> f64 {
        let cutoff = self.cutoff_for(now);
        let mut sum: f64 = 0.0;
        for (ts, bucket) in &self.buckets {
            if *ts < cutoff {
                continue;
            }
            if let Some(v) = bucket.get(k) {
                sum += v.as_f64();
            }
        }
        sum / self.window.as_secs_f64()
    }

    /// Snapshot every key with a non-zero rate over the
    /// active window. Yields `(K, rate_per_sec)` pairs in
    /// arbitrary order — pair with
    /// [`crate::correlate::TopK`] to get a top-N report.
    ///
    /// Returns owned `K` clones (since one key can appear in
    /// multiple buckets and the iterator yields a single
    /// summed entry per key). Allocation: one `HashMap`
    /// internal + one `Vec` of pairs to back the returned
    /// iterator. Use [`Self::for_each_bucket`] for a
    /// callback-based zero-alloc alternative when the caller
    /// just wants to fold over the snapshot.
    pub fn snapshot(&self, now: Timestamp) -> impl Iterator<Item = (K, f64)> + '_ {
        let cutoff = self.cutoff_for(now);
        let window_secs = self.window.as_secs_f64();
        let mut totals: HashMap<K, V> = HashMap::new();
        for (ts, bucket) in &self.buckets {
            if *ts < cutoff {
                continue;
            }
            for (k, v) in bucket {
                let entry = totals.entry(k.clone()).or_default();
                *entry += *v;
            }
        }
        totals
            .into_iter()
            .map(move |(k, sum)| (k, sum.as_f64() / window_secs))
    }

    /// Visit every in-window `(key, rate)` pair with the
    /// caller's closure. Zero-allocation alternative to
    /// [`Self::snapshot`] for the common "fold across the
    /// snapshot" use case.
    ///
    /// Each key is visited **once per bucket** it appears in
    /// — the caller is responsible for summing across visits
    /// if they want a per-key total. For the most common case
    /// ("compute the top-N talkers"), pair with a
    /// `HashMap<K, f64>` accumulator, or use
    /// [`Self::snapshot`] (which does the summing internally).
    pub fn for_each_bucket<F>(&self, now: Timestamp, mut f: F)
    where
        F: FnMut(&K, V),
    {
        let cutoff = self.cutoff_for(now);
        for (ts, bucket) in &self.buckets {
            if *ts < cutoff {
                continue;
            }
            for (k, v) in bucket {
                f(k, *v);
            }
        }
    }

    /// Drop buckets older than `now - window`. Idempotent.
    pub fn evict_expired(&mut self, now: Timestamp) {
        let cutoff = self.cutoff_for(now);
        while let Some((ts, _)) = self.buckets.front() {
            if *ts < cutoff {
                self.buckets.pop_front();
            } else {
                break;
            }
        }
    }

    /// True if no buckets are tracked.
    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty() || self.buckets.iter().all(|(_, m)| m.is_empty())
    }

    /// Number of active buckets currently tracked. Bounded
    /// to `ceil(window / bucket_width)` once the window fills.
    pub fn bucket_count(&self) -> usize {
        self.buckets.len()
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

    fn rr_bytes() -> RollingRate<&'static str, u64> {
        RollingRate::new_unbounded(Duration::from_secs(60), Duration::from_secs(1))
    }

    #[test]
    #[should_panic(expected = "bucket_width must be > 0")]
    fn new_unbounded_panics_on_zero_bucket_width() {
        let _: RollingRate<&'static str, u64> =
            RollingRate::new_unbounded(Duration::from_secs(60), Duration::ZERO);
    }

    #[test]
    #[should_panic(expected = "window must be >= bucket_width")]
    fn new_unbounded_panics_when_window_lt_bucket_width() {
        let _: RollingRate<&'static str, u64> =
            RollingRate::new_unbounded(Duration::from_secs(1), Duration::from_secs(5));
    }

    #[test]
    fn single_record_then_rate_returns_v_over_window_secs() {
        let mut r = rr_bytes();
        r.record("http", 600, Timestamp::new(0, 0));
        // sum = 600, window = 60s → rate = 10 B/s.
        let rate = r.rate(&"http", Timestamp::new(5, 0));
        assert!((rate - 10.0).abs() < 1e-9);
    }

    #[test]
    fn multiple_records_same_bucket_sum() {
        let mut r = rr_bytes();
        r.record("http", 100, Timestamp::new(0, 0));
        r.record("http", 200, Timestamp::new(0, 100_000_000));
        r.record("http", 300, Timestamp::new(0, 500_000_000));
        // All three fall in the [0, 1s) bucket. sum = 600.
        let rate = r.rate(&"http", Timestamp::new(0, 600_000_000));
        assert!((rate - 10.0).abs() < 1e-9);
        assert_eq!(r.bucket_count(), 1);
    }

    #[test]
    fn records_across_buckets_aggregate_in_window() {
        let mut r = rr_bytes();
        r.record("http", 100, Timestamp::new(0, 0));
        r.record("http", 200, Timestamp::new(10, 0));
        r.record("http", 300, Timestamp::new(30, 0));
        // Sum = 600 within 60s window → rate = 10 B/s.
        let rate = r.rate(&"http", Timestamp::new(35, 0));
        assert!((rate - 10.0).abs() < 1e-9);
    }

    #[test]
    fn rate_zero_when_window_elapsed() {
        let mut r = rr_bytes();
        r.record("http", 600, Timestamp::new(0, 0));
        // Look far past the 60s window.
        let rate = r.rate(&"http", Timestamp::new(200, 0));
        assert_eq!(rate, 0.0);
    }

    #[test]
    fn rate_zero_for_unknown_key() {
        let mut r = rr_bytes();
        r.record("http", 600, Timestamp::new(0, 0));
        assert_eq!(r.rate(&"never_seen", Timestamp::new(5, 0)), 0.0);
    }

    #[test]
    fn snapshot_yields_every_in_window_key() {
        let mut r = rr_bytes();
        r.record("http", 600, Timestamp::new(0, 0));
        r.record("tls", 1200, Timestamp::new(10, 0));
        let snap: Vec<_> = r.snapshot(Timestamp::new(30, 0)).collect();
        assert_eq!(snap.len(), 2);
        assert!(snap.iter().any(|(k, _)| *k == "http"));
        assert!(snap.iter().any(|(k, _)| *k == "tls"));
    }

    #[test]
    fn snapshot_excludes_keys_past_window() {
        let mut r = rr_bytes();
        r.record("http", 600, Timestamp::new(0, 0));
        // Snapshot 120s later — past 60s window.
        let snap: Vec<_> = r.snapshot(Timestamp::new(120, 0)).collect();
        assert!(snap.is_empty());
    }

    #[test]
    fn evict_expired_drops_old_buckets_idempotent() {
        let mut r = rr_bytes();
        r.record("http", 600, Timestamp::new(0, 0));
        r.record("http", 100, Timestamp::new(120, 0));
        let before = r.bucket_count();
        r.evict_expired(Timestamp::new(125, 0));
        let after_first = r.bucket_count();
        r.evict_expired(Timestamp::new(125, 0));
        let after_second = r.bucket_count();
        assert!(after_first <= before);
        assert_eq!(
            after_first, after_second,
            "evict_expired idempotent on second call"
        );
    }

    #[test]
    fn record_in_same_bucket_does_not_grow_bucket_count() {
        let mut r = rr_bytes();
        for nanos in [0, 100_000_000u32, 200_000_000, 300_000_000] {
            r.record("http", 50, Timestamp::new(0, nanos));
        }
        // All four fall in the [0, 1s) bucket.
        assert_eq!(r.bucket_count(), 1, "same-bucket records share storage");
    }

    #[test]
    fn for_each_bucket_visits_every_in_window_entry() {
        let mut r = rr_bytes();
        r.record("http", 100, Timestamp::new(0, 0));
        r.record("tls", 200, Timestamp::new(10, 0));
        let mut visited: Vec<(String, u64)> = Vec::new();
        r.for_each_bucket(Timestamp::new(30, 0), |k, v| {
            visited.push((k.to_string(), v));
        });
        assert_eq!(visited.len(), 2);
    }

    #[test]
    fn rate_works_for_request_count_use_case() {
        // RollingRate<K, u64> with record(k, 1) for req/sec.
        let mut r: RollingRate<&'static str, u64> =
            RollingRate::new_unbounded(Duration::from_secs(60), Duration::from_secs(1));
        for sec in 0..60 {
            r.record("api", 1, Timestamp::new(sec, 0));
        }
        // 60 requests over 60s → 1.0 req/s.
        let rate = r.rate(&"api", Timestamp::new(60, 0));
        assert!((rate - 1.0).abs() < 1e-9);
    }

    #[test]
    fn rate_works_for_f64_value_type() {
        // Latency-sum tracking — V = f64.
        let mut r: RollingRate<&'static str, f64> =
            RollingRate::new_unbounded(Duration::from_secs(60), Duration::from_secs(1));
        r.record("/users", 0.5, Timestamp::new(0, 0));
        r.record("/users", 1.0, Timestamp::new(10, 0));
        // Sum = 1.5s / 60s = 0.025 latency-seconds-per-sec.
        let rate = r.rate(&"/users", Timestamp::new(30, 0));
        assert!((rate - (1.5 / 60.0)).abs() < 1e-9);
    }
}

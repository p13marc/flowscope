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
//! See also:
//! - [`crate::correlate::TimeBucketedCounter`] — `u64`
//!   counter-only sibling.
//! - [`crate::correlate::TopK`] — Misra-Gries heavy-hitter
//!   tracker with per-update sorting.
//! - [`crate::correlate::Ewma`] — smoothed (exponential)
//!   moving average for the same data shape.
//! - [`crate::correlate::BurstDetector`] — z-score spike
//!   detection over `TimeBucketedCounter`.
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

/// One time bucket: per-key sums, and the sum of the keys that did
/// not fit under the key cap.
#[derive(Debug)]
struct Bucket<K, V> {
    start: Timestamp,
    sums: HashMap<K, V>,
    /// Values of keys refused by the cap (`None` until one was).
    other: Option<V>,
}

impl<K: Hash + Eq, V: RateValue> Bucket<K, V> {
    fn new(start: Timestamp) -> Self {
        Self {
            start,
            sums: HashMap::new(),
            other: None,
        }
    }

    /// Add `v` for `k`, or to `other` when `k` is new and the bucket
    /// already holds `max_keys` keys. Returns whether it overflowed.
    fn add(&mut self, k: K, v: V, max_keys: usize) -> bool {
        if let Some(sum) = self.sums.get_mut(&k) {
            *sum += v;
            return false;
        }
        if self.sums.len() < max_keys {
            self.sums.insert(k, v);
            return false;
        }
        *self.other.get_or_insert_with(V::default) += v;
        true
    }
}

/// Per-key rolling rate over a sliding time window.
///
/// See the module-level documentation
/// (`flowscope::correlate::rolling_rate`) for the design
/// shape — sibling to [`super::TimeBucketedCounter`] but
/// generic over the value type `V`.
///
/// # Bounded memory
///
/// Keyed by whatever the caller records — often attacker-influenced
/// (addresses, ports, owners). [`Self::new`] caps the number of keys
/// each time bucket holds: once a bucket has `max_keys` keys, the
/// values of further new keys are summed into that bucket's
/// **overflow** total ([`Self::other_rate`] / [`Self::other_sum`]) and
/// counted in [`Self::overflowed`], so the table holds at most
/// `max_keys × buckets` entries, where `buckets` is at most
/// `window / bucket_width + 1` (see below for out-of-order time). A
/// key folded into the overflow total in a
/// bucket is missing from that bucket in [`Self::rate`],
/// [`Self::sum`], [`Self::snapshot`] and [`Self::top_k`].
/// [`Self::new_unbounded`] keeps every key. New in 0.26.0 (#220).
///
/// Timestamps may go backwards (several capture queues, a replay): a
/// record goes to the bucket of its own time, and evicts the buckets
/// before the window ending at its time *and* those more than a window
/// after it. The table therefore holds at most
/// `window / bucket_width + 1` buckets for time that only moves
/// forward, `2 × window / bucket_width + 1` in any order, and one wild
/// future timestamp is gone as soon as a record more than a window
/// earlier arrives (before 0.26 a timestamp that went back opened a
/// new bucket on every call).
#[derive(Debug)]
pub struct RollingRate<K, V>
where
    K: Hash + Eq,
    V: RateValue,
{
    window: Duration,
    bucket_width: Duration,
    /// Oldest-first deque of buckets. Same shape as
    /// [`crate::correlate::TimeBucketedCounter`].
    buckets: VecDeque<Bucket<K, V>>,
    /// Most keys one bucket holds.
    max_keys: usize,
    /// `record` calls whose key went to a bucket's overflow total.
    overflowed: u64,
}

impl<K, V> RollingRate<K, V>
where
    K: Hash + Eq + Clone,
    V: RateValue,
{
    /// `RollingRate` with the given `window` and `bucket_width`,
    /// holding at most `max_keys` keys per time bucket (see
    /// [Bounded memory](Self#bounded-memory)). Common values:
    /// `window = 60s`, `bucket_width = 1s` (matches Prometheus'
    /// `rate(…)` default).
    ///
    /// `bucket_width` must be > 0 and `window` should be
    /// `>= bucket_width`. `max_keys == 0` sends every value to the
    /// overflow total.
    ///
    /// ```
    /// use std::time::Duration;
    /// use flowscope::Timestamp;
    /// use flowscope::correlate::RollingRate;
    ///
    /// let mut r: RollingRate<u32, u64> =
    ///     RollingRate::new(Duration::from_secs(10), Duration::from_secs(1), 2);
    /// let now = Timestamp::new(0, 0);
    /// r.record(1, 100, now);
    /// r.record(2, 100, now);
    /// r.record(3, 50, now); // a third key: folded into the overflow total
    /// assert_eq!(r.sum(&3, now), 0);
    /// assert_eq!(r.other_sum(now), 50);
    /// assert_eq!(r.overflowed(), 1);
    /// ```
    ///
    /// New in 0.26.0 (#220).
    pub fn new(window: Duration, bucket_width: Duration, max_keys: usize) -> Self {
        assert!(!bucket_width.is_zero(), "bucket_width must be > 0");
        assert!(window >= bucket_width, "window must be >= bucket_width");
        Self {
            window,
            bucket_width,
            buckets: VecDeque::new(),
            max_keys,
            overflowed: 0,
        }
    }

    /// Unbounded `RollingRate`: [`Self::new`] with no key cap
    /// (`max_keys = usize::MAX`). Only for key spaces the caller
    /// controls.
    pub fn new_unbounded(window: Duration, bucket_width: Duration) -> Self {
        Self::new(window, bucket_width, usize::MAX)
    }

    /// Add `v` to the current bucket for `k` at `now` — or to the
    /// bucket's overflow total when `k` is new to a bucket that
    /// already holds [`Self::max_keys`] keys.
    ///
    /// **Zero-allocation** when `now` falls in the same
    /// bucket as the previous `record` call and `k` already
    /// exists in that bucket — the same trick
    /// [`crate::correlate::TimeBucketedCounter`] uses.
    pub fn record(&mut self, k: K, v: V, now: Timestamp) {
        // Timestamps may go backwards (several capture queues, a
        // replayed file, a corrupt record): a record lands in the
        // bucket of its own start — one bucket per start — and the
        // window ends at its own time. Buckets before that window
        // expire; buckets more than a window after it (time went back
        // further than a window, or an earlier record carried a wild
        // future timestamp) belong to no window ending here and go
        // too. So at most two windows' worth of buckets are held, and
        // one wild timestamp never holds the window.
        self.evict_expired(now);
        let future = now.to_duration().saturating_add(self.window);
        while self
            .buckets
            .back()
            .is_some_and(|b| b.start.to_duration() > future)
        {
            self.buckets.pop_back();
        }
        let bucket_start = self.bucket_start_for(now);

        let pos = match self.buckets.back() {
            // The common case: the newest bucket.
            Some(b) if b.start == bucket_start => self.buckets.len() - 1,
            Some(b) if b.start < bucket_start => {
                self.buckets.push_back(Bucket::new(bucket_start));
                self.buckets.len() - 1
            }
            None => {
                self.buckets.push_back(Bucket::new(bucket_start));
                0
            }
            // Out of order: find or insert its bucket.
            Some(_) => match self.buckets.iter().rposition(|b| b.start <= bucket_start) {
                Some(i) if self.buckets[i].start == bucket_start => i,
                Some(i) => {
                    self.buckets.insert(i + 1, Bucket::new(bucket_start));
                    i + 1
                }
                None => {
                    self.buckets.push_front(Bucket::new(bucket_start));
                    0
                }
            },
        };
        if self.buckets[pos].add(k, v, self.max_keys) {
            self.overflowed = self.overflowed.saturating_add(1);
        }
    }

    /// `sum(V over last window) / window_secs` — per-second
    /// rate for `k`. Returns `0.0` if `k` has no samples in
    /// the window.
    pub fn rate(&self, k: &K, now: Timestamp) -> f64 {
        // Buckets add in `f64`: their sum may not fit `V`.
        let cutoff = self.cutoff_for(now);
        let total: f64 = self
            .buckets
            .iter()
            .filter(|b| b.start >= cutoff)
            .filter_map(|b| b.sums.get(k))
            .map(|v| v.as_f64())
            .sum();
        total / self.window.as_secs_f64()
    }

    /// Per-second rate of the values folded into the overflow total
    /// over the window — the keys the cap refused, summed. `0.0`
    /// when nothing overflowed. New in 0.26.0.
    pub fn other_rate(&self, now: Timestamp) -> f64 {
        let cutoff = self.cutoff_for(now);
        let total: f64 = self
            .buckets
            .iter()
            .filter(|b| b.start >= cutoff)
            .filter_map(|b| b.other)
            .map(|v| v.as_f64())
            .sum();
        total / self.window.as_secs_f64()
    }

    /// Raw sum of the overflow total over the window (see
    /// [`Self::other_rate`]). New in 0.26.0.
    pub fn other_sum(&self, now: Timestamp) -> V {
        let cutoff = self.cutoff_for(now);
        let mut total = V::default();
        for b in self.buckets.iter().filter(|b| b.start >= cutoff) {
            if let Some(v) = b.other {
                total += v;
            }
        }
        total
    }

    /// Number of `record` calls whose key was folded into a bucket's
    /// overflow total because the bucket was full. Cumulative since
    /// construction (or [`Self::clear`]). New in 0.26.0.
    pub fn overflowed(&self) -> u64 {
        self.overflowed
    }

    /// The per-bucket key cap ([`Self::new`]; `usize::MAX` when
    /// unbounded). New in 0.26.0.
    pub fn max_keys(&self) -> usize {
        self.max_keys
    }

    /// Snapshot every key with a non-zero rate over the
    /// active window. Yields `(K, rate_per_sec)` pairs in
    /// arbitrary order — pair with
    /// [`crate::correlate::TopK`] to get a top-N report.
    /// The overflow total is not a key and is not included (see
    /// [`Self::other_rate`]).
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
        for b in self.buckets.iter().filter(|b| b.start >= cutoff) {
            for (k, v) in &b.sums {
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
        for b in self.buckets.iter().filter(|b| b.start >= cutoff) {
            for (k, v) in &b.sums {
                f(k, *v);
            }
        }
    }

    /// Drop buckets older than `now - window`. Idempotent.
    pub fn evict_expired(&mut self, now: Timestamp) {
        let cutoff = self.cutoff_for(now);
        while self.buckets.front().is_some_and(|b| b.start < cutoff) {
            self.buckets.pop_front();
        }
    }

    /// Raw sum of `V` over the active window for `k`. No
    /// per-second divide — sibling to [`Self::rate`] for the
    /// "bytes-in-the-last-minute" / "requests-in-the-last-5"
    /// report shape. Returns `V::default()` if `k` is absent
    /// or has no in-window samples.
    ///
    /// Plan 171 (0.14).
    pub fn sum(&self, k: &K, now: Timestamp) -> V {
        let cutoff = self.cutoff_for(now);
        let mut total = V::default();
        for b in self.buckets.iter().filter(|b| b.start >= cutoff) {
            if let Some(v) = b.sums.get(k) {
                total += *v;
            }
        }
        total
    }

    /// Sorted top-N entries by rate (descending). Ties are broken
    /// arbitrarily. Returns at most `n` entries; fewer if the
    /// in-window key count is smaller. `top_k(0)` returns an empty
    /// `Vec`.
    ///
    /// Lighter-weight than maintaining a separate
    /// [`super::TopK`] — `top_k` selects at query time
    /// (`O(keys + n log n)`), [`super::TopK`] sorts at update
    /// time. Pick the latter for hot paths.
    ///
    /// Plan 171 (0.14).
    pub fn top_k(&self, n: usize, now: Timestamp) -> Vec<(K, f64)> {
        top_n(self.snapshot(now).collect(), n)
    }

    /// Drop every recorded bucket and reset [`Self::overflowed`].
    /// After this call, [`Self::is_empty`] is `true`,
    /// [`Self::bucket_count`] is `0`, every [`Self::rate`] returns
    /// `0.0`, every [`Self::sum`] returns `V::default()`.
    ///
    /// Plan 171 (0.14).
    pub fn clear(&mut self) {
        self.buckets.clear();
        self.overflowed = 0;
    }

    /// True if no buckets are tracked at all. This is a
    /// **storage**-state query — it does NOT consider whether
    /// the tracked buckets are inside the current window.
    ///
    /// For an in-window count, use [`Self::len`].
    pub fn is_empty(&self) -> bool {
        self.buckets
            .iter()
            .all(|b| b.sums.is_empty() && b.other.is_none())
    }

    /// Number of unique keys observed in the active window at
    /// `now`. Outside-window keys are not counted. Allocates
    /// one transient `HashSet` — for zero-alloc, use
    /// [`Self::for_each_bucket`] with a caller-owned
    /// accumulator.
    ///
    /// Plan 171 (0.14).
    pub fn len(&self, now: Timestamp) -> usize {
        let cutoff = self.cutoff_for(now);
        let mut seen: std::collections::HashSet<&K> = std::collections::HashSet::new();
        for b in self.buckets.iter().filter(|b| b.start >= cutoff) {
            for k in b.sums.keys() {
                seen.insert(k);
            }
        }
        seen.len()
    }

    /// Number of active buckets currently tracked: at most
    /// `window / bucket_width + 1` for time that only moves forward,
    /// `2 × window / bucket_width + 1` in any order.
    pub fn bucket_count(&self) -> usize {
        self.buckets.len()
    }

    /// Keys stored across every tracked bucket (a key held by two
    /// buckets counts twice) — the table's size, at most
    /// `max_keys × bucket_count()`. New in 0.26.0.
    pub fn stored_entries(&self) -> usize {
        self.buckets.iter().map(|b| b.sums.len()).sum()
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

/// The `n` largest entries by rate, descending: a linear-time
/// selection of the top `n`, then a sort of those `n` only.
pub(crate) fn top_n<K>(mut v: Vec<(K, f64)>, n: usize) -> Vec<(K, f64)> {
    if n == 0 {
        return Vec::new();
    }
    // `total_cmp`: a total order even with NaN rates (an inconsistent
    // comparator may make the std sort and select functions panic).
    let desc = |a: &(K, f64), b: &(K, f64)| b.1.total_cmp(&a.1);
    if n < v.len() {
        v.select_nth_unstable_by(n - 1, desc);
        v.truncate(n);
    }
    v.sort_unstable_by(desc);
    v
}

impl<K, V> crate::correlate::Mergeable for RollingRate<K, V>
where
    K: Hash + Eq + Clone,
    V: RateValue,
{
    /// Sum values across aligned buckets. Keys beyond this table's
    /// [`RollingRate::max_keys`] in a bucket fold into its overflow
    /// total (and count in [`RollingRate::overflowed`], with `other`'s
    /// own count); overflow totals add.
    ///
    /// **Panics** if `window` / `bucket_width` don't match —
    /// silent realignment would mask config bugs.
    ///
    /// Issue #19 (Release A).
    fn merge(&mut self, other: Self) {
        assert_eq!(
            self.window, other.window,
            "RollingRate::merge requires matching window",
        );
        assert_eq!(
            self.bucket_width, other.bucket_width,
            "RollingRate::merge requires matching bucket_width",
        );
        self.overflowed = self.overflowed.saturating_add(other.overflowed);
        let max_keys = self.max_keys;
        for b in other.buckets {
            let pos = match self.buckets.iter().position(|mine| mine.start >= b.start) {
                Some(i) if self.buckets[i].start == b.start => i,
                Some(i) => {
                    self.buckets.insert(i, Bucket::new(b.start));
                    i
                }
                None => {
                    self.buckets.push_back(Bucket::new(b.start));
                    self.buckets.len() - 1
                }
            };
            let mine = &mut self.buckets[pos];
            for (k, v) in b.sums {
                if mine.add(k, v, max_keys) {
                    self.overflowed = self.overflowed.saturating_add(1);
                }
            }
            if let Some(v) = b.other {
                *mine.other.get_or_insert_with(V::default) += v;
            }
        }
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

    // ── Plan 171 (0.14) — completeness sweep tests ─────────

    #[test]
    fn sum_returns_raw_v_without_window_divide() {
        let mut r = rr_bytes();
        r.record("http", 100, Timestamp::new(0, 0));
        r.record("http", 200, Timestamp::new(10, 0));
        r.record("http", 300, Timestamp::new(30, 0));
        // sum = 600. rate = 600 / 60s = 10 B/s.
        let s = r.sum(&"http", Timestamp::new(35, 0));
        assert_eq!(s, 600);
        let rate = r.rate(&"http", Timestamp::new(35, 0));
        assert!((rate - (s as f64 / 60.0)).abs() < 1e-9);
    }

    #[test]
    fn sum_zero_for_absent_key() {
        let r = rr_bytes();
        assert_eq!(r.sum(&"http", Timestamp::new(0, 0)), 0);
    }

    #[test]
    fn sum_zero_for_outside_window_samples() {
        let mut r = rr_bytes();
        r.record("http", 600, Timestamp::new(0, 0));
        // Look 200s after — well past the 60s window.
        assert_eq!(r.sum(&"http", Timestamp::new(200, 0)), 0);
    }

    #[test]
    fn top_k_returns_sorted_descending() {
        let mut r = rr_bytes();
        r.record("a", 100, Timestamp::new(0, 0));
        r.record("b", 500, Timestamp::new(0, 0));
        r.record("c", 200, Timestamp::new(0, 0));
        r.record("d", 50, Timestamp::new(0, 0));
        r.record("e", 350, Timestamp::new(0, 0));

        let top3 = r.top_k(3, Timestamp::new(0, 100_000_000));
        assert_eq!(top3.len(), 3);
        assert_eq!(top3[0].0, "b"); // 500
        assert_eq!(top3[1].0, "e"); // 350
        assert_eq!(top3[2].0, "c"); // 200
        // Descending rates.
        assert!(top3[0].1 >= top3[1].1);
        assert!(top3[1].1 >= top3[2].1);
    }

    #[test]
    fn top_k_zero_returns_empty_vec_no_panic() {
        let mut r = rr_bytes();
        r.record("a", 100, Timestamp::new(0, 0));
        assert!(r.top_k(0, Timestamp::new(0, 100_000_000)).is_empty());
    }

    #[test]
    fn top_k_larger_than_keyset_returns_all() {
        let mut r = rr_bytes();
        r.record("a", 100, Timestamp::new(0, 0));
        r.record("b", 200, Timestamp::new(0, 0));
        let top = r.top_k(100, Timestamp::new(0, 100_000_000));
        assert_eq!(top.len(), 2);
    }

    #[test]
    fn clear_resets_everything() {
        let mut r = rr_bytes();
        r.record("a", 100, Timestamp::new(0, 0));
        r.record("b", 200, Timestamp::new(10, 0));
        assert!(!r.is_empty());

        r.clear();
        assert!(r.is_empty());
        assert_eq!(r.bucket_count(), 0);
        assert_eq!(r.rate(&"a", Timestamp::new(15, 0)), 0.0);
        assert_eq!(r.sum(&"a", Timestamp::new(15, 0)), 0);
        assert_eq!(r.len(Timestamp::new(15, 0)), 0);
    }

    #[test]
    fn len_counts_unique_keys_in_window() {
        let mut r = rr_bytes();
        r.record("a", 100, Timestamp::new(0, 0));
        r.record("b", 200, Timestamp::new(0, 0));
        r.record("a", 50, Timestamp::new(10, 0)); // dup key, different bucket
        r.record("c", 30, Timestamp::new(30, 0));
        assert_eq!(r.len(Timestamp::new(35, 0)), 3);
    }

    #[test]
    fn len_excludes_outside_window_keys() {
        let mut r = rr_bytes();
        r.record("old", 100, Timestamp::new(0, 0));
        r.record("new", 200, Timestamp::new(120, 0));
        // Window is 60s — only "new" is in-window at t=130.
        assert_eq!(r.len(Timestamp::new(130, 0)), 1);
    }

    #[test]
    fn len_empty_on_fresh_instance() {
        let r = rr_bytes();
        assert_eq!(r.len(Timestamp::new(0, 0)), 0);
    }

    // ── #220: bounded keys ─────────────────────────────────

    #[test]
    fn key_cap_bounds_the_table_and_counts_overflow() {
        let mut r: RollingRate<u32, u64> =
            RollingRate::new(Duration::from_secs(10), Duration::from_secs(1), 100);
        // 10 000 distinct keys, all in one bucket.
        for k in 0..10_000u32 {
            r.record(k, 10, Timestamp::new(0, k));
        }
        let now = Timestamp::new(0, 999_999_999);
        assert_eq!(r.bucket_count(), 1);
        assert!(r.stored_entries() <= 100 * r.bucket_count());
        assert_eq!(r.overflowed(), 9_900);
        assert_eq!(r.other_sum(now), 99_000);
        assert!(r.other_rate(now) > 0.0);
        assert_eq!(r.len(now), 100);
        // A stored key keeps accumulating; a refused one stays out.
        r.record(5, 1, now);
        assert_eq!(r.sum(&5, now), 11);
        r.record(9_999, 1, now);
        assert_eq!(r.sum(&9_999, now), 0);
        assert_eq!(r.overflowed(), 9_901);
        assert_eq!(r.max_keys(), 100);
    }

    #[test]
    fn key_cap_applies_per_bucket_and_bounds_every_bucket() {
        let mut r: RollingRate<u32, u64> =
            RollingRate::new(Duration::from_secs(5), Duration::from_secs(1), 10);
        for sec in 0..20u32 {
            for k in 0..1_000u32 {
                r.record(sec * 1_000 + k, 1, Timestamp::new(sec, k));
            }
            assert!(r.bucket_count() <= 6);
            assert!(r.stored_entries() <= 10 * r.bucket_count());
        }
        assert_eq!(r.overflowed(), 20 * 990);
        // Expired buckets take their overflow totals with them.
        assert_eq!(r.other_sum(Timestamp::new(100, 0)), 0);
        r.clear();
        assert!(r.is_empty());
        assert_eq!(r.overflowed(), 0);
    }

    #[test]
    fn unbounded_never_overflows() {
        let mut r = rr_bytes();
        assert_eq!(r.max_keys(), usize::MAX);
        r.record("a", 1, Timestamp::new(0, 0));
        assert_eq!((r.overflowed(), r.other_sum(Timestamp::new(0, 1))), (0, 0));
    }

    #[test]
    fn zero_cap_sends_everything_to_other() {
        let mut r: RollingRate<&'static str, u64> =
            RollingRate::new(Duration::from_secs(60), Duration::from_secs(1), 0);
        r.record("a", 7, Timestamp::new(0, 0));
        assert!(!r.is_empty(), "the overflow total is stored");
        assert_eq!(r.other_sum(Timestamp::new(0, 1)), 7);
        assert_eq!(r.len(Timestamp::new(0, 1)), 0);
    }

    #[test]
    fn merge_respects_the_cap() {
        use crate::correlate::Mergeable;
        let mut a: RollingRate<u32, u64> =
            RollingRate::new(Duration::from_secs(10), Duration::from_secs(1), 3);
        let mut b: RollingRate<u32, u64> =
            RollingRate::new(Duration::from_secs(10), Duration::from_secs(1), 3);
        let t = Timestamp::new(0, 0);
        for k in 0..3 {
            a.record(k, 1, t);
        }
        for k in 2..6 {
            b.record(k, 1, t); // key 5 overflows in b
        }
        a.merge(b);
        let now = Timestamp::new(0, 1);
        assert_eq!(a.sum(&2, now), 2, "shared key adds");
        assert_eq!(a.stored_entries(), 3);
        // b's overflow (1) + keys 3 and 4 refused by a's cap (2).
        assert_eq!(a.other_sum(now), 3);
        assert_eq!(a.overflowed(), 3);
    }

    proptest::proptest! {
        /// `top_k` (selection + partial sort) agrees with sorting
        /// every key.
        #[test]
        fn top_k_matches_a_full_sort(
            values in proptest::collection::vec((0u32..64, 1u64..1_000), 0..300),
            n in 0usize..80,
        ) {
            let mut r: RollingRate<u32, u64> =
                RollingRate::new_unbounded(Duration::from_secs(60), Duration::from_secs(1));
            for (i, (k, v)) in values.iter().enumerate() {
                r.record(*k, *v, Timestamp::new((i / 50) as u32, 0));
            }
            let now = Timestamp::new(10, 0);
            let got = r.top_k(n, now);
            let mut all: Vec<(u32, f64)> = r.snapshot(now).collect();
            all.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
            proptest::prop_assert_eq!(got.len(), n.min(all.len()));
            // Same rates in the same order (keys may differ on ties).
            let got_rates: Vec<f64> = got.iter().map(|e| e.1).collect();
            let want_rates: Vec<f64> = all.iter().take(n).map(|e| e.1).collect();
            proptest::prop_assert_eq!(got_rates, want_rates);
            for (k, rate) in &got {
                proptest::prop_assert_eq!(r.rate(k, now), *rate);
            }
        }
    }

    // Review findings: timestamps that go backwards.

    #[test]
    fn out_of_order_timestamps_reuse_their_bucket() {
        let mut r: RollingRate<u32, u64> =
            RollingRate::new(Duration::from_secs(60), Duration::from_secs(1), 10);
        // Two capture queues interleaving across a bucket boundary.
        for i in 0..1_000u32 {
            let now = if i % 2 == 0 {
                Timestamp::new(10, 0)
            } else {
                Timestamp::new(9, 999_000_000)
            };
            r.record(i % 20, 1, now);
        }
        assert_eq!(r.bucket_count(), 2, "one bucket per start");
        assert!(r.stored_entries() <= 2 * 10);
        let now = Timestamp::new(10, 1);
        assert_eq!(r.sum(&0, now) + r.sum(&1, now), 100);
    }

    #[test]
    fn backwards_timestamps_stay_within_the_window() {
        let mut r: RollingRate<u32, u64> =
            RollingRate::new(Duration::from_secs(10), Duration::from_secs(1), 10);
        r.record(1, 1, Timestamp::new(1_000, 0));
        for back in 1..500u32 {
            r.record(1, 1, Timestamp::new(1_000 - back, 0));
            // At most two windows around the latest record.
            assert!(r.bucket_count() <= 21, "{} buckets", r.bucket_count());
        }
        // The window ending at the last record (501) holds 501 ..= 511.
        assert_eq!(r.sum(&1, Timestamp::new(511, 0)), 11);
    }

    #[test]
    fn top_k_with_nan_rates_does_not_panic() {
        let mut r: RollingRate<u32, f64> =
            RollingRate::new_unbounded(Duration::from_secs(1), Duration::from_secs(1));
        for k in 0..200u32 {
            let v = if k % 7 == 0 { f64::NAN } else { f64::from(k) };
            r.record(k, v, Timestamp::new(0, k));
        }
        let top = r.top_k(10, Timestamp::new(0, 999));
        assert_eq!(top.len(), 10);
    }

    /// Rates add the buckets in `f64` (as 0.25 did): two buckets whose
    /// sum overflows `V` still give the right rate.
    #[test]
    fn rates_do_not_overflow_the_value_type() {
        let mut r: RollingRate<&'static str, u32> =
            RollingRate::new(Duration::from_secs(10), Duration::from_secs(1), 1);
        for s in 0..2 {
            r.record("a", 3_000_000_000, Timestamp::new(s, 0));
            r.record("b", 3_000_000_000, Timestamp::new(s, 0)); // overflow total
        }
        let now = Timestamp::new(1, 0);
        assert!((r.rate(&"a", now) - 6e8).abs() < 1e-3);
        assert!((r.other_rate(now) - 6e8).abs() < 1e-3);
    }

    /// One record far in the future (a corrupt timestamp) does not
    /// blind the table: the next record more than a window before it
    /// evicts its bucket, and later records count.
    #[test]
    fn a_far_future_record_does_not_drop_later_ones() {
        let mut r: RollingRate<u32, u64> =
            RollingRate::new(Duration::from_secs(10), Duration::from_secs(1), 10);
        r.record(1, 1, Timestamp::new(1_000_000, 0));
        for s in 0..20u32 {
            r.record(1, 1, Timestamp::new(s, 0));
        }
        let now = Timestamp::new(19, 0);
        assert_eq!(r.sum(&1, now), 11, "records at 9 ..= 19");
        assert!(r.bucket_count() <= 21);
    }
}

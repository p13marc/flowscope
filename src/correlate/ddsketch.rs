//! [`DdSketch`] + [`WindowedQuantiles`] — relative-error quantile
//! sketches (issue #134).
//!
//! [`DdSketch`] (Masson, Rim & Lee, VLDB '19) answers quantile
//! queries (p50 / p95 / p99 …) over a positive-valued stream with
//! a **relative** error guarantee `α` and bounded memory — the
//! bins are log-spaced, so a fixed bin budget covers many orders
//! of magnitude (bytes, nanoseconds, packet sizes). Unlike
//! [`aggregate::Percentile`](crate::aggregate::Percentile) (a
//! t-digest over the *whole* stream, behind the `aggregate`
//! feature) this lives in `correlate`, has no extra deps, and is
//! [`Mergeable`](crate::correlate::Mergeable) for RSS-sharded
//! union.
//!
//! [`WindowedQuantiles`] rotates DdSketches through time buckets
//! (the [`TimeBucketedCounter`](crate::correlate::TimeBucketedCounter)
//! shape) for *sliding-window* quantiles — "p99 latency over the
//! last 60 s" — evicting old buckets and merging the live ones on
//! query.
//!
//! Both are scalar (one instance per stream); key them in a
//! `HashMap` / `KeyIndexed` for per-flow use.

use std::collections::VecDeque;
use std::time::Duration;

use crate::Timestamp;

/// Relative-error quantile sketch over a positive-valued stream.
///
/// Values `≤ 0` are counted separately (`zero_count`) and treated
/// as exactly 0 in quantile answers. Positive values map to
/// log-spaced bins keyed by `⌈ln(x) / ln(γ)⌉` with
/// `γ = (1+α)/(1−α)`; a query for quantile `q` returns the bin's
/// representative value, guaranteed within relative error `α` of
/// the true value. Memory is capped at `max_bins` bins via a
/// **collapse-lowest** strategy (smallest values lose resolution
/// first — the right trade for tail-latency / large-value work).
#[derive(Debug, Clone, PartialEq)]
pub struct DdSketch {
    alpha: f64,
    max_bins: usize,
    /// `ln(γ)` reciprocal — key(x) = ⌈ln(x) · gamma_ln_recip⌉.
    gamma_ln_recip: f64,
    gamma: f64,
    /// Count for the bin whose key is `min_key + i`.
    bins: Vec<u64>,
    /// Key of `bins[0]` (only meaningful when `bins` is non-empty).
    min_key: i32,
    /// Count of values `≤ 0`.
    zero_count: u64,
    /// Total positive-value count (sum of `bins`), maintained
    /// incrementally so `quantile` doesn't re-sum every call.
    positive_count: u64,
}

impl DdSketch {
    /// New sketch with relative accuracy `alpha` (0 < α < 1;
    /// typical 0.01) and a hard `max_bins` budget (≥ 1; 2048 is a
    /// common choice — ~16 KiB, covers a huge dynamic range).
    pub fn new(alpha: f64, max_bins: usize) -> Self {
        assert!(alpha > 0.0 && alpha < 1.0, "alpha must be in (0, 1)");
        assert!(max_bins >= 1, "max_bins must be >= 1");
        let gamma = (1.0 + alpha) / (1.0 - alpha);
        Self {
            alpha,
            max_bins,
            gamma_ln_recip: 1.0 / gamma.ln(),
            gamma,
            bins: Vec::new(),
            min_key: 0,
            zero_count: 0,
            positive_count: 0,
        }
    }

    /// Bin key for a positive value.
    fn key_for(&self, x: f64) -> i32 {
        (x.ln() * self.gamma_ln_recip).ceil() as i32
    }

    /// Insert one observation.
    pub fn insert(&mut self, x: f64) {
        self.add_key_count(x, 1);
    }

    /// Insert `count` copies of `x` at once (used by merges and
    /// weighted feeds).
    pub fn add_key_count(&mut self, x: f64, count: u64) {
        if count == 0 {
            return;
        }
        if x <= 0.0 {
            self.zero_count += count;
            return;
        }
        let key = self.key_for(x);
        self.add_positive(key, count);
    }

    /// Core bin-mutation with grow / collapse-lowest bookkeeping.
    fn add_positive(&mut self, key: i32, count: u64) {
        self.positive_count += count;

        if self.bins.is_empty() {
            self.min_key = key;
            self.bins.push(count);
            return;
        }

        let max_key = self.min_key + self.bins.len() as i32 - 1;

        if key >= self.min_key && key <= max_key {
            self.bins[(key - self.min_key) as usize] += count;
            return;
        }

        if key > max_key {
            let needed = (key - self.min_key + 1) as usize;
            if needed <= self.max_bins {
                self.bins.resize(needed, 0);
                self.bins[(key - self.min_key) as usize] += count;
            } else {
                // Collapse-lowest: slide the window up so `key` fits,
                // folding evicted low bins into the new lowest bin.
                let new_min_key = key - self.max_bins as i32 + 1;
                self.collapse_below(new_min_key);
                self.bins.resize(self.max_bins, 0);
                self.bins[(key - self.min_key) as usize] += count;
            }
            return;
        }

        // key < min_key — extend downward if it fits, else fold
        // into the current lowest bin (collapse-lowest).
        let span = (max_key - key + 1) as usize;
        if span <= self.max_bins {
            let extra = (self.min_key - key) as usize;
            let mut new_bins = vec![0u64; extra];
            new_bins.extend_from_slice(&self.bins);
            self.bins = new_bins;
            self.min_key = key;
            self.bins[0] += count;
        } else {
            // Can't grow down without exceeding the budget — the
            // value is smaller than anything we can resolve, so it
            // joins the lowest bin.
            self.bins[0] += count;
        }
    }

    /// Fold all bins with key `< new_min_key` into the bin at
    /// `new_min_key`, then drop them. Leaves `min_key ==
    /// new_min_key`.
    fn collapse_below(&mut self, new_min_key: i32) {
        if new_min_key <= self.min_key {
            return;
        }
        let drop_n = (new_min_key - self.min_key) as usize;
        let drop_n = drop_n.min(self.bins.len());
        let folded: u64 = self.bins.drain(..drop_n).sum();
        self.min_key = new_min_key;
        if self.bins.is_empty() {
            self.bins.push(folded);
        } else {
            self.bins[0] += folded;
        }
    }

    /// Representative value for a bin key (bin midpoint in
    /// log-space): `2·γᵏ / (γ+1)`.
    fn value_for_key(&self, key: i32) -> f64 {
        2.0 * self.gamma.powi(key) / (self.gamma + 1.0)
    }

    /// Estimate the value at quantile `q ∈ [0, 1]`. Returns `None`
    /// only when the sketch is empty. Values counted as zero
    /// (`≤ 0`) participate at the low end.
    pub fn quantile(&self, q: f64) -> Option<f64> {
        let total = self.zero_count + self.positive_count;
        if total == 0 {
            return None;
        }
        let q = q.clamp(0.0, 1.0);
        // Rank in [0, total-1].
        let rank = (q * (total - 1) as f64).round() as u64;

        if rank < self.zero_count {
            return Some(0.0);
        }
        let mut cum = self.zero_count;
        for (i, &c) in self.bins.iter().enumerate() {
            cum += c;
            if rank < cum {
                return Some(self.value_for_key(self.min_key + i as i32));
            }
        }
        // Rounding edge → last populated bin.
        self.bins
            .iter()
            .rposition(|&c| c > 0)
            .map(|i| self.value_for_key(self.min_key + i as i32))
    }

    /// Total observations (including zeros).
    pub fn count(&self) -> u64 {
        self.zero_count + self.positive_count
    }

    /// `true` if nothing has been inserted.
    pub fn is_empty(&self) -> bool {
        self.count() == 0
    }

    /// Configured relative accuracy.
    pub fn alpha(&self) -> f64 {
        self.alpha
    }

    /// Reset to empty (keeps parameters).
    pub fn clear(&mut self) {
        self.bins.clear();
        self.min_key = 0;
        self.zero_count = 0;
        self.positive_count = 0;
    }
}

impl crate::correlate::Mergeable for DdSketch {
    /// Union another sketch. **Panics** if `alpha` or `max_bins`
    /// differ — a silent realign would corrupt the error
    /// guarantee.
    fn merge(&mut self, other: Self) {
        assert!(
            (self.alpha - other.alpha).abs() < f64::EPSILON,
            "DdSketch::merge alpha mismatch: {} vs {}",
            self.alpha,
            other.alpha
        );
        assert_eq!(
            self.max_bins, other.max_bins,
            "DdSketch::merge max_bins mismatch"
        );
        self.zero_count += other.zero_count;
        // Re-add each populated bin at its representative value —
        // reuses the grow/collapse path so the result honours our
        // own budget regardless of the other's window.
        for (i, &c) in other.bins.iter().enumerate() {
            if c > 0 {
                let key = other.min_key + i as i32;
                self.add_positive(key, c);
            }
        }
    }
}

/// Sliding-window quantiles: rotate [`DdSketch`]es through time
/// buckets so a query answers "quantile over the last `window`".
///
/// Mirrors [`TimeBucketedCounter`](crate::correlate::TimeBucketedCounter)'s
/// bucket rotation. `record` is O(1); `quantile` clones and
/// merges the live buckets (alloc per query, not per record).
#[derive(Debug, Clone)]
pub struct WindowedQuantiles {
    window: Duration,
    bucket_width: Duration,
    alpha: f64,
    max_bins: usize,
    buckets: VecDeque<(Timestamp, DdSketch)>,
}

impl WindowedQuantiles {
    /// New windowed sketch. `window` = observation period;
    /// `bucket_width` = resolution; `alpha` / `max_bins` size each
    /// per-bucket [`DdSketch`].
    pub fn new(window: Duration, bucket_width: Duration, alpha: f64, max_bins: usize) -> Self {
        assert!(!bucket_width.is_zero(), "bucket_width must be > 0");
        assert!(alpha > 0.0 && alpha < 1.0, "alpha must be in (0, 1)");
        assert!(max_bins >= 1, "max_bins must be >= 1");
        Self {
            window,
            bucket_width,
            alpha,
            max_bins,
            buckets: VecDeque::new(),
        }
    }

    fn bucket_start_for(&self, ts: Timestamp) -> Timestamp {
        let nanos = ts.to_duration().as_nanos();
        let bw = self.bucket_width.as_nanos();
        let start_nanos = (nanos / bw) * bw;
        let start_dur = Duration::from_nanos(start_nanos as u64);
        Timestamp::new(start_dur.as_secs() as u32, start_dur.subsec_nanos())
    }

    fn cutoff_for(&self, now: Timestamp) -> Timestamp {
        let cutoff_dur = now.to_duration().saturating_sub(self.window);
        Timestamp::new(cutoff_dur.as_secs() as u32, cutoff_dur.subsec_nanos())
    }

    /// Record `value` at `now`.
    pub fn record(&mut self, value: f64, now: Timestamp) {
        self.evict_expired(now);
        let bucket_start = self.bucket_start_for(now);
        if let Some((ts, sketch)) = self.buckets.back_mut()
            && *ts == bucket_start
        {
            sketch.insert(value);
            return;
        }
        let mut sketch = DdSketch::new(self.alpha, self.max_bins);
        sketch.insert(value);
        self.buckets.push_back((bucket_start, sketch));
    }

    /// Estimate quantile `q` over `[now - window, now]`. Returns
    /// `None` if no live observations. Clones + merges the active
    /// buckets — O(live buckets) allocation per call.
    pub fn quantile(&self, q: f64, now: Timestamp) -> Option<f64> {
        let cutoff = self.cutoff_for(now);
        let mut merged: Option<DdSketch> = None;
        for (ts, sketch) in &self.buckets {
            if *ts < cutoff {
                continue;
            }
            match &mut merged {
                Some(m) => crate::correlate::Mergeable::merge(m, sketch.clone()),
                None => merged = Some(sketch.clone()),
            }
        }
        merged.and_then(|m| m.quantile(q))
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
    }

    /// Live bucket count.
    pub fn len(&self) -> usize {
        self.buckets.len()
    }

    /// `true` if there are no buckets.
    pub fn is_empty(&self) -> bool {
        self.buckets.is_empty()
    }
}

impl crate::correlate::Mergeable for WindowedQuantiles {
    /// Union same-aligned buckets. **Panics** on window /
    /// bucket_width / alpha / max_bins mismatch.
    fn merge(&mut self, other: Self) {
        assert_eq!(
            self.window, other.window,
            "WindowedQuantiles window mismatch"
        );
        assert_eq!(
            self.bucket_width, other.bucket_width,
            "WindowedQuantiles bucket_width mismatch"
        );
        assert!(
            (self.alpha - other.alpha).abs() < f64::EPSILON,
            "WindowedQuantiles alpha mismatch"
        );
        assert_eq!(
            self.max_bins, other.max_bins,
            "WindowedQuantiles max_bins mismatch"
        );
        for (ts, sketch) in other.buckets {
            match self.buckets.iter_mut().find(|(t, _)| *t == ts) {
                Some((_, existing)) => crate::correlate::Mergeable::merge(existing, sketch),
                None => {
                    // Insert keeping oldest-first ordering.
                    let pos = self
                        .buckets
                        .iter()
                        .position(|(t, _)| *t > ts)
                        .unwrap_or(self.buckets.len());
                    self.buckets.insert(pos, (ts, sketch));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::correlate::Mergeable;

    use super::*;

    fn t(secs: u32) -> Timestamp {
        Timestamp::new(secs, 0)
    }

    #[test]
    fn quantile_within_relative_error() {
        let alpha = 0.01;
        let mut s = DdSketch::new(alpha, 2048);
        for i in 1..=1000 {
            s.insert(i as f64);
        }
        // p50 ≈ 500, p99 ≈ 990 within α relative error.
        let p50 = s.quantile(0.5).unwrap();
        assert!((p50 - 500.0).abs() / 500.0 <= alpha * 2.0, "p50={p50}");
        let p99 = s.quantile(0.99).unwrap();
        assert!((p99 - 990.0).abs() / 990.0 <= alpha * 2.0, "p99={p99}");
    }

    #[test]
    fn empty_sketch_returns_none() {
        let s = DdSketch::new(0.01, 128);
        assert!(s.quantile(0.5).is_none());
        assert!(s.is_empty());
    }

    #[test]
    fn zeros_participate_at_low_end() {
        let mut s = DdSketch::new(0.01, 128);
        for _ in 0..50 {
            s.insert(0.0);
        }
        for _ in 0..50 {
            s.insert(100.0);
        }
        assert_eq!(s.quantile(0.1).unwrap(), 0.0);
        assert!(s.quantile(0.9).unwrap() > 90.0);
    }

    #[test]
    fn wide_dynamic_range_stays_bounded() {
        let mut s = DdSketch::new(0.02, 128);
        // 1 ns to 1 s in nanoseconds — 9 orders of magnitude.
        for e in 0..=9 {
            for _ in 0..100 {
                s.insert(10f64.powi(e));
            }
        }
        assert!(s.bins.len() <= 128, "bin budget respected");
        // Median around 10^4-10^5 region.
        let p50 = s.quantile(0.5).unwrap();
        assert!(p50 > 1.0 && p50 < 1e9);
    }

    #[test]
    fn collapse_lowest_preserves_high_quantiles() {
        // Tiny budget forces collapse; high quantiles must survive.
        let mut s = DdSketch::new(0.05, 8);
        for i in 1..=10_000 {
            s.insert(i as f64);
        }
        assert!(s.bins.len() <= 8);
        let p99 = s.quantile(0.99).unwrap();
        // p99 true ≈ 9900; collapse-lowest keeps the top resolved.
        assert!(p99 > 5000.0, "p99={p99} should stay in the high range");
    }

    #[test]
    fn merge_equals_serial() {
        let mut a = DdSketch::new(0.01, 2048);
        let mut b = DdSketch::new(0.01, 2048);
        let mut serial = DdSketch::new(0.01, 2048);
        for i in 1..=500 {
            a.insert(i as f64);
            serial.insert(i as f64);
        }
        for i in 501..=1000 {
            b.insert(i as f64);
            serial.insert(i as f64);
        }
        a.merge(b);
        assert_eq!(a.count(), serial.count());
        // Quantiles agree within relative error.
        for q in [0.5, 0.9, 0.99] {
            let m = a.quantile(q).unwrap();
            let sq = serial.quantile(q).unwrap();
            assert!((m - sq).abs() / sq <= 0.05, "q={q} merged={m} serial={sq}");
        }
    }

    #[test]
    fn merge_is_commutative() {
        let build = |lo: u32, hi: u32| {
            let mut s = DdSketch::new(0.01, 1024);
            for i in lo..=hi {
                s.insert(i as f64);
            }
            s
        };
        let mut ab = build(1, 300);
        ab.merge(build(301, 600));
        let mut ba = build(301, 600);
        ba.merge(build(1, 300));
        assert_eq!(ab.quantile(0.5).unwrap(), ba.quantile(0.5).unwrap());
        assert_eq!(ab.quantile(0.95).unwrap(), ba.quantile(0.95).unwrap());
    }

    #[test]
    #[should_panic(expected = "alpha mismatch")]
    fn merge_alpha_mismatch_panics() {
        let mut a = DdSketch::new(0.01, 1024);
        let b = DdSketch::new(0.02, 1024);
        a.merge(b);
    }

    #[test]
    fn windowed_quantile_slides() {
        let mut w =
            WindowedQuantiles::new(Duration::from_secs(10), Duration::from_secs(1), 0.01, 512);
        // t=0..4: values ~100.
        for s in 0..5 {
            for _ in 0..20 {
                w.record(100.0, t(s));
            }
        }
        let p50_early = w.quantile(0.5, t(4)).unwrap();
        assert!((p50_early - 100.0).abs() / 100.0 < 0.05);

        // t=20: everything from t<10 has aged out.
        for _ in 0..20 {
            w.record(1000.0, t(20));
        }
        let p50_late = w.quantile(0.5, t(20)).unwrap();
        assert!((p50_late - 1000.0).abs() / 1000.0 < 0.05, "p50={p50_late}");
    }

    #[test]
    fn windowed_empty_returns_none() {
        let w = WindowedQuantiles::new(Duration::from_secs(10), Duration::from_secs(1), 0.01, 128);
        assert!(w.quantile(0.5, t(0)).is_none());
        assert!(w.is_empty());
    }

    #[test]
    fn windowed_merge_aligned_buckets() {
        let mk =
            || WindowedQuantiles::new(Duration::from_secs(60), Duration::from_secs(1), 0.01, 512);
        let mut a = mk();
        let mut b = mk();
        for _ in 0..10 {
            a.record(50.0, t(5));
            b.record(50.0, t(5));
        }
        a.merge(b);
        // Same bucket ts merged, not duplicated.
        assert_eq!(a.len(), 1);
        let p50 = a.quantile(0.5, t(5)).unwrap();
        assert!((p50 - 50.0).abs() / 50.0 < 0.05);
    }
}

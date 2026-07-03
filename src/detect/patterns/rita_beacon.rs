//! RITA-style robust beacon detector — Bowley skewness + median
//! absolute deviation (MADM), the quartile/median statistics from
//! [RITA](https://github.com/activecm/rita) v5
//! (`analysis/beacons.go`).
//!
//! Where [`BeaconDetector`](super::beacon::BeaconDetector) scores
//! periodicity with the coefficient of variation (σ/μ), this
//! detector uses **robust order statistics** that survive
//! outliers — a single missed beacon or a retransmit storm barely
//! moves a median, but wrecks a mean/stddev. That robustness is
//! exactly why RITA scores jittered C2 (e.g. Cobalt Strike's
//! default jitter) where CV does not.
//!
//! Per series (inter-arrival intervals, and payload sizes) it
//! computes, faithfully to RITA:
//!
//! ```text
//!   skewScore = 1 − |Bowley skewness|
//!             where  Bowley = (Q1 + Q3 − 2·Q2) / (Q3 − Q1)
//!             forced to 0 (→ skewScore 1.0) when the spread is
//!             tight: Q3−Q1 < 10, or Q2 == Q1, or Q2 == Q3.
//!   madScore  = (median − MAD) / median        (median ≥ 1)
//!             clamped to 0 when negative / NaN; a per-series
//!             default otherwise (1 for intervals, 0 for sizes).
//!   stat      = (skewScore + madScore) / 2
//! ```
//!
//! The composite score weights the **timestamp** and **data-size**
//! statistical scores plus a **duration** coverage bonus
//! (`ts·0.45 + ds·0.35 + dur·0.20`). RITA's additional
//! histogram/modal-fit score is **not** reproduced here; the two
//! statistical scores are the robust heart and are bit-faithful to
//! RITA's `calculateStatisticalScore`.
//!
//! Like the CV detector, suppresses chatty short-lived flows:
//! requires `n ≥ 10` observations AND mean interval ∈
//! `[min_interval, max_interval]` before scoring.
//!
//! Reference: <https://github.com/activecm/rita>
//! `analysis/beacons.go` (`calculateBowleySkewness`,
//! `calculateMedianAbsoluteDeviation`, `calculateStatisticalScore`).

use std::{
    collections::{HashMap, VecDeque},
    hash::Hash,
    time::Duration,
};

use crate::Timestamp;

/// Per-key RITA-style robust beacon detector.
pub struct RitaBeaconDetector<K>
where
    K: Hash + Eq + Clone,
{
    window: usize,
    min_interval: Duration,
    max_interval: Duration,
    duration_full_secs: f64,
    keys: HashMap<K, RitaState>,
}

#[derive(Debug, Clone)]
struct RitaState {
    samples: VecDeque<(Timestamp, u64)>,
}

/// Robust beacon score (0.0–1.0; higher = more beacon-like).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RitaBeaconScore<K> {
    pub key: K,
    /// Composite score, `ts·0.45 + ds·0.35 + dur·0.20`.
    pub score: f64,
    /// Timestamp (inter-arrival) statistical score `(skew+madm)/2`.
    pub ts_score: f64,
    /// Data-size statistical score `(skew+madm)/2`.
    pub ds_score: f64,
    /// Duration coverage bonus.
    pub dur_score: f64,
    /// Bowley skewness of the interval series (signed).
    pub ts_skew: f64,
    /// Median absolute deviation of the interval series (seconds).
    pub ts_mad: f64,
    /// Mean inter-arrival time over the window.
    pub mean_interval: Duration,
    /// Observations in the window.
    pub n: usize,
}

impl<K> RitaBeaconDetector<K>
where
    K: Hash + Eq + Clone,
{
    /// Default tuning: window=20, interval ∈ [10 s, 24 h],
    /// duration bonus saturates at 30 min — RITA's standard
    /// thresholds, matching [`BeaconDetector`](super::beacon::BeaconDetector).
    pub fn new() -> Self {
        Self {
            window: 20,
            min_interval: Duration::from_secs(10),
            max_interval: Duration::from_secs(24 * 60 * 60),
            duration_full_secs: 30.0 * 60.0,
            keys: HashMap::new(),
        }
    }

    pub fn with_window(mut self, window: usize) -> Self {
        assert!(window >= 3, "window must be ≥ 3 (Bowley needs 3 quartiles)");
        self.window = window;
        self
    }

    pub fn with_interval_range(mut self, min: Duration, max: Duration) -> Self {
        assert!(min <= max, "min_interval must be ≤ max_interval");
        self.min_interval = min;
        self.max_interval = max;
        self
    }

    /// Record one observation for `key`. Returns `Some` once the
    /// window holds ≥ 10 samples and the mean interval is in range.
    pub fn observe(&mut self, key: K, ts: Timestamp, bytes: u64) -> Option<RitaBeaconScore<K>> {
        let entry = self.keys.entry(key.clone()).or_insert(RitaState {
            samples: VecDeque::with_capacity(self.window),
        });
        if entry.samples.len() == self.window {
            entry.samples.pop_front();
        }
        entry.samples.push_back((ts, bytes));

        let n = entry.samples.len();
        if n < 10 {
            return None;
        }

        // Inter-arrival times in seconds.
        let ordered: Vec<(Timestamp, u64)> = entry.samples.iter().copied().collect();
        let mut intervals = Vec::with_capacity(n - 1);
        for w in ordered.windows(2) {
            intervals.push(w[1].0.saturating_sub(w[0].0).as_secs_f64());
        }
        let mean_dt = mean(&intervals);
        if mean_dt <= 0.0 {
            return None;
        }
        let mean_dur = Duration::from_secs_f64(mean_dt);
        if mean_dur < self.min_interval || mean_dur > self.max_interval {
            return None;
        }

        // Timestamp score: robust on the interval series (default MAD 1.0).
        let (ts_score, ts_skew, ts_mad) = statistical_score(&intervals, 1.0);
        // Data-size score: robust on the payload sizes (default MAD 0.0).
        let sizes: Vec<f64> = ordered.iter().map(|(_, b)| *b as f64).collect();
        let (ds_score, _, _) = statistical_score(&sizes, 0.0);

        // Duration coverage bonus.
        let span = ordered
            .last()
            .zip(ordered.first())
            .map(|(b, f)| b.0.saturating_sub(f.0).as_secs_f64())
            .unwrap_or(0.0);
        let dur_score = (span / self.duration_full_secs).clamp(0.0, 1.0);

        let score = (0.45 * ts_score + 0.35 * ds_score + 0.20 * dur_score).clamp(0.0, 1.0);

        Some(RitaBeaconScore {
            key,
            score,
            ts_score,
            ds_score,
            dur_score,
            ts_skew,
            ts_mad,
            mean_interval: mean_dur,
            n,
        })
    }

    /// Drop per-key state (call on flow end).
    pub fn forget(&mut self, key: &K) {
        self.keys.remove(key);
    }

    /// Number of keys currently tracked.
    pub fn tracked(&self) -> usize {
        self.keys.len()
    }
}

impl<K> Default for RitaBeaconDetector<K>
where
    K: Hash + Eq + Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "tracker")]
impl<K> RitaBeaconScore<K>
where
    K: crate::KeyFields + Clone,
{
    /// Convert into the canonical [`OwnedAnomaly`](crate::OwnedAnomaly)
    /// (severity `Warning` — `observe` only emits on a beacon-shaped
    /// pattern). Metrics: `score`, `ts_score`, `ds_score`,
    /// `dur_score`, `ts_skew`, `mean_interval_secs`, `n`.
    pub fn into_anomaly(self, ts: crate::Timestamp) -> crate::OwnedAnomaly {
        crate::OwnedAnomaly::new(
            crate::DetectorKind::BeaconRita,
            crate::event::Severity::Warning,
            ts,
        )
        .with_key(&self.key)
        .with_metric("score", self.score)
        .with_metric("ts_score", self.ts_score)
        .with_metric("ds_score", self.ds_score)
        .with_metric("dur_score", self.dur_score)
        .with_metric("ts_skew", self.ts_skew)
        .with_metric("mean_interval_secs", self.mean_interval.as_secs_f64())
        .with_metric("n", self.n as f64)
    }
}

#[cfg(feature = "tracker")]
impl<K> crate::DetectorScore for RitaBeaconScore<K>
where
    K: crate::KeyFields + Clone,
{
    fn kind(&self) -> crate::DetectorKind {
        crate::DetectorKind::BeaconRita
    }

    fn into_anomaly(self, ts: crate::Timestamp) -> crate::OwnedAnomaly {
        self.into_anomaly(ts)
    }
}

// ── robust statistics (faithful to RITA / montanaflynn-stats) ────────────────

fn mean(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    xs.iter().sum::<f64>() / xs.len() as f64
}

/// Median of an already-sorted slice. Even `n` → mean of the two
/// middle elements; odd `n` → the middle element.
fn median_sorted(sorted: &[f64]) -> f64 {
    let n = sorted.len();
    if n == 0 {
        return 0.0;
    }
    if n.is_multiple_of(2) {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    } else {
        sorted[n / 2]
    }
}

/// Quartiles via the montanaflynn-stats split RITA uses: for odd
/// `n` the median is excluded from both halves; for even `n` the
/// halves meet in the middle.
fn quartiles(sorted: &[f64]) -> (f64, f64, f64) {
    let n = sorted.len();
    let (c1, c2) = if n.is_multiple_of(2) {
        (n / 2, n / 2)
    } else {
        ((n - 1) / 2, (n - 1) / 2 + 1)
    };
    let q1 = median_sorted(&sorted[..c1]);
    let q2 = median_sorted(sorted);
    let q3 = median_sorted(&sorted[c2..]);
    (q1, q2, q3)
}

/// Bowley skewness + its score `1 − |skew|`. Skewness is forced to
/// 0 (score 1.0) when the spread is tight or degenerate, per RITA.
fn bowley_skew_score(sorted: &[f64]) -> (f64, f64) {
    if sorted.len() < 3 {
        return (0.0, 1.0);
    }
    let (q1, q2, q3) = quartiles(sorted);
    let den = q3 - q1;
    let skew = if den >= 10.0 && q2 != q1 && q2 != q3 {
        (q1 + q3 - 2.0 * q2) / den
    } else {
        0.0
    };
    (skew, 1.0 - skew.abs())
}

/// Median absolute deviation + its normalized score
/// `(median − MAD) / median`. Uses `default_score` when the median
/// is < 1; clamps a negative / NaN score to 0.
fn madm_score(sorted: &[f64], default_score: f64) -> (f64, f64) {
    if sorted.is_empty() {
        return (0.0, default_score);
    }
    let median = median_sorted(sorted);
    let mut devs: Vec<f64> = sorted.iter().map(|x| (x - median).abs()).collect();
    devs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mad = median_sorted(&devs);
    let mut score = default_score;
    if median >= 1.0 {
        score = (median - mad) / median;
    }
    if score < 0.0 || score.is_nan() {
        score = 0.0;
    }
    (mad, score)
}

/// RITA's `calculateStatisticalScore`: `(skewScore + madScore) / 2`.
/// Returns `(score, skew, mad)`.
fn statistical_score(values: &[f64], default_mad_score: f64) -> (f64, f64, f64) {
    if values.is_empty() {
        return (0.0, 0.0, 0.0);
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let (skew, skew_score) = bowley_skew_score(&sorted);
    let (mad, mad_score) = madm_score(&sorted, default_mad_score);
    ((skew_score + mad_score) / 2.0, skew, mad)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(sec: u32) -> Timestamp {
        Timestamp::new(sec, 0)
    }

    #[test]
    fn perfect_beacon_scores_high() {
        let mut d: RitaBeaconDetector<u32> = RitaBeaconDetector::new();
        let mut score = None;
        for i in 0..20 {
            score = d.observe(1, ts(i * 60), 100); // perfect 60s cadence, constant bytes
        }
        let s = score.expect("window full");
        // Constant intervals → tight spread → skewScore 1.0, MAD 0 → madScore 1.0.
        assert!((s.ts_score - 1.0).abs() < 1e-9, "ts_score = {}", s.ts_score);
        assert!((s.ds_score - 1.0).abs() < 1e-9, "ds_score = {}", s.ds_score);
        assert!(
            s.score > 0.85,
            "perfect beacon should score > 0.85, got {}",
            s.score
        );
    }

    #[test]
    fn fewer_than_ten_observations_yield_none() {
        let mut d: RitaBeaconDetector<u32> = RitaBeaconDetector::new();
        for i in 0..9 {
            assert!(d.observe(1, ts(i * 60), 100).is_none());
        }
    }

    #[test]
    fn random_intervals_score_low() {
        let mut d: RitaBeaconDetector<u32> = RitaBeaconDetector::new();
        // Wildly irregular intervals (still in the [10s,24h] band on average).
        let gaps = [
            30u32, 600, 45, 1200, 90, 15, 800, 200, 60, 1500, 20, 400, 1100, 35, 700, 120, 900, 25,
            500, 300,
        ];
        let mut t = 0u32;
        let mut score = None;
        for &g in &gaps {
            t += g;
            score = d.observe(1, ts(t), 100);
        }
        let s = score.expect("window full");
        assert!(
            s.ts_score < 0.8,
            "irregular timing should depress ts_score, got {}",
            s.ts_score
        );
    }

    #[test]
    fn outlier_robustness_beats_cv() {
        // A near-perfect 60s beacon with ONE missed beacon (a single
        // 600s gap). The median-based RITA score barely moves; the
        // mean/stddev CV score craters. This is the whole point.
        use super::super::beacon::BeaconDetector;
        let gaps: Vec<u32> = {
            let mut g = vec![60u32; 19];
            g[9] = 600; // one missed beacon → big outlier interval
            g
        };

        let mut rita: RitaBeaconDetector<u32> = RitaBeaconDetector::new();
        let mut cv: BeaconDetector<u32> = BeaconDetector::new();
        let mut t = 0u32;
        let (mut rita_s, mut cv_s) = (None, None);
        // Seed the first sample at t=0, then apply the 19 gaps → 20 samples.
        rita_s = rita.observe(1, ts(0), 100).or(rita_s);
        cv_s = cv.observe(1, ts(0), 100).or(cv_s);
        for &g in &gaps {
            t += g;
            rita_s = rita.observe(1, ts(t), 100).or(rita_s);
            cv_s = cv.observe(1, ts(t), 100).or(cv_s);
        }
        let r = rita_s.expect("rita window full");
        let c = cv_s.expect("cv window full");
        // The single outlier barely moves RITA's median-based score but
        // wrecks CV's mean/stddev: the outlier inflates `cv_dt` past 1, so
        // CV's `(1 − cv_dt)` term clamps to 0 and its composite craters.
        assert!(
            r.ts_score > 0.8,
            "RITA ts_score stays high despite outlier: {}",
            r.ts_score
        );
        assert!(
            c.cv_dt > 1.0,
            "the outlier should inflate CV's cv_dt: {}",
            c.cv_dt
        );
        assert!(
            r.score > c.score,
            "RITA ({}) should out-score CV ({}) on an outlier-jittered beacon",
            r.score,
            c.score
        );
    }

    #[test]
    fn chatty_short_interval_returns_none() {
        let mut d: RitaBeaconDetector<u32> = RitaBeaconDetector::new();
        let mut score = None;
        for i in 0..20 {
            score = d.observe(1, ts(i), 100); // 1s cadence < 10s min
        }
        assert!(score.is_none());
    }

    #[test]
    fn forget_and_isolation() {
        let mut d: RitaBeaconDetector<u32> = RitaBeaconDetector::new();
        for i in 0..20 {
            d.observe(1, ts(i * 60), 100);
        }
        assert_eq!(d.tracked(), 1);
        assert!(d.observe(2, ts(0), 100).is_none());
        assert_eq!(d.tracked(), 2);
        d.forget(&1);
        d.forget(&2);
        assert_eq!(d.tracked(), 0);
    }

    #[test]
    fn quartiles_match_montanaflynn_odd() {
        // 1..=9, montanaflynn: Q1=median(1..4)=2.5, Q2=5, Q3=median(6..9)=7.5
        let xs: Vec<f64> = (1..=9).map(|x| x as f64).collect();
        let (q1, q2, q3) = quartiles(&xs);
        assert_eq!((q1, q2, q3), (2.5, 5.0, 7.5));
    }

    #[test]
    fn quartiles_match_montanaflynn_even() {
        // 1..=8: Q1=median(1..4)=2.5, Q2=4.5, Q3=median(5..8)=6.5
        let xs: Vec<f64> = (1..=8).map(|x| x as f64).collect();
        let (q1, q2, q3) = quartiles(&xs);
        assert_eq!((q1, q2, q3), (2.5, 4.5, 6.5));
    }
}

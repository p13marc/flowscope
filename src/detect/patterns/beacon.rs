//! Coefficient-of-variation beacon detector — RITA-style.
//!
//! Per-key rolling window of inter-arrival times and byte
//! counts. Score range: 0.0 (no beacon) → 1.0 (perfect beacon).
//!
//! Composite score per the RITA reference:
//!
//! ```text
//!   score = 0.5 · (1 − CV_dt)
//!         + 0.3 · (1 − CV_bytes)
//!         + 0.2 · duration_bonus
//! ```
//!
//! Where:
//!
//! - `CV_dt`    = stddev / mean of inter-arrival intervals.
//! - `CV_bytes` = stddev / mean of payload byte counts.
//! - `duration_bonus` ≈ 1.0 when the rolling window spans at
//!   least 30 min, scaling linearly down to 0 at 0 s.
//!
//! Suppresses chatty short-lived flows: requires `n ≥ 10`
//! observations AND mean interval ∈ `[min_interval,
//! max_interval]` before scoring.
//!
//! Reference: <https://github.com/activecm/rita> (beacon CV
//! formula and thresholds).

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::time::Duration;

use crate::Timestamp;

/// Per-key beacon detector.
pub struct BeaconDetector<K>
where
    K: Hash + Eq + Clone,
{
    window: usize,
    min_interval: Duration,
    max_interval: Duration,
    duration_full_secs: f64,
    keys: HashMap<K, BeaconState>,
}

#[derive(Debug, Clone)]
struct BeaconState {
    /// Tail-most-recent rolling window of `(ts, bytes)` tuples.
    samples: VecDeque<(Timestamp, u64)>,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BeaconScore<K> {
    pub key: K,
    /// 0.0–1.0; higher = more beacon-like.
    pub score: f64,
    /// Mean inter-arrival time over the window.
    pub mean_interval: Duration,
    /// Coefficient of variation on inter-arrival times.
    pub cv_dt: f64,
    /// Coefficient of variation on byte counts.
    pub cv_bytes: f64,
    /// Observations in the window.
    pub n: usize,
}

impl<K> BeaconDetector<K>
where
    K: Hash + Eq + Clone,
{
    /// Default tuning: window=20, interval ∈ [10 s, 24 h],
    /// duration bonus saturates at 30 min. Matches RITA's
    /// standard thresholds.
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
        assert!(window >= 2, "window must be ≥ 2");
        self.window = window;
        self
    }

    pub fn with_interval_range(mut self, min: Duration, max: Duration) -> Self {
        assert!(min <= max, "min_interval must be ≤ max_interval");
        self.min_interval = min;
        self.max_interval = max;
        self
    }

    /// Record one observation for `key`. Returns `Some` once
    /// the window is full and the mean interval is in range.
    pub fn observe(&mut self, key: K, ts: Timestamp, bytes: u64) -> Option<BeaconScore<K>> {
        let entry = self.keys.entry(key.clone()).or_insert(BeaconState {
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
        let mut intervals = Vec::with_capacity(n - 1);
        for w in entry.samples.iter().collect::<Vec<_>>().windows(2) {
            let dt = w[1].0.saturating_sub(w[0].0);
            intervals.push(dt.as_secs_f64());
        }
        let mean_dt = mean(&intervals);
        if mean_dt <= 0.0 {
            return None;
        }
        let mean_dur = Duration::from_secs_f64(mean_dt);
        if mean_dur < self.min_interval || mean_dur > self.max_interval {
            return None;
        }
        let cv_dt = cv(&intervals, mean_dt);
        let byte_samples: Vec<f64> = entry.samples.iter().map(|(_, b)| *b as f64).collect();
        let mean_bytes = mean(&byte_samples);
        let cv_bytes = if mean_bytes > 0.0 {
            cv(&byte_samples, mean_bytes)
        } else {
            // No byte data → no CV penalty.
            0.0
        };
        let window_span_secs = entry
            .samples
            .back()
            .zip(entry.samples.front())
            .map(|(b, f)| b.0.saturating_sub(f.0).as_secs_f64())
            .unwrap_or(0.0);
        let duration_bonus = (window_span_secs / self.duration_full_secs).clamp(0.0, 1.0);

        let score = (0.5 * (1.0 - cv_dt).clamp(0.0, 1.0))
            + (0.3 * (1.0 - cv_bytes).clamp(0.0, 1.0))
            + (0.2 * duration_bonus);

        Some(BeaconScore {
            key,
            score: score.clamp(0.0, 1.0),
            mean_interval: mean_dur,
            cv_dt,
            cv_bytes,
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

impl<K> Default for BeaconDetector<K>
where
    K: Hash + Eq + Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

fn mean(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    xs.iter().sum::<f64>() / xs.len() as f64
}

/// Coefficient of variation (σ / μ). Returns 0 for μ ≤ 0.
fn cv(xs: &[f64], mean_value: f64) -> f64 {
    if mean_value <= 0.0 || xs.len() < 2 {
        return 0.0;
    }
    let var = xs.iter().map(|x| (x - mean_value).powi(2)).sum::<f64>() / (xs.len() - 1) as f64;
    var.sqrt() / mean_value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(sec: u32) -> Timestamp {
        Timestamp::new(sec, 0)
    }

    #[test]
    fn fewer_than_ten_observations_yield_none() {
        let mut d: BeaconDetector<u32> = BeaconDetector::new();
        for i in 0..9 {
            assert!(d.observe(1, ts(i * 60), 100).is_none());
        }
    }

    #[test]
    fn synthetic_perfect_beacon_scores_high() {
        let mut d: BeaconDetector<u32> = BeaconDetector::new();
        let mut score = None;
        for i in 0..20 {
            score = d.observe(1, ts(i * 60), 100); // perfect 60s cadence, constant bytes
        }
        let s = score.expect("window should be full");
        assert!(
            s.score > 0.85,
            "perfect beacon should score > 0.85, got {}",
            s.score
        );
        assert!(s.cv_dt < 0.01);
        assert!(s.cv_bytes < 0.01);
        assert_eq!(s.n, 20);
    }

    #[test]
    fn chatty_short_interval_returns_none() {
        let mut d: BeaconDetector<u32> = BeaconDetector::new();
        // 1s cadence — below the 10s default min_interval.
        let mut score = None;
        for i in 0..20 {
            score = d.observe(1, ts(i), 100);
        }
        assert!(score.is_none(), "<10s interval should suppress score");
    }

    #[test]
    fn very_long_interval_returns_none() {
        let mut d: BeaconDetector<u32> = BeaconDetector::new();
        // 30h cadence — above the 24h default max_interval.
        let mut score = None;
        for i in 0..20 {
            score = d.observe(1, ts(i * 30 * 3600), 100);
        }
        assert!(score.is_none(), ">24h interval should suppress score");
    }

    #[test]
    fn jittered_beacon_still_scores_meaningfully() {
        let mut d: BeaconDetector<u32> = BeaconDetector::new();
        let mut score = None;
        // 60s ± a small fraction jitter.
        let jitter = [
            0i32, 2, -2, 3, -1, 1, -3, 2, 0, -2, 1, -1, 3, 0, -2, 1, -1, 2, -3, 0,
        ];
        let mut t: i64 = 0;
        for &j in &jitter {
            t += 60 + j as i64;
            score = d.observe(1, ts(t as u32), 100);
        }
        let s = score.expect("window should be full");
        // Small jitter → CV ≈ 5% / 60s ≈ 0.05. Composite stays
        // high.
        assert!(
            s.score > 0.6,
            "jittered beacon should score > 0.6, got {} (cv_dt={})",
            s.score,
            s.cv_dt
        );
    }

    #[test]
    fn variable_bytes_lowers_score() {
        let mut d: BeaconDetector<u32> = BeaconDetector::new();
        let mut score = None;
        // Perfect timing, highly variable bytes.
        for i in 0..20 {
            let bytes = if i % 2 == 0 { 100 } else { 50_000 };
            score = d.observe(1, ts(i * 60), bytes);
        }
        let s = score.expect("window should be full");
        // CV_bytes penalty drops composite below the "perfect"
        // tier.
        assert!(s.cv_bytes > 0.5);
        assert!(s.score < 0.7);
    }

    #[test]
    fn per_key_isolation() {
        let mut d: BeaconDetector<u32> = BeaconDetector::new();
        for i in 0..20 {
            d.observe(1, ts(i * 60), 100);
        }
        assert_eq!(d.tracked(), 1);
        // Fresh key — still under the n threshold.
        assert!(d.observe(2, ts(0), 100).is_none());
        assert_eq!(d.tracked(), 2);
    }

    #[test]
    fn forget_drops_state() {
        let mut d: BeaconDetector<u32> = BeaconDetector::new();
        d.observe(1, ts(0), 100);
        assert_eq!(d.tracked(), 1);
        d.forget(&1);
        assert_eq!(d.tracked(), 0);
    }
}

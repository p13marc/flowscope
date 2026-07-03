//! Welford's online running statistics.
//!
//! Maintains `(count, mean, variance, min, max)` over a stream
//! of `f64` values without storing the raw observations. The
//! variance update uses Welford's algorithm (Knuth TAOCP
//! Vol. 2 §4.2.2) which is numerically stable for large
//! counts and avoids the catastrophic cancellation of the
//! naïve "sum + sum-of-squares" approach.
//!
//! Use cases inside flowscope:
//!
//! - Per-flow inter-arrival-time (IAT) statistics — see
//!   [`crate::FlowStats::iat_flow`] and friends.
//! - Any detector accumulating real-valued samples (latency,
//!   header-length distribution, etc.).

/// Running stats over a stream of `f64`s. Tracks count, mean,
/// variance (via Welford's M2 form), min, and max.
///
/// `Default` produces an empty stats with `count = 0`,
/// `mean = 0`, `variance = 0`, `min = +inf`, `max = -inf`.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct WelfordStats {
    count: u64,
    mean: f64,
    /// Sum of squared deviations from the running mean
    /// (Welford's M2). Divide by `count` for population
    /// variance or `count - 1` for sample variance.
    m2: f64,
    /// `None` until the first observation. Stored as `Option`
    /// so the empty / serde-default state is JSON-safe (no
    /// `f64::INFINITY` that would serialise as `null`).
    min: Option<f64>,
    max: Option<f64>,
}

impl WelfordStats {
    /// Construct an empty stats. Same as [`Default::default`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one observation. Updates count, mean, M2,
    /// min, and max.
    pub fn observe(&mut self, value: f64) {
        self.count += 1;
        let delta = value - self.mean;
        self.mean += delta / self.count as f64;
        let delta2 = value - self.mean;
        self.m2 += delta * delta2;
        self.min = Some(self.min.map_or(value, |m| m.min(value)));
        self.max = Some(self.max.map_or(value, |m| m.max(value)));
    }

    /// Number of observations seen so far.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Running arithmetic mean, or `0.0` when count is zero.
    pub fn mean(&self) -> f64 {
        if self.count == 0 { 0.0 } else { self.mean }
    }

    /// Population variance — `M2 / count`. Returns `0.0`
    /// for fewer than 2 observations.
    pub fn variance_population(&self) -> f64 {
        if self.count < 2 {
            0.0
        } else {
            self.m2 / self.count as f64
        }
    }

    /// Sample (Bessel-corrected) variance — `M2 / (count - 1)`.
    /// Returns `0.0` for fewer than 2 observations.
    pub fn variance_sample(&self) -> f64 {
        if self.count < 2 {
            0.0
        } else {
            self.m2 / (self.count - 1) as f64
        }
    }

    /// Sample standard deviation — `sqrt(variance_sample)`.
    /// Returns `0.0` for fewer than 2 observations.
    pub fn std(&self) -> f64 {
        self.variance_sample().sqrt()
    }

    /// Smallest value observed, or `0.0` when count is zero.
    pub fn min(&self) -> f64 {
        self.min.unwrap_or(0.0)
    }

    /// Largest value observed, or `0.0` when count is zero.
    pub fn max(&self) -> f64 {
        self.max.unwrap_or(0.0)
    }

    /// `true` when no observations have been recorded yet.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Reset to the empty state.
    pub fn clear(&mut self) {
        *self = Self::default();
    }

    /// Merge another `WelfordStats` into self. Combines two
    /// independent streams into the same running stats —
    /// useful when aggregating per-shard stats into a global
    /// view. Uses the parallel-merge form of Welford's
    /// algorithm (Chan, Golub, LeVeque 1979).
    ///
    /// The [`Mergeable`](crate::correlate::Mergeable) trait impl
    /// delegates here (issue #134); in generic sharded-reducer
    /// contexts prefer the trait bound.
    pub fn merge(&mut self, other: &WelfordStats) {
        if other.count == 0 {
            return;
        }
        if self.count == 0 {
            *self = *other;
            return;
        }
        let n_a = self.count as f64;
        let n_b = other.count as f64;
        let delta = other.mean - self.mean;
        let total = n_a + n_b;
        let new_mean = self.mean + delta * (n_b / total);
        let new_m2 = self.m2 + other.m2 + delta * delta * n_a * n_b / total;
        self.mean = new_mean;
        self.m2 = new_m2;
        self.count = total as u64;
        match (self.min, other.min) {
            (Some(a), Some(b)) => self.min = Some(a.min(b)),
            (None, Some(b)) => self.min = Some(b),
            _ => {}
        }
        match (self.max, other.max) {
            (Some(a), Some(b)) => self.max = Some(a.max(b)),
            (None, Some(b)) => self.max = Some(b),
            _ => {}
        }
    }
}

impl crate::correlate::Mergeable for WelfordStats {
    /// Delegates to the inherent by-ref [`WelfordStats::merge`]
    /// (Chan–Golub–LeVeque parallel form) — exact, commutative,
    /// associative. Issue #134.
    fn merge(&mut self, other: Self) {
        WelfordStats::merge(self, &other);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_stats_safe_defaults() {
        let s = WelfordStats::new();
        assert_eq!(s.count(), 0);
        assert_eq!(s.mean(), 0.0);
        assert_eq!(s.std(), 0.0);
        assert_eq!(s.min(), 0.0);
        assert_eq!(s.max(), 0.0);
        assert!(s.is_empty());
    }

    #[test]
    fn single_observation_pins_min_max_mean() {
        let mut s = WelfordStats::new();
        s.observe(42.0);
        assert_eq!(s.count(), 1);
        assert_eq!(s.mean(), 42.0);
        assert_eq!(s.min(), 42.0);
        assert_eq!(s.max(), 42.0);
        // Std needs >=2 observations.
        assert_eq!(s.std(), 0.0);
    }

    #[test]
    fn mean_matches_arithmetic() {
        let mut s = WelfordStats::new();
        for v in [1.0, 2.0, 3.0, 4.0, 5.0] {
            s.observe(v);
        }
        assert_eq!(s.count(), 5);
        assert!((s.mean() - 3.0).abs() < 1e-12);
        // Sample variance of [1..5] = 2.5; std = sqrt(2.5).
        assert!((s.variance_sample() - 2.5).abs() < 1e-12);
        assert!((s.std() - 2.5_f64.sqrt()).abs() < 1e-12);
        assert_eq!(s.min(), 1.0);
        assert_eq!(s.max(), 5.0);
    }

    #[test]
    fn merge_matches_serial_observe() {
        let mut serial = WelfordStats::new();
        for v in [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0] {
            serial.observe(v);
        }
        let mut a = WelfordStats::new();
        for v in [1.0, 2.0, 3.0, 4.0] {
            a.observe(v);
        }
        let mut b = WelfordStats::new();
        for v in [5.0, 6.0, 7.0, 8.0] {
            b.observe(v);
        }
        a.merge(&b);
        assert_eq!(a.count(), serial.count());
        assert!((a.mean() - serial.mean()).abs() < 1e-12);
        assert!((a.variance_sample() - serial.variance_sample()).abs() < 1e-12);
        assert_eq!(a.min(), serial.min());
        assert_eq!(a.max(), serial.max());
    }

    #[test]
    fn merge_empty_self_inherits_other() {
        let mut a = WelfordStats::new();
        let mut b = WelfordStats::new();
        b.observe(10.0);
        b.observe(20.0);
        a.merge(&b);
        assert_eq!(a.count(), 2);
        assert_eq!(a.mean(), 15.0);
        assert_eq!(a.min(), 10.0);
        assert_eq!(a.max(), 20.0);
    }

    #[test]
    fn merge_empty_other_no_op() {
        let mut a = WelfordStats::new();
        a.observe(7.0);
        let b = WelfordStats::new();
        a.merge(&b);
        assert_eq!(a.count(), 1);
        assert_eq!(a.mean(), 7.0);
    }

    #[test]
    fn clear_resets_to_default() {
        let mut s = WelfordStats::new();
        s.observe(1.0);
        s.observe(2.0);
        s.clear();
        assert!(s.is_empty());
        assert_eq!(s.mean(), 0.0);
    }

    #[test]
    fn population_vs_sample_variance() {
        let mut s = WelfordStats::new();
        for v in [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0] {
            s.observe(v);
        }
        // Known textbook example: population variance = 4, sample = 32/7.
        assert!((s.variance_population() - 4.0).abs() < 1e-12);
        assert!((s.variance_sample() - 32.0 / 7.0).abs() < 1e-12);
    }
}

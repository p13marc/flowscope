//! [`Histogram`] — explicit-bucket counter.

use std::fmt;

/// Explicit-bucket histogram for `f64` samples.
///
/// Constructed with sorted boundary values. Each boundary acts as
/// the upper edge of one bucket; samples are counted into the
/// lowest bucket whose upper edge is `> value`. Samples `>=` the
/// last boundary land in an overflow bucket.
///
/// `Histogram::with_buckets(&[0.1, 1.0, 10.0])` creates 4 buckets:
/// `[(-∞, 0.1)`, `[0.1, 1.0)`, `[1.0, 10.0)`, `[10.0, +∞))`.
#[derive(Debug, Clone)]
pub struct Histogram {
    boundaries: Vec<f64>,
    counts: Vec<u64>,
    samples: u64,
    min: f64,
    max: f64,
    sum: f64,
}

/// Histogram error type.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HistogramError {
    /// Empty / unsorted / non-finite boundary list passed to
    /// [`Histogram::with_buckets`] or related constructors.
    InvalidBoundaries,
    /// [`Histogram::merge`] called with a histogram whose
    /// boundaries don't match `self`'s.
    BoundariesMismatch,
}

impl fmt::Display for HistogramError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HistogramError::InvalidBoundaries => {
                f.write_str("histogram boundaries must be non-empty, sorted, and finite")
            }
            HistogramError::BoundariesMismatch => {
                f.write_str("histogram boundaries do not match merge target")
            }
        }
    }
}

impl std::error::Error for HistogramError {}

impl Histogram {
    /// Construct with explicit bucket boundaries. Boundaries must
    /// be sorted ascending, finite, and non-empty.
    ///
    /// Panics if any boundary is non-finite, the list is empty,
    /// or the list is unsorted. Use
    /// [`Self::try_with_buckets`] for a fallible variant.
    pub fn with_buckets(boundaries: &[f64]) -> Self {
        Self::try_with_buckets(boundaries).expect("invalid histogram boundaries")
    }

    /// Fallible variant of [`Self::with_buckets`].
    pub fn try_with_buckets(boundaries: &[f64]) -> Result<Self, HistogramError> {
        if boundaries.is_empty() || !boundaries.iter().all(|b| b.is_finite()) {
            return Err(HistogramError::InvalidBoundaries);
        }
        for w in boundaries.windows(2) {
            if w[0] >= w[1] {
                return Err(HistogramError::InvalidBoundaries);
            }
        }
        let counts = vec![0u64; boundaries.len() + 1];
        Ok(Self {
            boundaries: boundaries.to_vec(),
            counts,
            samples: 0,
            min: f64::INFINITY,
            max: f64::NEG_INFINITY,
            sum: 0.0,
        })
    }

    /// Log-spaced boundaries between `low` and `high` (geometric
    /// progression) producing `count + 1` buckets. Both `low` and
    /// `high` must be > 0 and `low < high`.
    pub fn log_spaced(low: f64, high: f64, count: usize) -> Self {
        assert!(low > 0.0 && high > low, "log_spaced needs 0 < low < high");
        assert!(count > 0, "log_spaced count must be > 0");
        let log_low = low.ln();
        let log_high = high.ln();
        let step = (log_high - log_low) / count as f64;
        let boundaries: Vec<f64> = (0..=count)
            .map(|i| (log_low + step * i as f64).exp())
            .collect();
        Self::with_buckets(&boundaries)
    }

    /// Record one sample.
    pub fn record(&mut self, value: f64) {
        if !value.is_finite() {
            return;
        }
        let idx = match self
            .boundaries
            .binary_search_by(|b| b.partial_cmp(&value).unwrap_or(std::cmp::Ordering::Equal))
        {
            // `value == boundaries[i]` → next bucket up (half-open).
            Ok(i) => i + 1,
            // `value` would insert at position `i` → bucket index `i`.
            Err(i) => i,
        };
        self.counts[idx] += 1;
        self.samples += 1;
        self.sum += value;
        if value < self.min {
            self.min = value;
        }
        if value > self.max {
            self.max = value;
        }
    }

    /// Approximate quantile (linear interpolation within the
    /// bucket containing the target rank). `q` is clamped to
    /// `[0.0, 1.0]`. Returns `0.0` if no samples recorded.
    pub fn quantile(&self, q: f64) -> f64 {
        if self.samples == 0 {
            return 0.0;
        }
        let q = q.clamp(0.0, 1.0);
        let target_rank = q * self.samples as f64;
        let mut running: f64 = 0.0;
        for (i, &c) in self.counts.iter().enumerate() {
            let next = running + c as f64;
            if next >= target_rank {
                let lo = if i == 0 {
                    self.min.min(self.boundaries[0])
                } else {
                    self.boundaries[i - 1]
                };
                let hi = if i == self.boundaries.len() {
                    self.max.max(*self.boundaries.last().unwrap())
                } else {
                    self.boundaries[i]
                };
                if c == 0 {
                    return lo;
                }
                let frac = (target_rank - running) / c as f64;
                return lo + (hi - lo) * frac.clamp(0.0, 1.0);
            }
            running = next;
        }
        self.max
    }

    pub fn samples(&self) -> u64 {
        self.samples
    }

    pub fn mean(&self) -> f64 {
        if self.samples == 0 {
            0.0
        } else {
            self.sum / self.samples as f64
        }
    }

    pub fn min(&self) -> f64 {
        if self.samples == 0 { 0.0 } else { self.min }
    }

    pub fn max(&self) -> f64 {
        if self.samples == 0 { 0.0 } else { self.max }
    }

    /// Merge `other` into `self`. Both histograms must have
    /// identical bucket boundaries.
    pub fn merge(&mut self, other: &Histogram) -> Result<(), HistogramError> {
        if self.boundaries != other.boundaries {
            return Err(HistogramError::BoundariesMismatch);
        }
        for (a, b) in self.counts.iter_mut().zip(other.counts.iter()) {
            *a += *b;
        }
        self.samples += other.samples;
        self.sum += other.sum;
        if other.samples > 0 {
            self.min = self.min.min(other.min);
            self.max = self.max.max(other.max);
        }
        Ok(())
    }

    /// Iterate `(upper_boundary, count)` pairs for rendering.
    /// The final entry uses `f64::INFINITY` as the upper edge of
    /// the overflow bucket.
    pub fn buckets(&self) -> impl Iterator<Item = (f64, u64)> + '_ {
        self.counts.iter().enumerate().map(|(i, &c)| {
            let upper = if i < self.boundaries.len() {
                self.boundaries[i]
            } else {
                f64::INFINITY
            };
            (upper, c)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn with_buckets_accepts_sorted_finite() {
        let h = Histogram::with_buckets(&[0.1, 1.0, 10.0]);
        // 3 boundaries → 4 buckets.
        assert_eq!(h.buckets().count(), 4);
    }

    #[test]
    fn try_with_buckets_rejects_unsorted() {
        let err = Histogram::try_with_buckets(&[1.0, 0.5]).unwrap_err();
        assert_eq!(err, HistogramError::InvalidBoundaries);
    }

    #[test]
    fn try_with_buckets_rejects_empty() {
        let err = Histogram::try_with_buckets(&[]).unwrap_err();
        assert_eq!(err, HistogramError::InvalidBoundaries);
    }

    #[test]
    fn try_with_buckets_rejects_non_finite() {
        let err = Histogram::try_with_buckets(&[1.0, f64::NAN, 3.0]).unwrap_err();
        assert_eq!(err, HistogramError::InvalidBoundaries);
    }

    #[test]
    fn record_counts_into_correct_bucket() {
        let mut h = Histogram::with_buckets(&[1.0, 10.0]);
        h.record(0.5); // first bucket (idx 0)
        h.record(5.0); // second bucket (idx 1)
        h.record(50.0); // overflow (idx 2)
        h.record(1.0); // exactly at boundary → next bucket
        let counts: Vec<u64> = h.buckets().map(|(_, c)| c).collect();
        assert_eq!(counts, vec![1, 2, 1]);
        assert_eq!(h.samples(), 4);
    }

    #[test]
    fn record_skips_non_finite() {
        let mut h = Histogram::with_buckets(&[1.0]);
        h.record(f64::NAN);
        h.record(f64::INFINITY);
        h.record(f64::NEG_INFINITY);
        assert_eq!(h.samples(), 0);
    }

    #[test]
    fn quantile_zero_samples_returns_zero() {
        let h = Histogram::with_buckets(&[1.0]);
        assert_eq!(h.quantile(0.5), 0.0);
    }

    #[test]
    fn quantile_returns_reasonable_estimate() {
        let mut h = Histogram::with_buckets(&[1.0, 10.0, 100.0]);
        for _ in 0..100 {
            h.record(5.0);
        }
        let p50 = h.quantile(0.5);
        // p50 must fall in the [1.0, 10.0) bucket.
        assert!((1.0..10.0).contains(&p50), "p50 = {p50}");
    }

    #[test]
    fn merge_combines_counts() {
        let mut a = Histogram::with_buckets(&[1.0, 10.0]);
        let mut b = Histogram::with_buckets(&[1.0, 10.0]);
        a.record(0.5);
        a.record(5.0);
        b.record(5.0);
        b.record(50.0);
        a.merge(&b).unwrap();
        let counts: Vec<u64> = a.buckets().map(|(_, c)| c).collect();
        assert_eq!(counts, vec![1, 2, 1]);
        assert_eq!(a.samples(), 4);
    }

    #[test]
    fn merge_rejects_mismatched_boundaries() {
        let mut a = Histogram::with_buckets(&[1.0]);
        let b = Histogram::with_buckets(&[2.0]);
        assert_eq!(a.merge(&b).unwrap_err(), HistogramError::BoundariesMismatch);
    }

    #[test]
    fn log_spaced_geometric_progression() {
        let h = Histogram::log_spaced(1.0, 1000.0, 3);
        let edges: Vec<f64> = h.buckets().take(3).map(|(b, _)| b).collect();
        // 1, 10, 100 (within rounding).
        assert!((edges[0] - 1.0).abs() < 1e-6);
        assert!((edges[1] - 10.0).abs() < 1e-6);
        assert!((edges[2] - 100.0).abs() < 1e-6);
    }

    #[test]
    fn mean_min_max() {
        let mut h = Histogram::with_buckets(&[10.0]);
        h.record(1.0);
        h.record(2.0);
        h.record(3.0);
        assert!((h.mean() - 2.0).abs() < 1e-9);
        assert_eq!(h.min(), 1.0);
        assert_eq!(h.max(), 3.0);
    }
}

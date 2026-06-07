//! [`Percentile`] — streaming quantile estimator backed by
//! `tdigest`.

use tdigest::TDigest;

/// Streaming quantile estimator.
///
/// Wraps a `tdigest::TDigest` under a batched-record API:
/// [`Self::record`] buffers samples; once the buffer fills, the
/// internal digest is merged with the buffer in one shot.
/// [`Self::quantile`] flushes any pending buffer first, then
/// queries the digest.
///
/// Accuracy is tightest near the tails (p99, p999). For wide
/// distributions where mid-quantile accuracy matters, prefer
/// [`super::Histogram`] with explicit buckets.
pub struct Percentile {
    digest: TDigest,
    pending: Vec<f64>,
    pending_cap: usize,
    samples: u64,
}

impl std::fmt::Debug for Percentile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Percentile")
            .field("samples", &self.samples)
            .field("pending", &self.pending.len())
            .finish_non_exhaustive()
    }
}

impl Percentile {
    /// Construct with `compression` ≈ the centroid budget. Higher
    /// means more accurate but more memory. Typical: 100–200.
    /// Values below 50 are clamped to 50.
    pub fn new(compression: u32) -> Self {
        Self {
            digest: TDigest::new_with_size(compression.max(50) as usize),
            pending: Vec::with_capacity(512),
            pending_cap: 512,
            samples: 0,
        }
    }

    /// Record one sample. Skips non-finite values.
    pub fn record(&mut self, value: f64) {
        if !value.is_finite() {
            return;
        }
        self.pending.push(value);
        self.samples += 1;
        if self.pending.len() >= self.pending_cap {
            self.flush();
        }
    }

    /// Approximate quantile `q ∈ [0.0, 1.0]`. Flushes any pending
    /// buffer before querying. Returns `0.0` if no samples have
    /// been recorded.
    pub fn quantile(&mut self, q: f64) -> f64 {
        self.flush();
        if self.samples == 0 {
            return 0.0;
        }
        self.digest.estimate_quantile(q.clamp(0.0, 1.0))
    }

    /// Total samples recorded.
    pub fn samples(&self) -> u64 {
        self.samples
    }

    fn flush(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        let buf = std::mem::take(&mut self.pending);
        self.digest = self.digest.merge_unsorted(buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_quantile_is_zero() {
        let mut p = Percentile::new(100);
        assert_eq!(p.quantile(0.5), 0.0);
        assert_eq!(p.samples(), 0);
    }

    #[test]
    fn uniform_distribution_p50_near_center() {
        let mut p = Percentile::new(200);
        for i in 0..10_000 {
            p.record(i as f64 / 10_000.0);
        }
        let p50 = p.quantile(0.5);
        assert!((p50 - 0.5).abs() < 0.05, "p50 = {p50}");
    }

    #[test]
    fn p99_estimate() {
        let mut p = Percentile::new(200);
        for i in 0..10_000 {
            p.record(i as f64 / 10_000.0);
        }
        let p99 = p.quantile(0.99);
        assert!((p99 - 0.99).abs() < 0.02, "p99 = {p99}");
    }

    #[test]
    fn non_finite_samples_skipped() {
        let mut p = Percentile::new(100);
        p.record(f64::NAN);
        p.record(f64::INFINITY);
        p.record(f64::NEG_INFINITY);
        assert_eq!(p.samples(), 0);
    }

    #[test]
    fn record_after_query_still_works() {
        let mut p = Percentile::new(100);
        for i in 0..100 {
            p.record(i as f64);
        }
        let _ = p.quantile(0.5);
        // Recording after a query (which flushed) must keep working.
        p.record(1000.0);
        assert_eq!(p.samples(), 101);
        let p99 = p.quantile(0.99);
        assert!(p99 > 90.0);
    }
}

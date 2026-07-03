//! [`EwmaVar`] — per-key exponentially weighted mean **and
//! variance** (West's incremental algorithm).

use std::{
    collections::HashMap,
    hash::{BuildHasher, Hash, RandomState},
    time::Duration,
};

use crate::Timestamp;

/// Snapshot of a key's exponentially weighted mean + variance.
///
/// Returned by [`EwmaVar::record_at`] / [`EwmaVar::get`]. Use
/// [`std`](Self::std) for the standard deviation and pair with
/// [`EwmaVar::zscore`] for N-sigma outlier queries.
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct EwmaVarValue {
    /// Exponentially weighted mean.
    pub mean: f64,
    /// Exponentially weighted variance.
    pub variance: f64,
}

impl EwmaVarValue {
    /// Standard deviation (`√variance`, clamped at zero).
    pub fn std(&self) -> f64 {
        self.variance.max(0.0).sqrt()
    }
}

/// Per-key exponentially weighted moving average **with
/// variance** — West's incremental exponentially-weighted
/// mean/variance update:
///
/// ```text
/// diff = sample - mean
/// incr = alpha * diff
/// mean' = mean + incr
/// var'  = (1 - alpha) * (var + diff * incr)
/// ```
///
/// `alpha ∈ (0, 1]`: smaller → smoother / slower-reacting;
/// `alpha = 1.0` tracks the most recent sample with zero
/// variance.
///
/// The variance axis is what N-sigma outlier detectors need —
/// "is this sample more than `n` standard deviations above the
/// key's own baseline?" ([`Self::zscore`]). The mean-only
/// sibling is [`Ewma`](crate::correlate::Ewma); the
/// non-decayed whole-stream sibling is
/// [`WelfordStats`](crate::correlate::WelfordStats).
///
/// Generic over the hasher builder `S` like the sketch family
/// ([`BloomFilter`](crate::correlate::BloomFilter) /
/// [`CountMinSketch`](crate::correlate::CountMinSketch)) —
/// pass a seeded `ahash::RandomState` via
/// [`Self::with_hasher`] for throughput or cross-shard
/// determinism.
///
/// Issue #134 (0.21).
#[derive(Debug)]
pub struct EwmaVar<K: Hash + Eq, S: BuildHasher = RandomState> {
    alpha: f64,
    entries: HashMap<K, Entry, S>,
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    mean: f64,
    var: f64,
    last_ts: Timestamp,
}

impl<K: Hash + Eq + Clone> EwmaVar<K> {
    /// New tracker with the given smoothing factor.
    ///
    /// # Panics
    ///
    /// Panics unless `alpha ∈ (0, 1]`.
    pub fn new(alpha: f64) -> Self {
        Self::with_hasher(alpha, RandomState::new())
    }
}

impl<K: Hash + Eq + Clone, S: BuildHasher> EwmaVar<K, S> {
    /// [`Self::new`] with an explicit hasher builder.
    ///
    /// # Panics
    ///
    /// Panics unless `alpha ∈ (0, 1]`.
    pub fn with_hasher(alpha: f64, hasher_builder: S) -> Self {
        assert!(alpha > 0.0 && alpha <= 1.0, "alpha must be in (0, 1]");
        Self {
            alpha,
            entries: HashMap::with_hasher(hasher_builder),
        }
    }

    /// Record `sample` for `key`. Returns the updated snapshot.
    pub fn record(&mut self, key: K, sample: f64) -> EwmaVarValue {
        self.record_at(key, sample, Timestamp::default())
    }

    /// Variant of [`Self::record`] that timestamps the sample
    /// (used for [`Self::evict_stale`]).
    ///
    /// The first sample for a key seeds `mean = sample`,
    /// `variance = 0`.
    pub fn record_at(&mut self, key: K, sample: f64, now: Timestamp) -> EwmaVarValue {
        match self.entries.get_mut(&key) {
            Some(entry) => {
                entry.last_ts = now;
                if entry.mean.is_nan() {
                    entry.mean = sample;
                    entry.var = 0.0;
                } else {
                    // West's exponentially-weighted mean/variance.
                    let diff = sample - entry.mean;
                    let incr = self.alpha * diff;
                    entry.mean += incr;
                    entry.var = (1.0 - self.alpha) * (entry.var + diff * incr);
                }
                EwmaVarValue {
                    mean: entry.mean,
                    variance: entry.var,
                }
            }
            None => {
                self.entries.insert(
                    key,
                    Entry {
                        mean: sample,
                        var: 0.0,
                        last_ts: now,
                    },
                );
                EwmaVarValue {
                    mean: sample,
                    variance: 0.0,
                }
            }
        }
    }

    /// Current snapshot for `key`, or `None` if no samples have
    /// been recorded.
    pub fn get(&self, key: &K) -> Option<EwmaVarValue> {
        self.entries.get(key).map(|e| EwmaVarValue {
            mean: e.mean,
            variance: e.var,
        })
    }

    /// How many standard deviations `sample` sits above (positive)
    /// or below (negative) `key`'s current baseline. `None` when
    /// the key has no baseline yet.
    ///
    /// While the key's variance is still zero (single sample, or a
    /// perfectly constant stream) this returns `0.0` — a warmup
    /// baseline never alarms, which is the behaviour an N-sigma
    /// outlier detector wants (compare Suricata/RITA exfil
    /// heuristics: no deviation estimate → no verdict).
    pub fn zscore(&self, key: &K, sample: f64) -> Option<f64> {
        let v = self.get(key)?;
        let std = v.std();
        if std <= f64::EPSILON {
            return Some(0.0);
        }
        Some((sample - v.mean) / std)
    }

    /// Iterate `(key, snapshot)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&K, EwmaVarValue)> {
        self.entries.iter().map(|(k, e)| {
            (
                k,
                EwmaVarValue {
                    mean: e.mean,
                    variance: e.var,
                },
            )
        })
    }

    /// Drop entries that haven't been touched within `ttl` of
    /// `now`. Useful in long-running pipelines to bound memory.
    pub fn evict_stale(&mut self, now: Timestamp, ttl: Duration) {
        let now_dur = now.to_duration();
        self.entries
            .retain(|_, e| now_dur.saturating_sub(e.last_ts.to_duration()) <= ttl);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl<K: Hash + Eq + Clone, S: BuildHasher> crate::correlate::Mergeable for EwmaVar<K, S> {
    /// Per-key symmetric pooled fold: for keys present in both
    /// sides the merged mean is `0.5 * (mₐ + m_b)` (matching
    /// [`Ewma`](crate::correlate::Ewma)'s semantic) and the merged
    /// variance is the two-group pooled form
    /// `0.5 * (vₐ + v_b) + 0.25 * (mₐ − m_b)²` — the cross-term
    /// matters: without it, merging shards that observed different
    /// levels understates spread, and an N-sigma consumer
    /// over-fires. `last_ts` keeps the later of the two. Keys
    /// present on one side only are retained as-is.
    ///
    /// Commutative; associative only approximately (same caveat as
    /// `Ewma::merge` — the unweighted pairwise fold can't be
    /// exactly associative without sample counts). Fine for the
    /// intended per-shard union off the hot path.
    ///
    /// **Panics** if `alpha` doesn't match — different shards
    /// running with different smoothing factors is a config bug.
    fn merge(&mut self, other: Self) {
        assert_eq!(
            self.alpha, other.alpha,
            "EwmaVar::merge requires matching alpha",
        );
        for (k, e_other) in other.entries {
            match self.entries.get_mut(&k) {
                Some(e_self) => {
                    let mean_diff = e_self.mean - e_other.mean;
                    e_self.var = 0.5 * (e_self.var + e_other.var) + 0.25 * mean_diff * mean_diff;
                    e_self.mean = 0.5 * (e_self.mean + e_other.mean);
                    if e_other.last_ts > e_self.last_ts {
                        e_self.last_ts = e_other.last_ts;
                    }
                }
                None => {
                    self.entries.insert(k, e_other);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpha_one_tracks_last_sample_with_zero_variance() {
        let mut e: EwmaVar<u32> = EwmaVar::new(1.0);
        e.record(1, 10.0);
        let v = e.record(1, 5.0);
        assert!((v.mean - 5.0).abs() < 1e-9);
        assert!(v.variance.abs() < 1e-9, "alpha=1 has no memory → var 0");
    }

    #[test]
    fn constant_stream_variance_decays_to_zero() {
        let mut e: EwmaVar<u32> = EwmaVar::new(0.3);
        for _ in 0..100 {
            e.record(1, 42.0);
        }
        let v = e.get(&1).unwrap();
        assert!((v.mean - 42.0).abs() < 1e-9);
        assert!(v.variance < 1e-12);
    }

    #[test]
    fn two_sample_hand_computation() {
        // α = 0.5, samples 10 then 20:
        //   seed: mean = 10, var = 0
        //   diff = 10, incr = 5 → mean = 15, var = 0.5*(0 + 10*5) = 25
        let mut e: EwmaVar<u32> = EwmaVar::new(0.5);
        e.record(1, 10.0);
        let v = e.record(1, 20.0);
        assert!((v.mean - 15.0).abs() < 1e-9);
        assert!((v.variance - 25.0).abs() < 1e-9);
        assert!((v.std() - 5.0).abs() < 1e-9);
    }

    #[test]
    fn zscore_warmup_returns_zero() {
        let mut e: EwmaVar<u32> = EwmaVar::new(0.5);
        assert_eq!(e.zscore(&1, 100.0), None, "no baseline yet");
        e.record(1, 10.0);
        // Single sample → zero variance → zscore clamps to 0.
        assert_eq!(e.zscore(&1, 1_000_000.0), Some(0.0));
    }

    #[test]
    fn zscore_flags_outlier_after_stable_baseline() {
        let mut e: EwmaVar<u32> = EwmaVar::new(0.1);
        // Baseline with mild noise around 100.
        for i in 0..50 {
            let jitter = if i % 2 == 0 { 2.0 } else { -2.0 };
            e.record(1, 100.0 + jitter);
        }
        let z_normal = e.zscore(&1, 101.0).unwrap();
        let z_outlier = e.zscore(&1, 200.0).unwrap();
        assert!(z_normal.abs() < 3.0, "in-band sample: z={z_normal}");
        assert!(z_outlier > 3.0, "20x spike must exceed 3σ: z={z_outlier}");
    }

    #[test]
    fn per_key_isolation() {
        let mut e: EwmaVar<u32> = EwmaVar::new(1.0);
        e.record(1, 10.0);
        e.record(2, 20.0);
        assert_eq!(e.get(&1).unwrap().mean, 10.0);
        assert_eq!(e.get(&2).unwrap().mean, 20.0);
        assert_eq!(e.len(), 2);
    }

    #[test]
    fn evict_stale_drops_old_entries() {
        let mut e: EwmaVar<u32> = EwmaVar::new(0.5);
        e.record_at(1, 1.0, Timestamp::new(0, 0));
        e.record_at(2, 2.0, Timestamp::new(100, 0));
        e.evict_stale(Timestamp::new(100, 0), Duration::from_secs(10));
        assert!(e.get(&1).is_none());
        assert!(e.get(&2).is_some());
    }

    #[test]
    #[should_panic(expected = "alpha must be in (0, 1]")]
    fn zero_alpha_panics() {
        let _: EwmaVar<u32> = EwmaVar::new(0.0);
    }

    #[test]
    #[should_panic(expected = "alpha must be in (0, 1]")]
    fn alpha_above_one_panics() {
        let _: EwmaVar<u32> = EwmaVar::new(1.5);
    }
}

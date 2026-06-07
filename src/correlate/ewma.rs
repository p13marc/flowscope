//! [`Ewma`] — per-key exponentially weighted moving average.

use std::collections::HashMap;
use std::hash::Hash;
use std::time::Duration;

use crate::Timestamp;

/// Per-key exponentially weighted moving average.
///
/// `alpha ∈ (0, 1]` is the weight applied to each new sample:
///
/// ```text
/// ewma_new = alpha * sample + (1 - alpha) * ewma_old
/// ```
///
/// Smaller `alpha` → smoother / slower-reacting. `alpha = 1.0`
/// makes the EWMA equal the most recent sample.
#[derive(Debug)]
pub struct Ewma<K: Hash + Eq> {
    alpha: f64,
    entries: HashMap<K, (f64, Timestamp)>,
}

impl<K: Hash + Eq + Clone> Ewma<K> {
    pub fn new(alpha: f64) -> Self {
        assert!(alpha > 0.0 && alpha <= 1.0, "alpha must be in (0, 1]");
        Self {
            alpha,
            entries: HashMap::new(),
        }
    }

    /// Record `sample` for `key` at `now`. Returns the updated
    /// EWMA value.
    pub fn record(&mut self, key: K, sample: f64) -> f64 {
        self.record_at(key, sample, Timestamp::default())
    }

    /// Variant of [`Self::record`] that timestamps the sample
    /// (used for [`Self::evict_stale`]).
    pub fn record_at(&mut self, key: K, sample: f64, now: Timestamp) -> f64 {
        let entry = self.entries.entry(key).or_insert((sample, now));
        entry.1 = now;
        if entry.0.is_nan() {
            entry.0 = sample;
        } else {
            entry.0 = self.alpha * sample + (1.0 - self.alpha) * entry.0;
        }
        entry.0
    }

    /// Current EWMA for `key`, or `None` if no samples have been
    /// recorded.
    pub fn get(&self, key: &K) -> Option<f64> {
        self.entries.get(key).map(|(v, _)| *v)
    }

    /// Iterate `(key, ewma)` pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&K, f64)> {
        self.entries.iter().map(|(k, (v, _))| (k, *v))
    }

    /// Drop entries that haven't been touched within `ttl` of
    /// `now`. Useful in long-running pipelines to bound memory.
    pub fn evict_stale(&mut self, now: Timestamp, ttl: Duration) {
        let now_dur = now.to_duration();
        self.entries
            .retain(|_, (_, last_ts)| now_dur.saturating_sub(last_ts.to_duration()) <= ttl);
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpha_one_returns_last_sample() {
        let mut e: Ewma<u32> = Ewma::new(1.0);
        e.record(1, 10.0);
        e.record(1, 5.0);
        let v = e.get(&1).unwrap();
        assert!((v - 5.0).abs() < 1e-9);
    }

    #[test]
    fn alpha_half_averages_last_two() {
        let mut e: Ewma<u32> = Ewma::new(0.5);
        e.record(1, 10.0);
        e.record(1, 20.0);
        // After first record: 10.0; second: 0.5*20 + 0.5*10 = 15.
        let v = e.get(&1).unwrap();
        assert!((v - 15.0).abs() < 1e-9);
    }

    #[test]
    fn per_key_isolation() {
        let mut e: Ewma<u32> = Ewma::new(1.0);
        e.record(1, 10.0);
        e.record(2, 20.0);
        assert_eq!(e.get(&1).unwrap(), 10.0);
        assert_eq!(e.get(&2).unwrap(), 20.0);
    }

    #[test]
    fn evict_stale_drops_old_entries() {
        let mut e: Ewma<u32> = Ewma::new(0.5);
        e.record_at(1, 1.0, Timestamp::new(0, 0));
        e.record_at(2, 2.0, Timestamp::new(100, 0));
        e.evict_stale(Timestamp::new(100, 0), Duration::from_secs(10));
        assert!(e.get(&1).is_none());
        assert!(e.get(&2).is_some());
    }
}

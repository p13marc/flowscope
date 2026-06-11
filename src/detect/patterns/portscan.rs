//! Threshold Random Walk port-scan detector (Jung et al.,
//! "Fast Portscan Detection Using Sequential Hypothesis
//! Testing", IEEE S&P 2004).
//!
//! Per-source sequential hypothesis test on connection
//! outcomes. The detector maintains a log-likelihood ratio λ:
//!
//! ```text
//!   on success: λ += log(θ1 / θ0)        ≈ −1.386
//!   on failure: λ += log((1−θ1)/(1−θ0))  ≈ +1.386
//! ```
//!
//! with default priors θ0 = P(success | benign) = 0.8 and
//! θ1 = P(success | scanner) = 0.2.
//!
//! Decision thresholds (α = β = 0.01):
//!
//! ```text
//!   η1 = log((1−β) / α)     ≈ +4.595  → declare scanner
//!   η0 = log(β / (1−α))     ≈ −4.595  → declare benign
//! ```
//!
//! With the defaults, ~4 consecutive failures or ~4 consecutive
//! successes from a fresh source pushes the verdict to
//! `Scanner` or `Benign` respectively. The detector never
//! reuses state across verdicts — once a verdict crosses a
//! threshold, the next `observe` for that key starts at λ = 0.
//! Consumers wanting persistent classification keep their own
//! map.

use std::collections::HashMap;
use std::hash::Hash;

/// Per-source scanner-likelihood detector.
pub struct PortScanDetector<K>
where
    K: Hash + Eq + Clone,
{
    sources: HashMap<K, ScannerState>,
    success_step: f64,
    failure_step: f64,
    threshold_scanner: f64,
    threshold_benign: f64,
}

#[derive(Debug, Clone, Copy)]
struct ScannerState {
    log_likelihood: f64,
    n_observed: u32,
}

/// Verdict from a single observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ScanVerdict {
    /// Threshold crossed in the scanner direction.
    Scanner,
    /// Threshold crossed in the benign direction.
    Benign,
    /// Neither threshold crossed yet.
    Inconclusive,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ScanScore<K> {
    pub key: K,
    pub verdict: ScanVerdict,
    pub log_likelihood: f64,
    pub n_observed: u32,
}

impl<K> PortScanDetector<K>
where
    K: Hash + Eq + Clone,
{
    /// Default-tuned: θ0=0.8, θ1=0.2, α=β=0.01.
    pub fn new() -> Self {
        Self::with_params(0.8, 0.2, 0.01, 0.01)
    }

    /// Custom-tuned: caller supplies success priors + error
    /// rates. Asserts the parameters are in `(0, 1)` open
    /// intervals.
    pub fn with_params(theta0: f64, theta1: f64, alpha: f64, beta: f64) -> Self {
        assert!(
            (0.0..1.0).contains(&theta0) && theta0 > 0.0,
            "theta0 must be in (0, 1)"
        );
        assert!(
            (0.0..1.0).contains(&theta1) && theta1 > 0.0,
            "theta1 must be in (0, 1)"
        );
        assert!(
            (0.0..1.0).contains(&alpha) && alpha > 0.0,
            "alpha must be in (0, 1)"
        );
        assert!(
            (0.0..1.0).contains(&beta) && beta > 0.0,
            "beta must be in (0, 1)"
        );
        Self {
            sources: HashMap::new(),
            success_step: (theta1 / theta0).ln(),
            failure_step: ((1.0 - theta1) / (1.0 - theta0)).ln(),
            threshold_scanner: ((1.0 - beta) / alpha).ln(),
            threshold_benign: (beta / (1.0 - alpha)).ln(),
        }
    }

    /// Record a connection outcome.
    ///
    /// `success = true` for completed 3-way handshakes (or any
    /// other "connection succeeded" signal the consumer
    /// supplies); `false` for SYN-only / RST / timeout.
    pub fn observe(&mut self, key: K, success: bool) -> ScanScore<K> {
        let entry = self.sources.entry(key.clone()).or_insert(ScannerState {
            log_likelihood: 0.0,
            n_observed: 0,
        });
        entry.log_likelihood += if success {
            self.success_step
        } else {
            self.failure_step
        };
        entry.n_observed += 1;
        let verdict = if entry.log_likelihood >= self.threshold_scanner {
            ScanVerdict::Scanner
        } else if entry.log_likelihood <= self.threshold_benign {
            ScanVerdict::Benign
        } else {
            ScanVerdict::Inconclusive
        };
        let score = ScanScore {
            key: key.clone(),
            verdict,
            log_likelihood: entry.log_likelihood,
            n_observed: entry.n_observed,
        };
        if matches!(verdict, ScanVerdict::Scanner | ScanVerdict::Benign) {
            self.sources.remove(&key);
        }
        score
    }

    /// Drop per-key state without emitting a verdict.
    pub fn forget(&mut self, key: &K) {
        self.sources.remove(key);
    }

    /// Number of sources currently being tracked.
    pub fn tracked(&self) -> usize {
        self.sources.len()
    }
}

#[cfg(feature = "tracker")]
impl<K> ScanScore<K>
where
    K: crate::KeyFields + Clone,
{
    /// Convert into the canonical [`OwnedAnomaly`](crate::OwnedAnomaly) shape with
    /// the given timestamp. Severity follows `verdict`:
    /// `Scanner` → `Warning`, `Benign`/`Inconclusive` → `Info`.
    ///
    /// Metrics emitted: `log_likelihood`, `n_observed`.
    /// Observations emitted: `verdict` (slug).
    ///
    /// Gated on the `tracker` feature — `OwnedAnomaly` lives
    /// there.
    pub fn into_anomaly(self, ts: crate::Timestamp) -> crate::OwnedAnomaly {
        let severity = match self.verdict {
            ScanVerdict::Scanner => crate::event::Severity::Warning,
            ScanVerdict::Benign | ScanVerdict::Inconclusive => crate::event::Severity::Info,
        };
        let verdict_slug = match self.verdict {
            ScanVerdict::Scanner => "scanner",
            ScanVerdict::Benign => "benign",
            ScanVerdict::Inconclusive => "inconclusive",
        };
        crate::OwnedAnomaly::new("PortScanTRW", severity, ts)
            .with_key(&self.key)
            .with_observation("verdict", verdict_slug)
            .with_metric("log_likelihood", self.log_likelihood)
            .with_metric("n_observed", self.n_observed as f64)
    }
}

#[cfg(feature = "tracker")]
impl<K> crate::DetectorScore for ScanScore<K>
where
    K: crate::KeyFields + Clone,
{
    fn name(&self) -> &'static str {
        "PortScanTRW"
    }

    fn into_anomaly(self, ts: crate::Timestamp) -> crate::OwnedAnomaly {
        self.into_anomaly(ts)
    }
}

impl<K> Default for PortScanDetector<K>
where
    K: Hash + Eq + Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_source_is_inconclusive_after_one_observation() {
        let mut d: PortScanDetector<u32> = PortScanDetector::new();
        let s = d.observe(1, true);
        assert_eq!(s.verdict, ScanVerdict::Inconclusive);
    }

    #[test]
    fn consecutive_failures_eventually_classify_scanner() {
        let mut d: PortScanDetector<u32> = PortScanDetector::new();
        let mut classifications = Vec::new();
        for _ in 0..8 {
            classifications.push(d.observe(1, false).verdict);
        }
        // With default thresholds (~4.595) and per-failure step
        // (~+1.386), 4 failures push λ to ~5.544 > 4.595.
        assert!(
            classifications.contains(&ScanVerdict::Scanner),
            "expected Scanner verdict after enough failures, got: {classifications:?}"
        );
    }

    #[test]
    fn consecutive_successes_eventually_classify_benign() {
        let mut d: PortScanDetector<u32> = PortScanDetector::new();
        let mut classifications = Vec::new();
        for _ in 0..8 {
            classifications.push(d.observe(1, true).verdict);
        }
        assert!(
            classifications.contains(&ScanVerdict::Benign),
            "expected Benign verdict after enough successes, got: {classifications:?}"
        );
    }

    #[test]
    fn mixed_outcomes_stay_inconclusive() {
        let mut d: PortScanDetector<u32> = PortScanDetector::new();
        for i in 0..20 {
            let s = d.observe(1, i % 2 == 0);
            assert_eq!(
                s.verdict,
                ScanVerdict::Inconclusive,
                "step {i}: λ={}, expected Inconclusive",
                s.log_likelihood
            );
        }
    }

    #[test]
    fn custom_priors_change_step_magnitude() {
        let mut strict: PortScanDetector<u32> = PortScanDetector::with_params(0.9, 0.1, 0.01, 0.01);
        // With θ0=0.9, θ1=0.1, failure step is log(0.9/0.1)
        // ≈ +2.197 — single failure shouldn't trigger.
        let s = strict.observe(1, false);
        assert!(s.log_likelihood < 4.595);
        assert_eq!(s.verdict, ScanVerdict::Inconclusive);
    }

    #[test]
    fn per_key_isolation() {
        let mut d: PortScanDetector<u32> = PortScanDetector::new();
        // Source 1: scanner pattern.
        for _ in 0..4 {
            d.observe(1, false);
        }
        // Source 2: still fresh; should be unaffected.
        let s2 = d.observe(2, true);
        assert_eq!(s2.verdict, ScanVerdict::Inconclusive);
    }

    #[test]
    fn verdict_resets_state() {
        let mut d: PortScanDetector<u32> = PortScanDetector::new();
        // Drive to a Scanner verdict by observing failures until
        // the threshold is crossed (3 inconclusive + 1 scanner
        // under default tuning).
        let mut crossed = false;
        for _ in 0..6 {
            let s = d.observe(1, false);
            if matches!(s.verdict, ScanVerdict::Scanner) {
                crossed = true;
                break;
            }
        }
        assert!(crossed, "should cross Scanner threshold");
        // Right after the verdict, state for this key is gone.
        assert_eq!(d.tracked(), 0);
        // Next observation starts from a clean slate.
        let s = d.observe(1, true);
        assert_eq!(s.n_observed, 1);
        assert_eq!(s.verdict, ScanVerdict::Inconclusive);
    }

    #[test]
    fn forget_drops_state() {
        let mut d: PortScanDetector<u32> = PortScanDetector::new();
        d.observe(1, false);
        d.observe(1, false);
        assert_eq!(d.tracked(), 1);
        d.forget(&1);
        assert_eq!(d.tracked(), 0);
    }
}

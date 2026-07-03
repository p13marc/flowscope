//! Sequential change-point detectors — [`Cusum`] and
//! [`PageHinkley`] (issue #134).
//!
//! Both spot a shift in the *mean* of a scalar stream (flow rate,
//! byte throughput, inter-arrival time) online, in O(1) state per
//! stream, and signal the moment the shift becomes statistically
//! persistent rather than a single spike. Where an EWMA z-score
//! answers "is this sample far from normal", a change-point
//! detector answers "has normal itself moved" — the axis you want
//! for regime shifts (a beacon starting, an exfil transfer
//! ramping, a link degrading).
//!
//! Both are `Copy` scalars (one instance per stream — key them in
//! a [`HashMap`](std::collections::HashMap) /
//! [`KeyIndexed`](crate::correlate::KeyIndexed) for per-flow use),
//! two-sided (detect increases and decreases), and reset their
//! accumulators on alarm so a stream keeps detecting subsequent
//! shifts.
//!
//! # Not `Mergeable`
//!
//! Neither implements [`Mergeable`](crate::correlate::Mergeable):
//! both are **path-dependent** (their running statistic is a
//! cumulative sum over the *ordered* sample sequence), so there is
//! no order-independent union of two shards' states — the
//! commutative+associative contract cannot hold. Shard the *input
//! stream* upstream (one detector per key per shard) rather than
//! trying to merge detector state.

use crate::Timestamp;

/// Direction of a detected mean shift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum ChangeDirection {
    /// The mean shifted **up** (samples trending higher).
    Up,
    /// The mean shifted **down** (samples trending lower).
    Down,
}

impl ChangeDirection {
    /// Stable lowercase slug for metric labels / logs.
    pub fn as_str(&self) -> &'static str {
        match self {
            ChangeDirection::Up => "up",
            ChangeDirection::Down => "down",
        }
    }
}

/// A detected change point.
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct ChangePoint {
    /// Which way the mean moved.
    pub direction: ChangeDirection,
    /// The decision statistic at the alarm (how far it exceeded
    /// the threshold — larger = stronger evidence).
    pub statistic: f64,
}

/// Two-sided tabular CUSUM (cumulative sum) change detector.
///
/// Classic Page (1954) / Montgomery SPC form: given a target mean
/// `μ₀`, a slack `k` (allowable drift, conventionally ½ the shift
/// you want to catch, in the stream's units), and a decision
/// threshold `h`, maintain two one-sided sums
///
/// ```text
/// C⁺ = max(0, C⁺ + xᵢ − (μ₀ + k))
/// C⁻ = max(0, C⁻ + (μ₀ − k) − xᵢ)
/// ```
///
/// and alarm when either exceeds `h`. `k` and `h` are commonly
/// set to ½σ and 4–5σ respectively. Reset-on-alarm.
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Cusum {
    target: f64,
    slack: f64,
    threshold: f64,
    c_high: f64,
    c_low: f64,
}

impl Cusum {
    /// New CUSUM with target mean `μ₀`, slack `k`, threshold `h`
    /// (all in the stream's units). `slack` and `threshold` must
    /// be ≥ 0.
    pub fn new(target: f64, slack: f64, threshold: f64) -> Self {
        assert!(slack >= 0.0, "slack must be >= 0");
        assert!(threshold >= 0.0, "threshold must be >= 0");
        Self {
            target,
            slack,
            threshold,
            c_high: 0.0,
            c_low: 0.0,
        }
    }

    /// Feed one sample. Returns `Some` on the sample that pushes a
    /// one-sided sum past the threshold, resetting that sum.
    pub fn observe(&mut self, x: f64) -> Option<ChangePoint> {
        self.c_high = (self.c_high + x - (self.target + self.slack)).max(0.0);
        self.c_low = (self.c_low + (self.target - self.slack) - x).max(0.0);

        if self.c_high > self.threshold {
            let statistic = self.c_high - self.threshold;
            self.c_high = 0.0;
            return Some(ChangePoint {
                direction: ChangeDirection::Up,
                statistic,
            });
        }
        if self.c_low > self.threshold {
            let statistic = self.c_low - self.threshold;
            self.c_low = 0.0;
            return Some(ChangePoint {
                direction: ChangeDirection::Down,
                statistic,
            });
        }
        None
    }

    /// Current upper / lower accumulators (diagnostics).
    pub fn sums(&self) -> (f64, f64) {
        (self.c_high, self.c_low)
    }

    /// Reset both accumulators without changing the parameters.
    pub fn reset(&mut self) {
        self.c_high = 0.0;
        self.c_low = 0.0;
    }
}

/// Two-sided Page-Hinkley change detector.
///
/// Tracks a running mean and the cumulative deviation from it,
/// tolerating a per-sample magnitude `delta` before accumulating;
/// alarms when the cumulative sum departs from its running
/// extremum by more than `lambda`. Unlike [`Cusum`] it needs **no
/// target mean** — it estimates the mean online — which suits
/// streams whose baseline is unknown a priori. Reference: Page
/// (1954); Hinkley (1971); the Gama et al. concept-drift form.
///
/// ```text
/// x̄ₜ  = x̄ₜ₋₁ + (xₜ − x̄ₜ₋₁)/t
/// mₜ  = mₜ₋₁ + (xₜ − x̄ₜ − δ)      Mₜ = min(Mₜ, mₜ)   ; alarm up   if mₜ − Mₜ > λ
/// m'ₜ = m'ₜ₋₁ + (xₜ − x̄ₜ + δ)     M'ₜ = max(M'ₜ, m'ₜ) ; alarm down if M'ₜ − m'ₜ > λ
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PageHinkley {
    delta: f64,
    lambda: f64,
    count: u64,
    mean: f64,
    // Increase-detection accumulator + running minimum.
    m_up: f64,
    min_up: f64,
    // Decrease-detection accumulator + running maximum.
    m_down: f64,
    max_down: f64,
}

impl PageHinkley {
    /// New detector with magnitude tolerance `delta` (drift
    /// allowed before accumulating) and alarm threshold `lambda`.
    /// Both must be ≥ 0. Larger `delta` → fewer false alarms /
    /// slower detection; larger `lambda` → same.
    pub fn new(delta: f64, lambda: f64) -> Self {
        assert!(delta >= 0.0, "delta must be >= 0");
        assert!(lambda >= 0.0, "lambda must be >= 0");
        Self {
            delta,
            lambda,
            count: 0,
            mean: 0.0,
            m_up: 0.0,
            min_up: 0.0,
            m_down: 0.0,
            max_down: 0.0,
        }
    }

    /// Feed one sample. Returns `Some` when the Page-Hinkley
    /// statistic crosses `lambda`, resetting the accumulators
    /// (but keeping the running-mean estimate).
    pub fn observe(&mut self, x: f64) -> Option<ChangePoint> {
        self.count += 1;
        self.mean += (x - self.mean) / self.count as f64;

        self.m_up += x - self.mean - self.delta;
        self.min_up = self.min_up.min(self.m_up);

        self.m_down += x - self.mean + self.delta;
        self.max_down = self.max_down.max(self.m_down);

        let ph_up = self.m_up - self.min_up;
        let ph_down = self.max_down - self.m_down;

        if ph_up > self.lambda {
            let statistic = ph_up - self.lambda;
            self.reset_accumulators();
            return Some(ChangePoint {
                direction: ChangeDirection::Up,
                statistic,
            });
        }
        if ph_down > self.lambda {
            let statistic = ph_down - self.lambda;
            self.reset_accumulators();
            return Some(ChangePoint {
                direction: ChangeDirection::Down,
                statistic,
            });
        }
        None
    }

    /// Samples observed since construction / last full reset.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// Current running-mean estimate.
    pub fn mean(&self) -> f64 {
        self.mean
    }

    /// Reset accumulators but keep the running-mean estimate —
    /// what `observe` does on alarm.
    pub fn reset_accumulators(&mut self) {
        self.m_up = 0.0;
        self.min_up = 0.0;
        self.m_down = 0.0;
        self.max_down = 0.0;
    }
}

/// Convenience: a [`PageHinkley`] fed from *timestamped* samples,
/// converting an inter-arrival gap to the sample. Not required —
/// most callers feed a scalar directly — but handy for
/// "did the cadence change" checks. Returns the same
/// [`ChangePoint`].
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct InterArrivalPageHinkley {
    inner: PageHinkley,
    last: Option<Timestamp>,
}

impl InterArrivalPageHinkley {
    /// New inter-arrival detector — `delta` / `lambda` are in
    /// **seconds** (the gap unit).
    pub fn new(delta: f64, lambda: f64) -> Self {
        Self {
            inner: PageHinkley::new(delta, lambda),
            last: None,
        }
    }

    /// Record an arrival at `now`. The first arrival only seeds
    /// the clock (returns `None`); subsequent arrivals feed the
    /// gap in seconds to the underlying detector.
    pub fn observe(&mut self, now: Timestamp) -> Option<ChangePoint> {
        let out = if let Some(prev) = self.last {
            let gap = now.to_duration().saturating_sub(prev.to_duration());
            self.inner.observe(gap.as_secs_f64())
        } else {
            None
        };
        self.last = Some(now);
        out
    }

    /// Access the underlying detector (mean gap, count).
    pub fn inner(&self) -> &PageHinkley {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cusum_detects_upward_shift() {
        // Target 10, slack 1, threshold 5. Stable at 10 → no alarm.
        let mut c = Cusum::new(10.0, 1.0, 5.0);
        for _ in 0..50 {
            assert!(c.observe(10.0).is_none());
        }
        // Shift to 20 → C⁺ accumulates 9/sample, crosses 5 fast.
        let mut fired = None;
        for _ in 0..5 {
            if let Some(cp) = c.observe(20.0) {
                fired = Some(cp);
                break;
            }
        }
        assert_eq!(fired.unwrap().direction, ChangeDirection::Up);
    }

    #[test]
    fn cusum_detects_downward_shift() {
        let mut c = Cusum::new(10.0, 1.0, 5.0);
        for _ in 0..20 {
            c.observe(10.0);
        }
        let mut fired = None;
        for _ in 0..5 {
            if let Some(cp) = c.observe(0.0) {
                fired = Some(cp);
                break;
            }
        }
        assert_eq!(fired.unwrap().direction, ChangeDirection::Down);
    }

    #[test]
    fn cusum_resets_after_alarm() {
        let mut c = Cusum::new(0.0, 0.0, 3.0);
        // One big sample trips it.
        let cp = c.observe(10.0).expect("alarm");
        assert_eq!(cp.direction, ChangeDirection::Up);
        // Accumulator reset — a return to target is quiet.
        assert!(c.observe(0.0).is_none());
        assert_eq!(c.sums().0, 0.0);
    }

    #[test]
    fn cusum_stable_stream_is_quiet() {
        let mut c = Cusum::new(100.0, 5.0, 20.0);
        // Bounded jitter around the target never trips.
        for i in 0..1000 {
            let x = 100.0 + if i % 2 == 0 { 3.0 } else { -3.0 };
            assert!(c.observe(x).is_none());
        }
    }

    #[test]
    fn page_hinkley_detects_upward_shift_without_target() {
        let mut ph = PageHinkley::new(1.0, 10.0);
        // Baseline ~5.
        for _ in 0..100 {
            ph.observe(5.0);
        }
        // Jump to 25.
        let mut fired = None;
        for _ in 0..20 {
            if let Some(cp) = ph.observe(25.0) {
                fired = Some(cp);
                break;
            }
        }
        assert_eq!(fired.unwrap().direction, ChangeDirection::Up);
    }

    #[test]
    fn page_hinkley_detects_downward_shift() {
        let mut ph = PageHinkley::new(1.0, 10.0);
        for _ in 0..100 {
            ph.observe(50.0);
        }
        let mut fired = None;
        for _ in 0..30 {
            if let Some(cp) = ph.observe(5.0) {
                fired = Some(cp);
                break;
            }
        }
        assert_eq!(fired.unwrap().direction, ChangeDirection::Down);
    }

    #[test]
    fn page_hinkley_stable_stream_is_quiet() {
        let mut ph = PageHinkley::new(2.0, 50.0);
        for i in 0..2000 {
            let x = 20.0 + if i % 2 == 0 { 1.0 } else { -1.0 };
            assert!(ph.observe(x).is_none());
        }
    }

    #[test]
    fn inter_arrival_first_sample_seeds() {
        let mut d = InterArrivalPageHinkley::new(0.1, 5.0);
        assert!(d.observe(Timestamp::new(0, 0)).is_none());
        // Steady 1 s cadence — quiet.
        for s in 1..30 {
            assert!(d.observe(Timestamp::new(s, 0)).is_none());
        }
        assert!(d.inner().count() >= 1);
    }

    #[test]
    fn change_direction_slugs() {
        assert_eq!(ChangeDirection::Up.as_str(), "up");
        assert_eq!(ChangeDirection::Down.as_str(), "down");
    }
}

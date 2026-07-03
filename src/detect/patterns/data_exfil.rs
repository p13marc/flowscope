//! Data-exfiltration detector — per-source outbound-volume
//! N-sigma outlier over an EWMA baseline (issue #132).
//!
//! Bulk exfil shows up as a flow whose initiator-sent byte count
//! sits far above that source's own recent baseline. This
//! detector keeps a per-source
//! [`EwmaVar`] of initiator bytes and
//! fires when a finished flow exceeds `mean + n·σ` (and clears an
//! absolute floor, so a tiny-but-noisy baseline can't alarm on a
//! still-small transfer). The RITA / AC-Hunter outbound-volume
//! heuristic, upstreamed.
//!
//! Feed via [`Detector::on_flow_end`](crate::detect::Detector) —
//! the finished flow is the unit of observation.
//!
//! # Known false positives
//!
//! Legitimate bulk transfers (backups, CI artifact pushes, cloud
//! sync) look identical to exfil by volume alone; pair with
//! destination reputation / time-of-day / newly-observed-domain
//! for confidence. Per-source baselining means a *consistently*
//! high-volume source won't trip once its baseline catches up.

use std::{net::IpAddr, time::Duration};

use crate::{
    DetectorKind, OwnedAnomaly, Timestamp,
    anomaly_fields::KeyFields,
    correlate::EwmaVar,
    detect::registry::SrcHost,
    event::{FlowStats, Severity},
    extractor::L4Proto,
    history::HistoryString,
};

/// Per-source data-exfiltration detector.
pub struct DataExfilDetector {
    baseline: EwmaVar<IpAddr>,
    n_sigma: f64,
    min_samples: u64,
    min_bytes: u64,
    counts: crate::correlate::KeyIndexed<IpAddr, u64>,
    cooldown: Duration,
    last_emitted: crate::correlate::KeyIndexed<IpAddr, ()>,
}

/// Score from a data-exfil observation over threshold.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ExfilScore {
    /// Exfiltrating source.
    pub src: IpAddr,
    /// Initiator-sent bytes on the flagged flow.
    pub bytes: u64,
    /// Source's EWMA baseline mean at the time of the flow.
    pub mean: f64,
    /// Source's baseline standard deviation.
    pub sigma: f64,
    /// Samples observed for this source so far.
    pub n: u64,
}

impl DataExfilDetector {
    /// Default tuning: EWMA α=0.1, 3σ threshold, ≥ 10 samples
    /// baseline, ≥ 1 MiB absolute floor, 300 s per-source
    /// cooldown, one-day baseline TTL.
    pub fn new() -> Self {
        Self {
            baseline: EwmaVar::new(0.1),
            n_sigma: 3.0,
            min_samples: 10,
            min_bytes: 1024 * 1024,
            counts: crate::correlate::KeyIndexed::new(Duration::from_secs(24 * 3600), 10_000),
            cooldown: Duration::from_secs(300),
            last_emitted: crate::correlate::KeyIndexed::new(Duration::from_secs(300), 10_000),
        }
    }

    /// EWMA smoothing factor (default 0.1).
    pub fn with_alpha(mut self, alpha: f64) -> Self {
        self.baseline = EwmaVar::new(alpha);
        self
    }

    /// Standard-deviation multiple that trips a verdict (default 3.0).
    pub fn with_n_sigma(mut self, n: f64) -> Self {
        self.n_sigma = n;
        self
    }

    /// Minimum baseline samples before scoring (default 10).
    pub fn with_min_samples(mut self, n: u64) -> Self {
        self.min_samples = n;
        self
    }

    /// Absolute byte floor a flow must clear regardless of the
    /// z-score (default 1 MiB) — stops a tiny, noisy baseline
    /// from alarming on a still-small transfer.
    pub fn with_min_bytes(mut self, bytes: u64) -> Self {
        self.min_bytes = bytes;
        self
    }

    /// Per-source re-alert cooldown (default 300 s).
    pub fn with_cooldown(mut self, cooldown: Duration) -> Self {
        self.cooldown = cooldown;
        self.last_emitted = crate::correlate::KeyIndexed::new(cooldown, 10_000);
        self
    }

    /// Observe one finished flow's initiator byte count for `src`.
    /// Returns `Some` when the flow is an N-sigma outlier above
    /// the source's baseline, clears the absolute floor, and the
    /// baseline is warm (cooldown-gated).
    ///
    /// The current sample is folded into the baseline **after**
    /// the outlier test, so a flow is scored against the history
    /// that preceded it.
    pub fn observe(&mut self, src: IpAddr, bytes: u64, now: Timestamp) -> Option<ExfilScore> {
        let n = self.counts.get(&src, now).copied().unwrap_or(0);
        let baseline = self.baseline.get(&src);

        let score = if n >= self.min_samples
            && bytes >= self.min_bytes
            && let Some(b) = baseline
        {
            let sigma = b.std();
            let z = if sigma > f64::EPSILON {
                (bytes as f64 - b.mean) / sigma
            } else {
                0.0
            };
            if z >= self.n_sigma && self.last_emitted.get(&src, now).is_none() {
                self.last_emitted.insert(src, (), now);
                Some(ExfilScore {
                    src,
                    bytes,
                    mean: b.mean,
                    sigma,
                    n,
                })
            } else {
                None
            }
        } else {
            None
        };

        // Fold the sample into the baseline after scoring.
        self.baseline.record_at(src, bytes as f64, now);
        self.counts.insert(src, n + 1, now);
        score
    }

    /// Reclaim stale per-source baselines.
    pub fn evict_expired(&mut self, now: Timestamp) {
        self.baseline
            .evict_stale(now, Duration::from_secs(24 * 3600));
        self.counts.evict_expired(now);
        self.last_emitted.evict_expired(now);
    }

    /// Sources currently tracked.
    pub fn tracked(&self) -> usize {
        self.baseline.len()
    }
}

impl Default for DataExfilDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl ExfilScore {
    /// Canonical anomaly. `Warning`; metrics `bytes`, `mean`,
    /// `sigma`, `n`.
    pub fn into_anomaly(self, ts: Timestamp) -> OwnedAnomaly {
        OwnedAnomaly::new(DetectorKind::DataExfil, Severity::Warning, ts)
            .with_key(&SrcHost(self.src))
            .with_metric("bytes", self.bytes as f64)
            .with_metric("mean", self.mean)
            .with_metric("sigma", self.sigma)
            .with_metric("n", self.n as f64)
    }
}

impl crate::DetectorScore for ExfilScore {
    fn kind(&self) -> DetectorKind {
        DetectorKind::DataExfil
    }
    fn into_anomaly(self, ts: Timestamp) -> OwnedAnomaly {
        self.into_anomaly(ts)
    }
}

impl<K: KeyFields + Send> crate::detect::Detector<K> for DataExfilDetector {
    fn kind(&self) -> DetectorKind {
        DetectorKind::DataExfil
    }

    /// Observes at flow end. Deliberately ignores
    /// [`on_flow_tick`](crate::detect::Detector::on_flow_tick) in
    /// v1 — tick stats are cumulative, so naive per-tick recording
    /// would double-count a flow's bytes (delta-tracking is a
    /// follow-up).
    fn on_flow_end(
        &mut self,
        key: &K,
        stats: &FlowStats,
        _history: &HistoryString,
        _l4: Option<L4Proto>,
        ts: Timestamp,
        out: &mut Vec<OwnedAnomaly>,
    ) {
        let Some(src) = key.src_ip() else {
            return;
        };
        if let Some(score) = self.observe(src, stats.bytes_initiator, ts) {
            out.push(score.into_anomaly(ts));
        }
    }

    fn tracked(&self) -> usize {
        DataExfilDetector::tracked(self)
    }

    fn evict_expired(&mut self, now: Timestamp) {
        DataExfilDetector::evict_expired(self, now);
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn ip() -> IpAddr {
        IpAddr::from(Ipv4Addr::new(10, 0, 0, 1))
    }

    fn t(secs: u32) -> Timestamp {
        Timestamp::new(secs, 0)
    }

    #[test]
    fn spike_after_stable_baseline_fires() {
        let mut d = DataExfilDetector::new()
            .with_min_samples(10)
            .with_min_bytes(1_000_000);
        // 15 baseline flows near 2 MiB with mild jitter.
        for i in 0..15u32 {
            let bytes = 2_000_000 + if i % 2 == 0 { 10_000 } else { 0 };
            assert!(
                d.observe(ip(), bytes, t(i)).is_none(),
                "baseline flow {i} shouldn't fire"
            );
        }
        // A 50 MiB flow is a gross outlier.
        let s = d.observe(ip(), 50_000_000, t(100)).expect("exfil fires");
        assert_eq!(s.bytes, 50_000_000);
        assert!(s.n >= 10);
    }

    #[test]
    fn spike_below_min_bytes_does_not_fire() {
        let mut d = DataExfilDetector::new()
            .with_min_samples(5)
            .with_min_bytes(1_000_000);
        // Tiny, near-constant baseline (~100 bytes).
        for i in 0..10u32 {
            d.observe(ip(), 100 + (i % 2) as u64, t(i));
        }
        // 10 KiB is a huge z-score but below the 1 MiB floor.
        assert!(d.observe(ip(), 10_000, t(50)).is_none());
    }

    #[test]
    fn warmup_suppresses_before_min_samples() {
        let mut d = DataExfilDetector::new().with_min_samples(10);
        // Even a huge flow can't fire before the baseline warms.
        assert!(d.observe(ip(), 100_000_000, t(0)).is_none());
    }

    #[test]
    fn steady_high_volume_source_does_not_trip() {
        let mut d = DataExfilDetector::new()
            .with_min_samples(10)
            .with_min_bytes(1_000_000);
        // Consistently ~10 MiB — the baseline tracks it, so no
        // single flow is an outlier.
        for i in 0..40u32 {
            let bytes = 10_000_000 + (i as u64 % 3) * 1000;
            assert!(
                d.observe(ip(), bytes, t(i)).is_none(),
                "steady high volume shouldn't alarm at flow {i}"
            );
        }
    }

    #[test]
    fn cooldown_suppresses_repeat_spikes() {
        let mut d = DataExfilDetector::new()
            .with_min_samples(5)
            .with_min_bytes(1_000_000)
            .with_cooldown(Duration::from_secs(300));
        for i in 0..10u32 {
            d.observe(ip(), 2_000_000, t(i));
        }
        let mut alerts = 0;
        // Two back-to-back spikes within the cooldown.
        if d.observe(ip(), 50_000_000, t(100)).is_some() {
            alerts += 1;
        }
        if d.observe(ip(), 50_000_000, t(101)).is_some() {
            alerts += 1;
        }
        assert_eq!(alerts, 1, "cooldown suppresses the second spike");
    }
}

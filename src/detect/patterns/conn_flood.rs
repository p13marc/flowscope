//! Connection-flood detector — per-source new-flow rate over a
//! sliding window (issue #132).
//!
//! A source opening an abnormal number of connections in a short
//! window is the shape of a SYN/connection flood (DoS), a
//! misbehaving client, or aggressive scanning. This detector
//! counts **flow starts** per source IP in a
//! [`TimeBucketedCounter`]
//! and fires when the count crosses a threshold within the
//! window.
//!
//! Feed via [`Detector::on_flow_start`](crate::detect::Detector).
//! Rate-shaped (DoS, ATT&CK T1498); *scan*-shaped fan-out across
//! many destinations is [`PortScanDetector`](super::PortScanDetector)'s
//! job (T1046).
//!
//! # Known false positives
//!
//! NAT gateways, corporate proxies, and connection-pooling
//! clients legitimately front many flows from one IP; set the
//! threshold above the site's busiest legitimate source, or
//! allowlist known aggregators.

use std::{net::IpAddr, time::Duration};

use crate::{
    DetectorKind, OwnedAnomaly, Timestamp,
    anomaly_fields::KeyFields,
    correlate::{KeyIndexed, TimeBucketedCounter},
    detect::registry::SrcHost,
    event::Severity,
};

/// Per-source connection-flood detector.
pub struct ConnectionFloodDetector {
    starts: TimeBucketedCounter<IpAddr>,
    threshold: u64,
    window: Duration,
    cooldown: Duration,
    last_emitted: KeyIndexed<IpAddr, ()>,
}

/// Score from a connection-flood observation over threshold.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct FloodScore {
    /// Flooding source.
    pub src: IpAddr,
    /// New-flow count in the window.
    pub count: u64,
    /// Window length, seconds.
    pub window_secs: f64,
}

impl ConnectionFloodDetector {
    /// Default tuning: 10 s window / 1 s buckets, 100 flows per
    /// window, 10 000-source capacity, 60 s per-source cooldown.
    pub fn new() -> Self {
        Self::with_params(Duration::from_secs(10), Duration::from_secs(1), 100)
    }

    /// Custom window / bucket width / threshold.
    pub fn with_params(window: Duration, bucket_width: Duration, threshold: u64) -> Self {
        Self {
            starts: TimeBucketedCounter::new(window, bucket_width, 10_000),
            threshold,
            window,
            cooldown: Duration::from_secs(60),
            last_emitted: KeyIndexed::new(Duration::from_secs(60), 10_000),
        }
    }

    /// Per-source re-alert cooldown (default 60 s).
    pub fn with_cooldown(mut self, cooldown: Duration) -> Self {
        self.cooldown = cooldown;
        self.last_emitted = KeyIndexed::new(cooldown, 10_000);
        self
    }

    /// Observe one new flow from `src`. Returns `Some` when the
    /// windowed count crosses the threshold (cooldown-gated).
    pub fn observe(&mut self, src: IpAddr, now: Timestamp) -> Option<FloodScore> {
        self.starts.bump(src, now);
        let count = self.starts.count(&src, now);
        if count < self.threshold {
            return None;
        }
        if self.last_emitted.get(&src, now).is_some() {
            return None;
        }
        self.last_emitted.insert(src, (), now);
        Some(FloodScore {
            src,
            count,
            window_secs: self.window.as_secs_f64(),
        })
    }

    /// Reclaim window-expired counters.
    pub fn evict_expired(&mut self, now: Timestamp) {
        self.starts.evict_expired(now);
        self.last_emitted.evict_expired(now);
    }

    /// Sources currently tracked.
    pub fn tracked(&self) -> usize {
        self.starts.len()
    }
}

impl Default for ConnectionFloodDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl FloodScore {
    /// Canonical anomaly. `Warning`; metrics `count` +
    /// `window_secs`.
    pub fn into_anomaly(self, ts: Timestamp) -> OwnedAnomaly {
        OwnedAnomaly::new(DetectorKind::ConnectionFlood, Severity::Warning, ts)
            .with_key(&SrcHost(self.src))
            .with_metric("count", self.count as f64)
            .with_metric("window_secs", self.window_secs)
    }
}

impl crate::DetectorScore for FloodScore {
    fn kind(&self) -> DetectorKind {
        DetectorKind::ConnectionFlood
    }
    fn into_anomaly(self, ts: Timestamp) -> OwnedAnomaly {
        self.into_anomaly(ts)
    }
}

impl<K: KeyFields + Send> crate::detect::Detector<K> for ConnectionFloodDetector {
    fn kind(&self) -> DetectorKind {
        DetectorKind::ConnectionFlood
    }

    fn on_flow_start(&mut self, key: &K, ts: Timestamp, out: &mut Vec<OwnedAnomaly>) {
        let Some(src) = key.src_ip() else {
            return;
        };
        if let Some(score) = self.observe(src, ts) {
            out.push(score.into_anomaly(ts));
        }
    }

    fn tracked(&self) -> usize {
        ConnectionFloodDetector::tracked(self)
    }

    fn evict_expired(&mut self, now: Timestamp) {
        ConnectionFloodDetector::evict_expired(self, now);
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn ip(last: u8) -> IpAddr {
        IpAddr::from(Ipv4Addr::new(10, 0, 0, last))
    }

    #[test]
    fn burst_over_threshold_fires_once() {
        let mut d = ConnectionFloodDetector::with_params(
            Duration::from_secs(10),
            Duration::from_secs(1),
            100,
        );
        let mut alerts = 0;
        for i in 0..150 {
            // 150 flows within a 10 s window (all at t=0..1s).
            if d.observe(ip(1), Timestamp::new(0, i)).is_some() {
                alerts += 1;
            }
        }
        assert_eq!(alerts, 1, "one alert per cooldown");
    }

    #[test]
    fn slow_rate_stays_quiet() {
        let mut d = ConnectionFloodDetector::with_params(
            Duration::from_secs(10),
            Duration::from_secs(1),
            100,
        );
        // 1 flow/sec for 60 s — never 100 within any 10 s window.
        for s in 0..60 {
            assert!(d.observe(ip(1), Timestamp::new(s, 0)).is_none());
        }
    }

    #[test]
    fn per_source_isolation() {
        let mut d = ConnectionFloodDetector::with_params(
            Duration::from_secs(10),
            Duration::from_secs(1),
            50,
        );
        // Source 1 floods; source 2 is quiet.
        for i in 0..60 {
            d.observe(ip(1), Timestamp::new(0, i));
        }
        assert!(d.observe(ip(2), Timestamp::new(0, 0)).is_none());
    }

    #[test]
    fn cooldown_then_realert_after_window() {
        let mut d = ConnectionFloodDetector::with_params(
            Duration::from_secs(2),
            Duration::from_secs(1),
            10,
        )
        .with_cooldown(Duration::from_secs(5));
        let mut alerts = 0;
        // First flood at t≈0.
        for i in 0..20 {
            if d.observe(ip(1), Timestamp::new(0, i)).is_some() {
                alerts += 1;
            }
        }
        // Second flood at t=10 (past both window + cooldown).
        for i in 0..20 {
            if d.observe(ip(1), Timestamp::new(10, i)).is_some() {
                alerts += 1;
            }
        }
        assert_eq!(alerts, 2, "re-alert after cooldown elapses");
    }
}

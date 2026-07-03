//! DNS tunneling detector — distinct-subdomain cardinality per
//! `(source, registered domain)` over a sliding window (issue
//! #132).
//!
//! DNS tunnels (iodine, dnscat2, data-exfil-over-DNS) encode
//! payload into the *subdomain* labels of queries to an
//! attacker-controlled zone, producing an unusually large number
//! of **distinct** long qnames under one registered domain in a
//! short window. This detector counts distinct subdomains per
//! `(src IP, registered domain)` in a [`TimeBucketedSet`] and
//! fires when the count crosses a threshold (long qnames only —
//! short lookups don't carry a payload).
//!
//! Feed it via [`Detector::on_dns_query`](crate::detect::Detector)
//! (or call [`observe`](DnsTunnelDetector::observe) directly).
//! Names are pre-extracted `&str`, so this stays independent of
//! the `dns` Cargo feature.
//!
//! # Known false positives
//!
//! CDNs and telemetry backends legitimately query many distinct
//! long subdomains under one domain (`*.cloudfront.net`,
//! `*.telemetry.example`); DNSSEC NSEC3 walking looks similar.
//! Tune `subdomain_threshold` / `min_qname_len` for the site, or
//! allowlist known-good registered domains upstream.

use std::{hash::BuildHasher, net::IpAddr, time::Duration};

use crate::{
    DetectorKind, OwnedAnomaly, Timestamp, anomaly_fields::KeyFields, correlate::TimeBucketedSet,
    detect::registry::SrcHost, event::Severity,
};

/// Per-`(source, registered-domain)` DNS-tunnel detector.
pub struct DnsTunnelDetector {
    distinct: TimeBucketedSet<(IpAddr, String), u64>,
    subdomain_threshold: usize,
    min_qname_len: usize,
    cooldown: Duration,
    last_emitted: crate::correlate::KeyIndexed<(IpAddr, String), ()>,
    hasher: std::hash::RandomState,
}

/// Score from a DNS-tunnel observation that crossed the
/// threshold.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DnsTunnelScore {
    /// Querying source.
    pub src: IpAddr,
    /// Registered (last-two-label) domain the subdomains sit under.
    pub domain: String,
    /// Distinct long subdomains seen in the window.
    pub distinct_subdomains: usize,
    /// Length of the qname that tripped the threshold.
    pub qname_len: usize,
}

impl DnsTunnelDetector {
    /// Default tuning: 300 s window / 30 s buckets, capacity
    /// 10 000 source-domain pairs, ≥ 50 distinct subdomains of
    /// ≥ 50 bytes, 300 s per-pair cooldown.
    pub fn new() -> Self {
        Self {
            distinct: TimeBucketedSet::new(
                Duration::from_secs(300),
                Duration::from_secs(30),
                10_000,
            ),
            subdomain_threshold: 50,
            min_qname_len: 50,
            cooldown: Duration::from_secs(300),
            last_emitted: crate::correlate::KeyIndexed::new(Duration::from_secs(300), 10_000),
            hasher: std::hash::RandomState::new(),
        }
    }

    /// Distinct-subdomain count that trips a verdict (default 50).
    pub fn with_subdomain_threshold(mut self, n: usize) -> Self {
        self.subdomain_threshold = n;
        self
    }

    /// Minimum qname byte length counted (default 50 — short
    /// lookups carry no tunnel payload).
    pub fn with_min_qname_len(mut self, n: usize) -> Self {
        self.min_qname_len = n;
        self
    }

    /// Per-`(source, domain)` re-alert cooldown (default 300 s).
    pub fn with_cooldown(mut self, cooldown: Duration) -> Self {
        self.cooldown = cooldown;
        self.last_emitted = crate::correlate::KeyIndexed::new(cooldown, 10_000);
        self
    }

    /// PSL-free registered domain: last two dot-labels
    /// (`a.b.evil.com` → `evil.com`). Imperfect for `co.uk`-style
    /// public suffixes — allowlist or pre-extract when it matters.
    fn registered_domain(qname: &str) -> Option<(String, &str)> {
        let trimmed = qname.trim().trim_end_matches('.');
        if trimmed.is_empty() {
            return None;
        }
        let labels: Vec<&str> = trimmed.split('.').collect();
        let domain = match labels.len() {
            0 => return None,
            1 | 2 => trimmed.to_ascii_lowercase(),
            n => format!(
                "{}.{}",
                labels[n - 2].to_ascii_lowercase(),
                labels[n - 1].to_ascii_lowercase()
            ),
        };
        Some((domain, trimmed))
    }

    /// Observe one DNS query name from `src`. Returns `Some` when
    /// this query pushes the `(src, registered-domain)` pair over
    /// the distinct-subdomain threshold (cooldown-gated).
    pub fn observe(&mut self, src: IpAddr, qname: &str, now: Timestamp) -> Option<DnsTunnelScore> {
        let qname_len = qname.len();
        if qname_len < self.min_qname_len {
            return None;
        }
        let (domain, full) = Self::registered_domain(qname)?;
        // Store a hash of the full qname, not the owned string — the
        // set only needs distinct-cardinality, not the values.
        let subdomain_hash = self.hasher.hash_one(full.to_ascii_lowercase());

        let bucket_key = (src, domain.clone());
        self.distinct
            .insert(bucket_key.clone(), subdomain_hash, now);
        let distinct = self.distinct.cardinality(&bucket_key, now);
        if distinct < self.subdomain_threshold {
            return None;
        }
        // Cooldown: at most one alert per pair per window.
        if self.last_emitted.get(&bucket_key, now).is_some() {
            return None;
        }
        self.last_emitted.insert(bucket_key, (), now);
        Some(DnsTunnelScore {
            src,
            domain,
            distinct_subdomains: distinct,
            qname_len,
        })
    }

    /// Reclaim window-expired state.
    pub fn evict_expired(&mut self, now: Timestamp) {
        self.distinct.evict_expired(now);
        self.last_emitted.evict_expired(now);
    }

    /// Number of `(source, domain)` pairs currently tracked.
    pub fn tracked(&self) -> usize {
        self.distinct.len()
    }
}

impl Default for DnsTunnelDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsTunnelScore {
    /// Canonical anomaly. `Warning`; metrics
    /// `distinct_subdomains` + `qname_len`, observation `domain`.
    pub fn into_anomaly(self, ts: Timestamp) -> OwnedAnomaly {
        OwnedAnomaly::new(DetectorKind::DnsTunnel, Severity::Warning, ts)
            .with_key(&SrcHost(self.src))
            .with_observation("domain", self.domain)
            .with_metric("distinct_subdomains", self.distinct_subdomains as f64)
            .with_metric("qname_len", self.qname_len as f64)
    }
}

impl crate::DetectorScore for DnsTunnelScore {
    fn kind(&self) -> DetectorKind {
        DetectorKind::DnsTunnel
    }
    fn into_anomaly(self, ts: Timestamp) -> OwnedAnomaly {
        self.into_anomaly(ts)
    }
}

impl<K: KeyFields + Send> crate::detect::Detector<K> for DnsTunnelDetector {
    fn kind(&self) -> DetectorKind {
        DetectorKind::DnsTunnel
    }

    fn on_dns_query(&mut self, key: &K, qname: &str, ts: Timestamp, out: &mut Vec<OwnedAnomaly>) {
        let Some(src) = key.src_ip() else {
            return;
        };
        if let Some(score) = self.observe(src, qname, ts) {
            out.push(score.into_anomaly(ts));
        }
    }

    fn tracked(&self) -> usize {
        DnsTunnelDetector::tracked(self)
    }

    fn evict_expired(&mut self, now: Timestamp) {
        DnsTunnelDetector::evict_expired(self, now);
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn ip() -> IpAddr {
        IpAddr::from(Ipv4Addr::new(10, 0, 0, 1))
    }

    fn long_sub(i: usize) -> String {
        // ~60-byte qname under evil.com.
        format!("{i:0>54}.evil.com")
    }

    #[test]
    fn many_distinct_long_subdomains_fire() {
        let mut d = DnsTunnelDetector::new().with_subdomain_threshold(50);
        let mut fired = None;
        for i in 0..60 {
            if let Some(s) = d.observe(ip(), &long_sub(i), Timestamp::new(i as u32, 0)) {
                fired = Some(s);
                break;
            }
        }
        let s = fired.expect("threshold crossed");
        assert_eq!(s.domain, "evil.com");
        assert!(s.distinct_subdomains >= 50);
    }

    #[test]
    fn short_qnames_never_fire() {
        let mut d = DnsTunnelDetector::new().with_subdomain_threshold(5);
        for i in 0..100 {
            // "aN.evil.com" — well under min_qname_len.
            let q = format!("a{i}.evil.com");
            assert!(d.observe(ip(), &q, Timestamp::new(i, 0)).is_none());
        }
    }

    #[test]
    fn repeated_same_subdomain_does_not_inflate() {
        let mut d = DnsTunnelDetector::new().with_subdomain_threshold(50);
        for i in 0..200 {
            // Same qname every time → cardinality stays 1.
            assert!(
                d.observe(ip(), &long_sub(7), Timestamp::new(i, 0))
                    .is_none()
            );
        }
    }

    #[test]
    fn cooldown_suppresses_repeat_alerts() {
        let mut d = DnsTunnelDetector::new()
            .with_subdomain_threshold(50)
            .with_cooldown(Duration::from_secs(300));
        let mut alerts = 0;
        for i in 0..120 {
            if d.observe(ip(), &long_sub(i), Timestamp::new(i as u32, 0))
                .is_some()
            {
                alerts += 1;
            }
        }
        assert_eq!(alerts, 1, "one alert within the cooldown window");
    }

    #[test]
    fn benign_cdn_under_threshold_stays_quiet() {
        let mut d = DnsTunnelDetector::new().with_subdomain_threshold(50);
        // 20 distinct long subdomains — below threshold.
        for i in 0..20 {
            assert!(
                d.observe(
                    ip(),
                    &format!("{i:0>54}.cloudfront.net"),
                    Timestamp::new(i as u32, 0)
                )
                .is_none()
            );
        }
    }
}

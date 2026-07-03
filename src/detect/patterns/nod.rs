//! Newly-observed-domain (NOD) detector — first-contact with a
//! registered domain never seen before (issue #132).
//!
//! Malware C2, phishing, and fast-flux infrastructure lean on
//! freshly-registered / rarely-seen domains. This detector keeps
//! a bounded TTL'd first-seen set
//! ([`FirstSeen`]) of registered
//! domains and flags the **first** query to a domain not seen
//! within the TTL — after a warmup grace so a cold start doesn't
//! flag the entire legitimate baseline.
//!
//! Feed via [`Detector::on_dns_query`](crate::detect::Detector)
//! (pre-extracted `&str`, so no `dns`-feature coupling).
//!
//! # Known false positives
//!
//! Every legitimate first visit to a new site is "newly
//! observed"; NOD is a **context** signal, best paired with
//! reputation / beaconing / volume — not a standalone verdict.
//! CDN and cloud-tenant subdomains churn constantly; the
//! registered-domain rollup dampens but doesn't eliminate this.

use std::{net::IpAddr, time::Duration};

use crate::{
    DetectorKind, OwnedAnomaly, Timestamp, anomaly_fields::KeyFields, correlate::FirstSeen,
    detect::registry::SrcHost, event::Severity,
};

/// Newly-observed-domain detector over a bounded first-seen set.
pub struct NewlyObservedDomainDetector {
    seen: FirstSeen<String>,
    warmup: Duration,
    started_at: Option<Timestamp>,
}

/// Score from a newly-observed-domain hit.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct NodScore {
    /// Querying source (for anomaly 5-tuple context).
    pub src: Option<IpAddr>,
    /// The newly-observed registered domain.
    pub domain: String,
}

impl NewlyObservedDomainDetector {
    /// Default tuning: 100 000-domain capacity, 7-day TTL,
    /// 600 s warmup (suppress all hits until the set has had time
    /// to fill with the legitimate baseline).
    pub fn new() -> Self {
        Self {
            seen: FirstSeen::new(Duration::from_secs(7 * 24 * 60 * 60), 100_000),
            warmup: Duration::from_secs(600),
            started_at: None,
        }
    }

    /// First-seen set capacity + TTL. A domain silent longer than
    /// `ttl` is "new" again.
    pub fn with_capacity(mut self, ttl: Duration, capacity: usize) -> Self {
        self.seen = FirstSeen::new(ttl, capacity);
        self
    }

    /// Warmup grace after the first observation during which no
    /// hit is emitted (default 600 s). Prevents a cold start from
    /// flagging the whole baseline.
    pub fn with_warmup(mut self, warmup: Duration) -> Self {
        self.warmup = warmup;
        self
    }

    /// PSL-free registered domain (last two labels).
    fn registered_domain(qname: &str) -> Option<String> {
        let trimmed = qname.trim().trim_end_matches('.');
        if trimmed.is_empty() {
            return None;
        }
        let labels: Vec<&str> = trimmed.split('.').collect();
        Some(match labels.len() {
            0 => return None,
            1 | 2 => trimmed.to_ascii_lowercase(),
            n => format!(
                "{}.{}",
                labels[n - 2].to_ascii_lowercase(),
                labels[n - 1].to_ascii_lowercase()
            ),
        })
    }

    /// Observe one query name. Returns `Some` the first time a
    /// registered domain is seen (post-warmup). `src` is carried
    /// into the score for 5-tuple context only.
    pub fn observe(
        &mut self,
        src: Option<IpAddr>,
        qname: &str,
        now: Timestamp,
    ) -> Option<NodScore> {
        let started = *self.started_at.get_or_insert(now);
        let domain = Self::registered_domain(qname)?;
        let is_new = self.seen.observe(domain.clone(), now);
        // Suppress during warmup (still records the domain above, so
        // the baseline fills).
        if !is_new || now.saturating_sub(started) < self.warmup {
            return None;
        }
        Some(NodScore { src, domain })
    }

    /// Reclaim TTL-expired domains.
    pub fn evict_expired(&mut self, now: Timestamp) {
        self.seen.evict_expired(now);
    }

    /// Distinct domains currently tracked.
    pub fn tracked(&self) -> usize {
        self.seen.len()
    }
}

impl Default for NewlyObservedDomainDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl NodScore {
    /// Canonical anomaly. `Info` (NOD is a context signal, not a
    /// standalone verdict); observation `domain`.
    pub fn into_anomaly(self, ts: Timestamp) -> OwnedAnomaly {
        let mut a = OwnedAnomaly::new(DetectorKind::NewlyObservedDomain, Severity::Info, ts);
        if let Some(src) = self.src {
            a = a.with_key(&SrcHost(src));
        }
        a.with_observation("domain", self.domain)
    }
}

impl crate::DetectorScore for NodScore {
    fn kind(&self) -> DetectorKind {
        DetectorKind::NewlyObservedDomain
    }
    fn into_anomaly(self, ts: Timestamp) -> OwnedAnomaly {
        self.into_anomaly(ts)
    }
}

impl<K: KeyFields + Send> crate::detect::Detector<K> for NewlyObservedDomainDetector {
    fn kind(&self) -> DetectorKind {
        DetectorKind::NewlyObservedDomain
    }

    fn on_dns_query(&mut self, key: &K, qname: &str, ts: Timestamp, out: &mut Vec<OwnedAnomaly>) {
        if let Some(score) = self.observe(key.src_ip(), qname, ts) {
            out.push(score.into_anomaly(ts));
        }
    }

    fn tracked(&self) -> usize {
        NewlyObservedDomainDetector::tracked(self)
    }

    fn evict_expired(&mut self, now: Timestamp) {
        NewlyObservedDomainDetector::evict_expired(self, now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(secs: u32) -> Timestamp {
        Timestamp::new(secs, 0)
    }

    #[test]
    fn first_sight_after_warmup_fires_once() {
        let mut d = NewlyObservedDomainDetector::new().with_warmup(Duration::from_secs(600));
        // t=0 starts the clock; warmup suppresses everything <600 s.
        assert!(d.observe(None, "warmup.example", t(0)).is_none());
        // Post-warmup first sight fires.
        let s = d.observe(None, "evil.com", t(700)).expect("NOD hit");
        assert_eq!(s.domain, "evil.com");
        // Second sight of the same domain does not.
        assert!(d.observe(None, "sub.evil.com", t(701)).is_none());
    }

    #[test]
    fn warmup_suppresses_baseline_but_records_it() {
        let mut d = NewlyObservedDomainDetector::new().with_warmup(Duration::from_secs(600));
        // Seen during warmup — suppressed but recorded.
        assert!(d.observe(None, "google.com", t(0)).is_none());
        // Same domain post-warmup: NOT new (recorded during warmup).
        assert!(d.observe(None, "google.com", t(700)).is_none());
    }

    #[test]
    fn ttl_expiry_makes_domain_new_again() {
        let mut d = NewlyObservedDomainDetector::new()
            .with_capacity(Duration::from_secs(10), 1024)
            .with_warmup(Duration::from_secs(0));
        assert!(d.observe(None, "evil.com", t(0)).is_some());
        assert!(d.observe(None, "evil.com", t(5)).is_none());
        // Silent > 10 s TTL → new again.
        assert!(d.observe(None, "evil.com", t(30)).is_some());
    }

    #[test]
    fn registered_domain_rollup() {
        let mut d = NewlyObservedDomainDetector::new().with_warmup(Duration::from_secs(0));
        assert!(d.observe(None, "a.b.evil.com", t(0)).is_some());
        // Different subdomain, same registered domain: not new.
        assert!(d.observe(None, "x.y.evil.com", t(1)).is_none());
    }
}

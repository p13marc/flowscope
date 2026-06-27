//! [`FlowAnalyzer`] — the per-flow analysis accumulation engine.
//!
//! A bounded, runtime-free composition layer (the same shape as
//! [`crate::asset::Inventory`]) that turns the stream of parser
//! messages + flow-lifecycle events into enriched
//! [`AnalyzedFlow`] records. It:
//!
//! 1. accumulates the curated [`L7Summary`] per flow as you feed
//!    it parser messages (`observe_*`),
//! 2. on flow end, [`finalize`](FlowAnalyzer::finalize)s: computes
//!    the [`FlowRisk`] and screens the flow against the optional
//!    [`IocSet`], evicts the per-flow state, and returns the
//!    [`AnalyzedFlow`],
//! 3. bounds memory via a TTL + capacity on the per-flow state
//!    ([`evict_expired`](FlowAnalyzer::evict_expired) reclaims
//!    flows that ended without an explicit `finalize`).
//!
//! It is deliberately **not** a driver — wire it to whatever
//! source you already run (`Driver<E>` slots + the `Event` stream,
//! a `FlowSessionDriver`, a pcap loop). See
//! `examples/03-detection/flow_analysis.rs`.

use std::hash::Hash;
use std::time::Duration;

use crate::analysis::{AnalyzedFlow, L7Summary};
use crate::correlate::KeyIndexed;
use crate::detect::patterns::DgaScorer;
use crate::detect::risk::{is_weak_cipher, label_matches};
use crate::detect::{FlowRisk, IocKind, IocMatch, IocSet};
use crate::{FlowStats, KeyFields, Timestamp};

/// Per-flow analysis accumulator. Generic over the flow key `K`.
pub struct FlowAnalyzer<K>
where
    K: Hash + Eq,
{
    summaries: KeyIndexed<K, L7Summary>,
    ioc: Option<IocSet>,
    dga: DgaScorer,
}

impl<K> FlowAnalyzer<K>
where
    K: Hash + Eq + Clone,
{
    /// New analyzer with unbounded per-flow state expired only by
    /// `ttl` (idle flows reclaimed by
    /// [`evict_expired`](Self::evict_expired)). Prefer
    /// [`with_capacity`](Self::with_capacity) in production.
    pub fn new(ttl: Duration) -> Self {
        Self {
            summaries: KeyIndexed::new_unbounded(ttl),
            ioc: None,
            dga: DgaScorer::new(),
        }
    }

    /// New analyzer bounded to `capacity` concurrently-tracked
    /// flows (LRU eviction past the cap) plus the `ttl` idle
    /// expiry — the project's bounded-memory contract.
    pub fn with_capacity(ttl: Duration, capacity: usize) -> Self {
        Self {
            summaries: KeyIndexed::new(ttl, capacity),
            ioc: None,
            dga: DgaScorer::new(),
        }
    }

    /// Attach a threat-intel [`IocSet`] to screen flows against at
    /// [`finalize`](Self::finalize) time (SNI / DNS qnames / IPs /
    /// JA3 / JA4). Without one, [`AnalyzedFlow::ioc_hits`] is
    /// always empty.
    pub fn with_ioc(mut self, ioc: IocSet) -> Self {
        self.ioc = Some(ioc);
        self
    }

    /// Number of flows with accumulated state.
    pub fn len(&self) -> usize {
        self.summaries.len()
    }

    /// `true` if no flow state is held.
    pub fn is_empty(&self) -> bool {
        self.summaries.is_empty()
    }

    #[cfg(any(feature = "tls", feature = "http", feature = "dns"))]
    fn summary_mut(&mut self, key: &K, ts: Timestamp) -> &mut L7Summary {
        if self.summaries.get_mut(key, ts).is_none() {
            self.summaries.insert(key.clone(), L7Summary::default(), ts);
        }
        self.summaries
            .get_mut(key, ts)
            .expect("summary just inserted")
    }

    /// Fold a completed TLS handshake into the flow's summary.
    #[cfg(feature = "tls")]
    pub fn observe_tls(&mut self, key: &K, hs: &crate::tls::TlsHandshake, ts: Timestamp) {
        self.summary_mut(key, ts).observe_tls(hs);
    }

    /// Fold an HTTP message into the flow's summary (requests
    /// only; see [`L7Summary::observe_http`]).
    #[cfg(feature = "http")]
    pub fn observe_http(&mut self, key: &K, msg: &crate::http::HttpMessage, ts: Timestamp) {
        self.summary_mut(key, ts).observe_http(msg);
    }

    /// Record the query names from a DNS query.
    #[cfg(feature = "dns")]
    pub fn observe_dns_query(&mut self, key: &K, q: &crate::dns::DnsQuery, ts: Timestamp) {
        self.summary_mut(key, ts).observe_dns_query(q);
    }

    /// Record the query names from a DNS response.
    #[cfg(feature = "dns")]
    pub fn observe_dns_response(&mut self, key: &K, r: &crate::dns::DnsResponse, ts: Timestamp) {
        self.summary_mut(key, ts).observe_dns_response(r);
    }

    /// Reclaim per-flow state for flows idle longer than the TTL —
    /// call periodically (e.g. on a tracker tick) so flows that
    /// end without an explicit [`finalize`](Self::finalize) don't
    /// linger.
    pub fn evict_expired(&mut self, now: Timestamp) {
        self.summaries.evict_expired(now);
    }

    /// Drop a flow's accumulated state without producing a record
    /// (e.g. a flow you decided not to analyze). Returns whether
    /// state was present.
    pub fn forget(&mut self, key: &K) -> bool {
        self.summaries.remove(key).is_some()
    }
}

impl<K> FlowAnalyzer<K>
where
    K: Hash + Eq + Clone + KeyFields,
{
    /// Finalize a flow on its `Ended` event: take its accumulated
    /// [`L7Summary`], compute the [`FlowRisk`] and IOC hits, evict
    /// the per-flow state, and return the enriched
    /// [`AnalyzedFlow`]. Idempotent — a second call for the same
    /// key sees an empty summary.
    pub fn finalize(&mut self, key: &K, stats: FlowStats) -> AnalyzedFlow<K> {
        let l7 = self.summaries.remove(key).unwrap_or_default();
        let ioc_hits = self.compute_ioc(key, &l7);
        let risk = self.compute_risk(key, &l7, &ioc_hits);
        AnalyzedFlow {
            key: key.clone(),
            stats,
            l7,
            risk,
            ioc_hits,
        }
    }

    /// Compute the [`AnalyzedFlow`] for a flow **without** evicting
    /// its state — a mid-flow snapshot at `now`. Use
    /// [`finalize`](Self::finalize) on the terminal event.
    pub fn snapshot(&self, key: &K, now: Timestamp, stats: FlowStats) -> AnalyzedFlow<K> {
        let l7 = self.summaries.peek(key, now).cloned().unwrap_or_default();
        let ioc_hits = self.compute_ioc(key, &l7);
        let risk = self.compute_risk(key, &l7, &ioc_hits);
        AnalyzedFlow {
            key: key.clone(),
            stats,
            l7,
            risk,
            ioc_hits,
        }
    }

    fn compute_ioc(&self, key: &K, l7: &L7Summary) -> Vec<IocMatch> {
        let mut hits = Vec::new();
        let Some(ioc) = &self.ioc else {
            return hits;
        };
        if let Some(ip) = key.src_ip()
            && let Some(m) = ioc.contains_ip(ip)
        {
            hits.push(m);
        }
        if let Some(ip) = key.dest_ip()
            && let Some(m) = ioc.contains_ip(ip)
        {
            hits.push(m);
        }
        if let Some(sn) = &l7.server_name
            && let Some(m) = ioc.contains_domain(sn)
        {
            hits.push(m);
        }
        for q in &l7.dns_queries {
            if let Some(m) = ioc.contains_domain(q) {
                hits.push(m);
            }
        }
        if let Some(j) = &l7.ja3
            && let Some(m) = ioc.contains(IocKind::Ja3, j)
        {
            hits.push(m);
        }
        if let Some(j) = &l7.ja4
            && let Some(m) = ioc.contains(IocKind::Ja4, j)
        {
            hits.push(m);
        }
        hits
    }

    fn compute_risk(&self, key: &K, l7: &L7Summary, ioc_hits: &[IocMatch]) -> FlowRisk {
        let mut r = FlowRisk::empty();

        // TLS posture (raw code points carried in the summary).
        if let Some(v) = l7.tls_version
            && v < 0x0303
        {
            r |= FlowRisk::TLS_OBSOLETE_VERSION;
        }
        if let Some(c) = l7.tls_cipher
            && is_weak_cipher(c)
        {
            r |= FlowRisk::TLS_WEAK_CIPHER;
        }

        // DGA / Punycode over every name the flow asked for.
        for q in &l7.dns_queries {
            r |= FlowRisk::from_dns(q, &self.dga);
        }
        if let Some(sn) = &l7.server_name {
            r |= FlowRisk::from_dns(sn, &self.dga);
        }

        // Port / protocol consistency, using the detected app slug
        // vs the well-known port label (alias-token aware, so
        // "tls" on 443's "tls/https" label is consistent).
        if let Some(detected) = l7.app_proto
            && let (Some(pid), Some(sp), Some(dp)) =
                (key.protocol_identifier(), key.src_port(), key.dest_port())
        {
            let proto = l4_from_id(pid);
            match crate::well_known::protocol_label(proto, sp, dp) {
                Some(label) if label_matches(label, detected) => {}
                Some(_) => r |= FlowRisk::PORT_PROTO_MISMATCH,
                None => r |= FlowRisk::KNOWN_PROTO_NONSTD_PORT,
            }
        }

        // A JA3/JA4 fingerprint on a threat-intel list.
        if ioc_hits
            .iter()
            .any(|m| matches!(m.kind, IocKind::Ja3 | IocKind::Ja4))
        {
            r |= FlowRisk::SUSPICIOUS_JA4;
        }

        r
    }
}

/// Reconstruct an [`crate::L4Proto`] from its IANA number (the
/// value [`KeyFields::protocol_identifier`] reports).
fn l4_from_id(id: u8) -> crate::L4Proto {
    match id {
        6 => crate::L4Proto::Tcp,
        17 => crate::L4Proto::Udp,
        1 => crate::L4Proto::Icmp,
        58 => crate::L4Proto::IcmpV6,
        132 => crate::L4Proto::Sctp,
        other => crate::L4Proto::Other(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::FiveTupleKey;
    use std::net::SocketAddr;

    fn key(dport: u16) -> FiveTupleKey {
        FiveTupleKey {
            proto: crate::L4Proto::Tcp,
            a: "10.0.0.9:40000".parse::<SocketAddr>().unwrap(),
            b: format!("93.184.216.34:{dport}")
                .parse::<SocketAddr>()
                .unwrap(),
        }
    }

    fn ttl() -> Duration {
        Duration::from_secs(60)
    }

    #[test]
    fn empty_flow_finalizes_clean() {
        let mut a = FlowAnalyzer::<FiveTupleKey>::new(ttl());
        let af = a.finalize(&key(443), FlowStats::default());
        assert!(af.is_clean());
        assert!(af.l7.is_empty());
        assert_eq!(a.len(), 0);
    }

    #[cfg(feature = "tls")]
    #[test]
    fn tls_obsolete_and_weak_cipher_scored() {
        use crate::tls::{TlsHandshake, TlsVersion};
        let mut a = FlowAnalyzer::<FiveTupleKey>::new(ttl());
        let k = key(443);
        let hs = TlsHandshake {
            sni: Some("example.com".into()),
            version: Some(TlsVersion::Tls1_0),
            cipher_suite: Some(0x0005), // RC4
            ..Default::default()
        };
        a.observe_tls(&k, &hs, Timestamp::default());
        assert_eq!(a.len(), 1);
        let af = a.finalize(&k, FlowStats::default());
        assert!(af.risk.contains(FlowRisk::TLS_OBSOLETE_VERSION));
        assert!(af.risk.contains(FlowRisk::TLS_WEAK_CIPHER));
        // "tls" on 443 is consistent — no port/proto mismatch.
        assert!(!af.risk.contains(FlowRisk::PORT_PROTO_MISMATCH));
        assert_eq!(af.l7.server_name.as_deref(), Some("example.com"));
        // State evicted on finalize.
        assert_eq!(a.len(), 0);
    }

    #[cfg(feature = "tls")]
    #[test]
    fn ioc_ja4_hit_sets_suspicious_and_records_match() {
        use crate::tls::TlsHandshake;
        let mut ioc = IocSet::new();
        ioc.insert(IocKind::Ja4, "t13d1516h2_abc_def", Some(95), Some("intel"));
        let mut a = FlowAnalyzer::<FiveTupleKey>::new(ttl()).with_ioc(ioc);
        let k = key(8443);
        let hs = TlsHandshake {
            ja4: Some("t13d1516h2_abc_def".into()),
            ..Default::default()
        };
        a.observe_tls(&k, &hs, Timestamp::default());
        let af = a.finalize(&k, FlowStats::default());
        assert!(af.has_ioc());
        assert!(af.risk.contains(FlowRisk::SUSPICIOUS_JA4));
        assert!(af.ioc_hits.iter().any(|m| m.kind == IocKind::Ja4));
    }

    #[cfg(feature = "dns")]
    #[test]
    fn dns_dga_and_ip_ioc() {
        use crate::dns::{DnsFlags, DnsQuery, DnsQuestion};
        let mut ioc = IocSet::new();
        // The responder IP from `key()`.
        ioc.insert(IocKind::Ipv4, "93.184.216.34", Some(80), Some("c2-list"));
        let mut a = FlowAnalyzer::<FiveTupleKey>::new(ttl()).with_ioc(ioc);
        let k = key(53);
        let q = DnsQuery {
            transaction_id: 1,
            flags: DnsFlags(0),
            questions: vec![DnsQuestion {
                name: "kq3v9z7xj2wq.com".into(),
                qtype: 1,
                qclass: 1,
            }],
            timestamp: Timestamp::default(),
        };
        a.observe_dns_query(&k, &q, Timestamp::default());
        let af = a.finalize(&k, FlowStats::default());
        assert!(af.risk.contains(FlowRisk::DGA_DOMAIN));
        assert!(af.ioc_hits.iter().any(|m| m.kind == IocKind::Ipv4));
    }

    #[test]
    fn evict_expired_reclaims_idle_state() {
        let mut a = FlowAnalyzer::<FiveTupleKey>::with_capacity(Duration::from_secs(1), 100);
        // Insert at t=0 via a forget-then-observe-free path: use a
        // direct summary insert through observe-less API isn't
        // exposed, so drive through finalize-less accumulation.
        a.summaries
            .insert(key(443), L7Summary::default(), Timestamp::new(0, 0));
        assert_eq!(a.len(), 1);
        a.evict_expired(Timestamp::new(5, 0));
        assert_eq!(a.len(), 0);
    }
}

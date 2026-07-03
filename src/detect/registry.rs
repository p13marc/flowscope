//! Unified [`Detector`] trait + [`DetectorRegistry`] pipeline
//! (issue #131).
//!
//! Before 0.21 every detector had its own observe surface —
//! `(key, ts, bytes)` for beacons, `(key, success)` for the
//! port-scan TRW, `&str` for DGA — and consumers hand-wired a
//! `Vec` of detectors, each with bespoke feed/drain plumbing.
//! The registry keeps the heterogeneous inputs (they're
//! genuinely different) but unifies the **event-to-detector
//! dispatch**: register detectors once, then drive them all
//! from one `observe(&event, &mut out)` call per flow event and
//! one `observe_dns` call per DNS query.
//!
//! ```text
//! tracker/driver events ─▶ registry.observe(&evt, &mut out) ─▶ Vec<OwnedAnomaly> ─▶ EVE/NDJSON
//! DNS slot drain ────────▶ registry.observe_dns(key, qname, ts, &mut out) ──┘
//! ```
//!
//! # Design notes
//!
//! - **Hook-based, not input-enum-based.** [`Detector`] exposes
//!   one defaulted no-op hook per feed (`on_flow_start`,
//!   `on_flow_end`, `on_dns_query`, …). The registry matches
//!   each event **once** and fans the right hook to N
//!   detectors; a detector implements only the feeds it
//!   consumes. New feeds arrive as new defaulted hooks —
//!   non-breaking.
//! - **DNS names are not flow events.** Query names reach
//!   consumers through DNS parser drains (`SlotHandle` /
//!   `DnsMessage`), so the registry has a dedicated
//!   [`observe_dns`](DetectorRegistry::observe_dns) entry point
//!   — the same split `analysis::FlowAnalyzer` uses. Names are
//!   pre-extracted `&str`, keeping `detect` independent of the
//!   `dns` Cargo feature.
//! - **Caller-buffer output.** Hooks append to a caller-owned
//!   `Vec<OwnedAnomaly>` (the `track_into` idiom): zero
//!   per-event allocation in steady state, no unbounded
//!   internal queues.
//! - **Actionable-only emission.** The shipped impls gate on
//!   per-detector thresholds + cooldowns
//!   (`with_anomaly_threshold` / `with_cooldown` /
//!   suppression), so a registry drain is alert-shaped, not
//!   score-shaped. Use the detectors' raw `observe` methods
//!   directly when you want every score.

use std::{net::IpAddr, time::Duration};

use lru::LruCache;

use crate::{
    DetectorKind, OwnedAnomaly, Timestamp,
    anomaly_fields::KeyFields,
    detect::patterns::{BeaconDetector, DgaScorer, PortScanDetector, RitaBeaconDetector},
    event::{FlowEvent, FlowStats},
    extractor::L4Proto,
    history::HistoryString,
};

/// One detection algorithm, driven by a [`DetectorRegistry`].
///
/// Every hook defaults to a no-op — implement only the feeds
/// the detector consumes. Hooks append emission-worthy
/// anomalies to `out` (caller-owned buffer, `track_into`
/// idiom).
///
/// `Send` so a registry can ride a driver task across worker
/// threads (all shipped detectors are trivially `Send`).
pub trait Detector<K>: Send {
    /// Typed identity — lands on every anomaly this detector
    /// emits and drives metric labels / ATT&CK tagging.
    fn kind(&self) -> DetectorKind;

    /// New flow observed ([`FlowEvent::Started`]).
    fn on_flow_start(&mut self, _key: &K, _ts: Timestamp, _out: &mut Vec<OwnedAnomaly>) {}

    /// TCP 3-way handshake completed ([`FlowEvent::Established`]).
    fn on_flow_established(&mut self, _key: &K, _ts: Timestamp, _out: &mut Vec<OwnedAnomaly>) {}

    /// Flow ended ([`FlowEvent::Ended`]) — the natural
    /// per-connection observation (RITA's unit of analysis).
    ///
    /// `ts` is the flow's last activity: the tracker-level
    /// `Ended` carries no timestamp of its own, so the registry
    /// passes `stats.last_seen` (the driver-level adapter uses
    /// `Event::Ended.ts`, which equals it).
    fn on_flow_end(
        &mut self,
        _key: &K,
        _stats: &FlowStats,
        _history: &HistoryString,
        _l4: Option<L4Proto>,
        _ts: Timestamp,
        _out: &mut Vec<OwnedAnomaly>,
    ) {
    }

    /// Periodic live-flow snapshot ([`FlowEvent::Tick`] — only
    /// fires when `FlowTrackerConfig::flow_tick_interval` is
    /// set). Note tick stats are **cumulative**; delta-track
    /// inside the detector if you need per-interval values.
    fn on_flow_tick(
        &mut self,
        _key: &K,
        _stats: &FlowStats,
        _ts: Timestamp,
        _out: &mut Vec<OwnedAnomaly>,
    ) {
    }

    /// DNS query name observed on flow `key`. Pre-extracted
    /// `&str` (e.g. from a `DnsMessage::Query`'s first question)
    /// — feed it via [`DetectorRegistry::observe_dns`] from your
    /// DNS slot drain, resolver log, or any other name source.
    fn on_dns_query(
        &mut self,
        _key: &K,
        _qname: &str,
        _ts: Timestamp,
        _out: &mut Vec<OwnedAnomaly>,
    ) {
    }

    /// Keys currently tracked (0 for stateless detectors).
    fn tracked(&self) -> usize {
        0
    }

    /// Drop per-key state stale relative to `now` — bounds
    /// memory across key churn.
    fn evict_expired(&mut self, _now: Timestamp) {}
}

/// Heterogeneous detector set driven from one event stream.
///
/// See the [module docs](self) for the shape. Registered
/// detectors are boxed trait objects; drive them with
/// [`observe`](Self::observe) (tracker events),
/// [`observe_event`](Self::observe_event) (typed-driver
/// events), and [`observe_dns`](Self::observe_dns) (DNS query
/// names), then route the accumulated [`OwnedAnomaly`] buffer
/// to your sink.
///
/// ```
/// use flowscope::detect::{Detector, DetectorRegistry, HostPair, SrcHost};
/// use flowscope::detect::patterns::{BeaconDetector, PortScanDetector};
/// use flowscope::extract::FiveTupleKey;
///
/// let mut registry: DetectorRegistry<FiveTupleKey> = DetectorRegistry::new();
/// registry
///     .register(BeaconDetector::<HostPair>::new())
///     .register(PortScanDetector::<SrcHost>::new());
/// assert_eq!(registry.len(), 2);
///
/// // per event: registry.observe(&flow_event, &mut anomalies);
/// // per DNS query: registry.observe_dns(&key, qname, ts, &mut anomalies);
/// ```
#[must_use = "a registry does nothing until driven via observe/observe_dns"]
pub struct DetectorRegistry<K> {
    detectors: Vec<Box<dyn Detector<K>>>,
}

impl<K: KeyFields> DetectorRegistry<K> {
    /// Empty registry.
    pub fn new() -> Self {
        Self {
            detectors: Vec::new(),
        }
    }

    /// Register a detector. Chainable.
    pub fn register(&mut self, detector: impl Detector<K> + 'static) -> &mut Self {
        self.detectors.push(Box::new(detector));
        self
    }

    /// Drive every registered detector from one tracker-level
    /// event. Anomalies append to `out` — reuse the buffer
    /// across calls (`out.clear()` per drain).
    pub fn observe(&mut self, event: &FlowEvent<K>, out: &mut Vec<OwnedAnomaly>) {
        match event {
            FlowEvent::Started { key, ts, .. } => {
                for d in &mut self.detectors {
                    d.on_flow_start(key, *ts, out);
                }
            }
            FlowEvent::Established { key, ts, .. } => {
                for d in &mut self.detectors {
                    d.on_flow_established(key, *ts, out);
                }
            }
            FlowEvent::Ended {
                key,
                stats,
                history,
                l4,
                ..
            } => {
                let ts = stats.last_seen;
                for d in &mut self.detectors {
                    d.on_flow_end(key, stats, history, *l4, ts, out);
                }
            }
            FlowEvent::Tick { key, stats, ts } => {
                for d in &mut self.detectors {
                    d.on_flow_tick(key, stats, *ts, out);
                }
            }
            // Packet / StateChange / FlowAnomaly / TrackerAnomaly —
            // no detector feed (and both enums are #[non_exhaustive]).
            _ => {}
        }
    }

    /// Typed-driver adapter — same fan-out from a
    /// [`crate::driver::Event`]. Two-line integration for
    /// `Driver::track_into` pipelines.
    #[cfg(all(feature = "extractors", feature = "reassembler", feature = "session"))]
    pub fn observe_event(&mut self, event: &crate::driver::Event<K>, out: &mut Vec<OwnedAnomaly>) {
        use crate::driver::Event;
        match event {
            Event::Started { key, ts, .. } => {
                for d in &mut self.detectors {
                    d.on_flow_start(key, *ts, out);
                }
            }
            Event::Established { key, ts, .. } => {
                for d in &mut self.detectors {
                    d.on_flow_established(key, *ts, out);
                }
            }
            Event::Ended {
                key,
                stats,
                history,
                l4,
                ts,
                ..
            } => {
                for d in &mut self.detectors {
                    d.on_flow_end(key, stats, history, *l4, *ts, out);
                }
            }
            Event::Tick { key, stats, ts } => {
                for d in &mut self.detectors {
                    d.on_flow_tick(key, stats, *ts, out);
                }
            }
            _ => {}
        }
    }

    /// Feed one DNS query name (from a DNS slot drain / resolver
    /// log) to every registered detector.
    pub fn observe_dns(
        &mut self,
        key: &K,
        qname: &str,
        ts: Timestamp,
        out: &mut Vec<OwnedAnomaly>,
    ) {
        for d in &mut self.detectors {
            d.on_dns_query(key, qname, ts, out);
        }
    }

    /// Fan [`Detector::evict_expired`] out to every detector.
    pub fn evict_expired(&mut self, now: Timestamp) {
        for d in &mut self.detectors {
            d.evict_expired(now);
        }
    }

    /// Sum of every detector's tracked-key count.
    pub fn tracked(&self) -> usize {
        self.detectors.iter().map(|d| d.tracked()).sum()
    }

    /// The registered detectors' kinds, in registration order.
    pub fn kinds(&self) -> impl Iterator<Item = DetectorKind> + '_ {
        self.detectors.iter().map(|d| d.kind())
    }

    /// Number of registered detectors.
    pub fn len(&self) -> usize {
        self.detectors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.detectors.is_empty()
    }
}

impl<K: KeyFields> Default for DetectorRegistry<K> {
    fn default() -> Self {
        Self::new()
    }
}

// ─── derived aggregation keys ────────────────────────────────────

/// Source-host aggregation key — pivots per-flow events to a
/// per-source-IP detector axis (port scans, floods, exfil).
///
/// Replaces the `SrcIpKey` newtype every consumer re-declared.
/// Build from any flow key via [`Self::from_key`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SrcHost(pub IpAddr);

impl SrcHost {
    /// Derive from any [`KeyFields`] flow key; `None` when the
    /// key exposes no source IP (custom keys).
    pub fn from_key<K: KeyFields + ?Sized>(key: &K) -> Option<Self> {
        key.src_ip().map(SrcHost)
    }
}

impl KeyFields for SrcHost {
    fn src_ip(&self) -> Option<IpAddr> {
        Some(self.0)
    }
}

/// `(src, dst, dst_port)` aggregation key — the beaconing axis:
/// each beacon ping is its own 5-tuple (ephemeral source port),
/// so beacon detectors must aggregate across flows on the
/// host-pair, not the flow key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct HostPair {
    pub src: IpAddr,
    pub dst: IpAddr,
    /// Destination port, when the flow key exposes one. Kept in
    /// the key so beacons to distinct services score separately.
    pub dst_port: Option<u16>,
}

impl HostPair {
    /// Derive from any [`KeyFields`] flow key; `None` unless the
    /// key exposes both IPs.
    pub fn from_key<K: KeyFields + ?Sized>(key: &K) -> Option<Self> {
        Some(Self {
            src: key.src_ip()?,
            dst: key.dest_ip()?,
            dst_port: key.dest_port(),
        })
    }
}

impl KeyFields for HostPair {
    fn src_ip(&self) -> Option<IpAddr> {
        Some(self.src)
    }
    fn dest_ip(&self) -> Option<IpAddr> {
        Some(self.dst)
    }
    fn dest_port(&self) -> Option<u16> {
        self.dst_port
    }
}

// ─── shipped Detector impls ──────────────────────────────────────

/// Derive the port-scan "connection succeeded" signal from a
/// finished flow. TCP: the responder answered the handshake
/// (`'s'` — responder SYN[-ACK] — in the Zeek-style history);
/// an unanswered SYN or a RST refusal both read as failure.
/// Non-TCP: any responder packet counts as success.
fn flow_succeeded(history: &HistoryString, stats: &FlowStats, l4: Option<L4Proto>) -> bool {
    match l4 {
        Some(L4Proto::Tcp) => history.contains('s'),
        _ => stats.packets_responder > 0,
    }
}

impl<K: KeyFields + Send> Detector<K> for BeaconDetector<HostPair> {
    fn kind(&self) -> DetectorKind {
        DetectorKind::BeaconCv
    }

    /// One observation per finished flow, keyed by
    /// [`HostPair`]: `(ts = last activity, bytes =
    /// initiator-sent bytes)`. Emits when the gated observe
    /// (threshold + cooldown) fires. No-op for keys without
    /// both IPs.
    fn on_flow_end(
        &mut self,
        key: &K,
        stats: &FlowStats,
        _history: &HistoryString,
        _l4: Option<L4Proto>,
        ts: Timestamp,
        out: &mut Vec<OwnedAnomaly>,
    ) {
        let Some(pair) = HostPair::from_key(key) else {
            return;
        };
        if let Some(score) = self.observe_gated(pair, ts, stats.bytes_initiator) {
            out.push(score.into_anomaly(ts));
        }
    }

    fn tracked(&self) -> usize {
        BeaconDetector::tracked(self)
    }

    fn evict_expired(&mut self, now: Timestamp) {
        // One day of silence retires a host-pair's window — far
        // beyond the 24 h max beacon interval the detector scores.
        self.evict_stale(now, Duration::from_secs(24 * 60 * 60));
    }
}

impl<K: KeyFields + Send> Detector<K> for RitaBeaconDetector<HostPair> {
    fn kind(&self) -> DetectorKind {
        DetectorKind::BeaconRita
    }

    /// Same feed as the CV impl — see
    /// [`BeaconDetector`]'s `on_flow_end` docs.
    fn on_flow_end(
        &mut self,
        key: &K,
        stats: &FlowStats,
        _history: &HistoryString,
        _l4: Option<L4Proto>,
        ts: Timestamp,
        out: &mut Vec<OwnedAnomaly>,
    ) {
        let Some(pair) = HostPair::from_key(key) else {
            return;
        };
        if let Some(score) = self.observe_gated(pair, ts, stats.bytes_initiator) {
            out.push(score.into_anomaly(ts));
        }
    }

    fn tracked(&self) -> usize {
        RitaBeaconDetector::tracked(self)
    }

    fn evict_expired(&mut self, now: Timestamp) {
        self.evict_stale(now, Duration::from_secs(24 * 60 * 60));
    }
}

impl<K: KeyFields + Send> Detector<K> for PortScanDetector<SrcHost> {
    fn kind(&self) -> DetectorKind {
        DetectorKind::PortScanTrw
    }

    /// One TRW observation per finished flow, keyed by
    /// [`SrcHost`]. Success derives statelessly from the flow
    /// record (see the module-private `flow_succeeded`). Emits
    /// only on a `Scanner` verdict — TRW resets the key's state
    /// at every terminal verdict, which is natural
    /// re-alert dedup. No-op for keys without a source IP.
    fn on_flow_end(
        &mut self,
        key: &K,
        stats: &FlowStats,
        history: &HistoryString,
        l4: Option<L4Proto>,
        ts: Timestamp,
        out: &mut Vec<OwnedAnomaly>,
    ) {
        let Some(src) = SrcHost::from_key(key) else {
            return;
        };
        let success = flow_succeeded(history, stats, l4);
        let score = self.observe(src, success);
        if matches!(score.verdict, crate::detect::patterns::ScanVerdict::Scanner) {
            out.push(score.into_anomaly(ts));
        }
    }

    fn tracked(&self) -> usize {
        PortScanDetector::tracked(self)
    }
}

/// Registry adapter for the stateless [`DgaScorer`] — adds the
/// qname plumbing and alert dedup the raw scorer deliberately
/// doesn't carry.
///
/// Feeds from [`Detector::on_dns_query`]: extracts the
/// second-to-last dot-label as the registrable-ish domain (the
/// same PSL-free heuristic as `FlowRisk::from_dns` — imperfect
/// for `co.uk`-style suffixes; pre-extract with the
/// `publicsuffix` crate when that matters), scores it, and
/// emits one anomaly per `(source IP, domain)` pair — repeat
/// queries for a flagged domain are suppressed through a
/// bounded LRU.
///
/// [`DgaScorer`] itself stays public and unchanged for direct
/// scoring (`FlowRisk::from_dns`, `analysis::FlowAnalyzer`).
pub struct DgaDetector {
    scorer: DgaScorer,
    threshold: f32,
    seen: LruCache<(Option<IpAddr>, String), ()>,
}

impl DgaDetector {
    /// Default threshold (−3.5, [`DgaScorer::is_dga`]'s) and a
    /// 4 096-entry suppression LRU.
    pub fn new() -> Self {
        Self {
            scorer: DgaScorer::new(),
            threshold: -3.5,
            seen: LruCache::new(std::num::NonZeroUsize::new(4096).unwrap()),
        }
    }

    /// Bigram log-likelihood verdict threshold (more negative =
    /// stricter; see [`DgaScorer::is_dga_with_threshold`]).
    pub fn with_threshold(mut self, threshold: f32) -> Self {
        self.threshold = threshold;
        self
    }

    /// Capacity of the `(source, domain)` alert-suppression LRU
    /// (clamped to ≥ 1).
    pub fn with_suppression_capacity(mut self, capacity: usize) -> Self {
        self.seen = LruCache::new(std::num::NonZeroUsize::new(capacity.max(1)).unwrap());
        self
    }

    /// PSL-free registrable-domain heuristic: second-to-last
    /// label (`sub.evil.com` → `evil`), single label kept as-is.
    fn sld(qname: &str) -> Option<String> {
        let trimmed = qname.trim().trim_end_matches('.');
        if trimmed.is_empty() {
            return None;
        }
        let lower = trimmed.to_ascii_lowercase();
        let labels: Vec<&str> = lower.split('.').collect();
        let sld = match labels.len() {
            0 => return None,
            1 => labels[0],
            n => labels[n - 2],
        };
        if sld.is_empty() {
            None
        } else {
            Some(sld.to_string())
        }
    }
}

impl Default for DgaDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl<K: KeyFields + Send> Detector<K> for DgaDetector {
    fn kind(&self) -> DetectorKind {
        DetectorKind::Dga
    }

    fn on_dns_query(&mut self, key: &K, qname: &str, ts: Timestamp, out: &mut Vec<OwnedAnomaly>) {
        let Some(sld) = Self::sld(qname) else {
            return;
        };
        if !self.scorer.is_dga_with_threshold(&sld, self.threshold) {
            return;
        }
        let suppress_key = (key.src_ip(), sld.clone());
        if self.seen.contains(&suppress_key) {
            return;
        }
        self.seen.put(suppress_key, ());
        out.push(
            self.scorer
                .score(&sld)
                .into_anomaly(ts, Some(key as &dyn KeyFields))
                .with_observation("qname", qname.to_string())
                .with_observation("sld", sld),
        );
    }

    fn tracked(&self) -> usize {
        self.seen.len()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    struct NoIpKey;
    impl KeyFields for NoIpKey {}

    fn key_a() -> SrcHost {
        SrcHost(IpAddr::from(Ipv4Addr::new(10, 0, 0, 1)))
    }

    #[test]
    fn derived_keys_from_keyfields() {
        let pair = HostPair {
            src: IpAddr::from(Ipv4Addr::new(10, 0, 0, 1)),
            dst: IpAddr::from(Ipv4Addr::new(10, 0, 0, 2)),
            dst_port: Some(443),
        };
        // A HostPair is itself a KeyFields impl — round-trips.
        assert_eq!(HostPair::from_key(&pair), Some(pair));
        assert_eq!(SrcHost::from_key(&pair), Some(SrcHost(pair.src)));
        // Keys without IPs derive nothing.
        assert_eq!(HostPair::from_key(&NoIpKey), None);
        assert_eq!(SrcHost::from_key(&NoIpKey), None);
    }

    #[test]
    fn dga_detector_flags_and_suppresses() {
        let mut d = DgaDetector::new();
        let mut out = Vec::new();
        let key = key_a();
        <DgaDetector as Detector<SrcHost>>::on_dns_query(
            &mut d,
            &key,
            "kq3v9z7xj2wq.com",
            Timestamp::new(0, 0),
            &mut out,
        );
        assert_eq!(out.len(), 1, "DGA-shaped SLD emits");
        assert_eq!(out[0].kind, DetectorKind::Dga);
        // Same (src, domain): suppressed.
        <DgaDetector as Detector<SrcHost>>::on_dns_query(
            &mut d,
            &key,
            "www.kq3v9z7xj2wq.com",
            Timestamp::new(1, 0),
            &mut out,
        );
        assert_eq!(out.len(), 1, "repeat domain suppressed");
        // Benign domain: no emission.
        <DgaDetector as Detector<SrcHost>>::on_dns_query(
            &mut d,
            &key,
            "www.google.com",
            Timestamp::new(2, 0),
            &mut out,
        );
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn flow_succeeded_rules() {
        let mut history = HistoryString::new();
        let mut stats = FlowStats::default();
        // Unanswered TCP SYN: failure.
        history.push_str("S");
        assert!(!flow_succeeded(&history, &stats, Some(L4Proto::Tcp)));
        // RST-refused: failure.
        let mut refused = HistoryString::new();
        refused.push_str("Sr");
        assert!(!flow_succeeded(&refused, &stats, Some(L4Proto::Tcp)));
        // Responder SYN-ACK: success.
        let mut ok = HistoryString::new();
        ok.push_str("Ss");
        assert!(flow_succeeded(&ok, &stats, Some(L4Proto::Tcp)));
        // UDP: responder packets decide.
        assert!(!flow_succeeded(&history, &stats, Some(L4Proto::Udp)));
        stats.packets_responder = 1;
        assert!(flow_succeeded(&history, &stats, Some(L4Proto::Udp)));
    }
}

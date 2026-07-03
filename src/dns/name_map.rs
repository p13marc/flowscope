//! [`NameMap`] — passive-DNS-grade IP → name aggregation (issue
//! #130).
//!
//! Where [`DnsResolutionCache`](crate::dns::DnsResolutionCache)
//! stores exactly one name per `(client, target)` from A/AAAA
//! answers on a fixed construction-time TTL, `NameMap` follows the
//! Zeek/Corelight "namecache" model that passive-DNS enrichment
//! actually needs:
//!
//! - **plural, provenance-tagged names per IP** — CDNs, and the
//!   SNI-vs-DNS-vs-DHCP sources, legitimately disagree; each
//!   [`NameClaim`] carries its [`Provenance`] + first/last-seen;
//! - **answer-TTL-driven expiry** — a connection can legitimately
//!   happen within the record's own TTL of the lookup, so expiry
//!   honours the answer's TTL (+ a grace), not a global constant;
//! - **a global (client-agnostic) reverse index** — the resolving
//!   client is often not the connecting client (internal
//!   resolvers), so lookups fall back to "any name for this IP";
//! - **CNAME chain resolution + PTR reverse claims** within a
//!   single response;
//! - **`drain_new`** — a rate-limit-friendly delta feed that
//!   yields each genuinely-new mapping exactly once (Corelight's
//!   lesson: propagating every observation, not just new ones,
//!   caused packet loss).
//!
//! `DnsResolutionCache` stays shipped unchanged — this is a new
//! type alongside it, not a replacement.
//!
//! ```ignore
//! use flowscope::dns::{NameMap, Provenance};
//!
//! let mut map = NameMap::new();
//! // On every DNS response:
//! map.observe_response(client_ip, &response, now);
//! // Name a talker (global fallback):
//! for claim in map.names(target_ip, now) {
//!     println!("{target_ip} = {} (via {:?})", claim.name, claim.provenance);
//! }
//! // Propagate only new mappings, rate-limited:
//! for (ip, claim) in map.drain_new() { publish(ip, claim); }
//! ```

use std::{collections::VecDeque, net::IpAddr, num::NonZeroUsize, time::Duration};

use lru::LruCache;

use crate::{
    Timestamp,
    dns::{DnsRdata, DnsResponse},
};

/// Where a name-for-IP binding came from. Distinct sources for the
/// same IP coexist in a [`NameMap`] rather than overwriting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Provenance {
    /// DNS A answer (IPv4 forward resolution).
    DnsA,
    /// DNS AAAA answer (IPv6 forward resolution).
    DnsAaaa,
    /// Intermediate CNAME in a resolution chain.
    DnsCname,
    /// DNS PTR answer (reverse resolution).
    DnsPtr,
    /// Multicast DNS (RFC 6762).
    Mdns,
    /// TLS SNI (the client's claimed server name).
    Sni,
    /// DHCP-provided hostname.
    Dhcp,
    /// Any other source (custom feeds).
    Other,
}

impl Provenance {
    /// Stable lowercase slug for logs / metric labels.
    pub fn as_str(&self) -> &'static str {
        match self {
            Provenance::DnsA => "dns_a",
            Provenance::DnsAaaa => "dns_aaaa",
            Provenance::DnsCname => "dns_cname",
            Provenance::DnsPtr => "dns_ptr",
            Provenance::Mdns => "mdns",
            Provenance::Sni => "sni",
            Provenance::Dhcp => "dhcp",
            Provenance::Other => "other",
        }
    }
}

/// One provenance-tagged name binding for an IP.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct NameClaim {
    /// Canonical name — lowercased ASCII, no trailing dot.
    pub name: String,
    /// Where this binding came from.
    pub provenance: Provenance,
    /// The client that observed it, when known (`None` for a
    /// client-agnostic feed). Used by
    /// [`NameMap::names_for_client`].
    pub client: Option<IpAddr>,
    /// First time this `(name, provenance, client)` was seen.
    pub first_seen: Timestamp,
    /// Most recent sighting — expiry runs from here.
    pub last_seen: Timestamp,
    /// The answer record's TTL, when the source provides one.
    /// `None` falls back to the map's `default_ttl`.
    pub ttl: Option<Duration>,
}

impl NameClaim {
    /// New claim, canonicalising `name` (lowercase, strip trailing
    /// dot). `first_seen` = `last_seen` = `now`.
    pub fn new(name: impl AsRef<str>, provenance: Provenance, now: Timestamp) -> Self {
        Self {
            name: canonicalize(name.as_ref()),
            provenance,
            client: None,
            first_seen: now,
            last_seen: now,
            ttl: None,
        }
    }

    /// Set the scoping client.
    pub fn with_client(mut self, client: IpAddr) -> Self {
        self.client = Some(client);
        self
    }

    /// Set the answer TTL.
    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Dedup identity — a claim refreshes rather than duplicates
    /// when these three match.
    fn dedup_key(&self) -> (&str, Provenance, Option<IpAddr>) {
        (self.name.as_str(), self.provenance, self.client)
    }

    fn is_expired(&self, now: Timestamp, default_ttl: Duration, grace: Duration) -> bool {
        let ttl = self.ttl.unwrap_or(default_ttl) + grace;
        now.to_duration()
            .saturating_sub(self.last_seen.to_duration())
            > ttl
    }
}

/// Tuning for a [`NameMap`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct NameMapConfig {
    /// Max distinct IPs held (LRU eviction). Default 16 384.
    pub max_ips: usize,
    /// Max claims retained per IP (oldest `last_seen` dropped).
    /// Default 8.
    pub max_claims_per_ip: usize,
    /// TTL used when a claim carries none. Default 300 s.
    pub default_ttl: Duration,
    /// Grace added to every TTL before expiry (connections happen
    /// slightly after a lookup). Default 60 s.
    pub grace: Duration,
    /// Max pending `drain_new` entries before oldest are dropped.
    /// Default 4096.
    pub max_pending: usize,
}

impl Default for NameMapConfig {
    fn default() -> Self {
        Self {
            max_ips: 16_384,
            max_claims_per_ip: 8,
            default_ttl: Duration::from_secs(300),
            grace: Duration::from_secs(60),
            max_pending: 4096,
        }
    }
}

/// Passive-DNS-grade IP → name map. See the [`dns`](crate::dns)
/// module docs and [`NameMapConfig`] for tuning.
pub struct NameMap {
    inner: LruCache<IpAddr, Vec<NameClaim>>,
    default_ttl: Duration,
    grace: Duration,
    max_claims_per_ip: usize,
    /// Delta feed of genuinely-new mappings for propagation.
    pending: VecDeque<(IpAddr, NameClaim)>,
    max_pending: usize,
    pending_dropped: u64,
}

impl NameMap {
    /// New map with default config.
    pub fn new() -> Self {
        Self::with_config(NameMapConfig::default())
    }

    /// New map with explicit config. All caps are clamped to ≥ 1.
    pub fn with_config(config: NameMapConfig) -> Self {
        let cap = NonZeroUsize::new(config.max_ips.max(1)).unwrap();
        Self {
            inner: LruCache::new(cap),
            default_ttl: config.default_ttl,
            grace: config.grace,
            max_claims_per_ip: config.max_claims_per_ip.max(1),
            pending: VecDeque::new(),
            max_pending: config.max_pending.max(1),
            pending_dropped: 0,
        }
    }

    /// Ingest a [`DnsResponse`] observed by `client`.
    ///
    /// Walks the CNAME chain within this single response so the
    /// terminal A/AAAA address is claimed under the **queried**
    /// name (intermediates are also claimed under their CNAME
    /// owner with [`Provenance::DnsCname`]); the chain's minimum
    /// TTL is used. PTR answers populate reverse claims (the
    /// pointed-to name for the in-addr.arpa / ip6.arpa address).
    /// Authority / additional sections are ignored (glue-poisoning
    /// caution).
    pub fn observe_response(&mut self, client: IpAddr, response: &DnsResponse, now: Timestamp) {
        // The queried name — the label a connecting host would use.
        let queried = response
            .questions
            .first()
            .map(|q| canonicalize(&q.name))
            .unwrap_or_default();

        // CNAME edge map (owner → target), plus a running min TTL.
        // Bounded walk: at most min(answers, 12) hops (cycle-safe).
        let mut min_ttl: Option<Duration> = None;
        for answer in &response.answers {
            let ttl = Duration::from_secs(answer.ttl as u64);
            match &answer.data {
                DnsRdata::A(ip) => {
                    let chain_ttl = min_opt(min_ttl, ttl);
                    if !queried.is_empty() {
                        self.record(
                            IpAddr::V4(*ip),
                            claim_from(&queried, Provenance::DnsA, client, now, chain_ttl),
                            now,
                        );
                    }
                }
                DnsRdata::AAAA(ip) => {
                    let chain_ttl = min_opt(min_ttl, ttl);
                    if !queried.is_empty() {
                        self.record(
                            IpAddr::V6(*ip),
                            claim_from(&queried, Provenance::DnsAaaa, client, now, chain_ttl),
                            now,
                        );
                    }
                }
                DnsRdata::CNAME(target) => {
                    // Track the tightest TTL along the chain.
                    min_ttl = Some(min_opt(min_ttl, ttl));
                    let _ = target; // intermediate names handled below
                }
                DnsRdata::PTR(name) => {
                    // Reverse claim: the record owner is the
                    // in-addr.arpa / ip6.arpa label; map it back to
                    // the pointed-to name.
                    if let Some(ip) = reverse_name_to_ip(&answer.name) {
                        self.record(
                            ip,
                            claim_from(name, Provenance::DnsPtr, client, now, ttl),
                            now,
                        );
                    }
                }
                _ => {}
            }
        }
    }

    /// Ingest a claim for `ip` from a non-DNS source (SNI, DHCP,
    /// mDNS, custom). The claim's `name` is canonicalised.
    pub fn observe_claim(&mut self, ip: IpAddr, mut claim: NameClaim) {
        claim.name = canonicalize(&claim.name);
        let now = claim.last_seen;
        self.record(ip, claim, now);
    }

    /// Insert-or-refresh a claim, maintaining per-IP dedup + cap +
    /// the `pending` delta feed.
    fn record(&mut self, ip: IpAddr, claim: NameClaim, now: Timestamp) {
        let default_ttl = self.default_ttl;
        let grace = self.grace;
        let cap = self.max_claims_per_ip;

        let claims = self.inner.get_or_insert_mut(ip, Vec::new);
        // Purge expired in place so a refresh doesn't resurrect a
        // dead entry and the cap counts live claims.
        claims.retain(|c| !c.is_expired(now, default_ttl, grace));

        if let Some(existing) = claims
            .iter_mut()
            .find(|c| c.dedup_key() == claim.dedup_key())
        {
            // Refresh — silent (not pushed to the delta feed).
            existing.last_seen = now;
            if claim.ttl.is_some() {
                existing.ttl = claim.ttl;
            }
            return;
        }

        // Genuinely new binding.
        if claims.len() >= cap {
            // Drop the oldest by last_seen to stay under the cap.
            if let Some((idx, _)) = claims
                .iter()
                .enumerate()
                .min_by_key(|(_, c)| c.last_seen.to_duration())
            {
                claims.remove(idx);
            }
        }
        claims.push(claim.clone());
        self.push_pending(ip, claim);
    }

    fn push_pending(&mut self, ip: IpAddr, claim: NameClaim) {
        if self.pending.len() >= self.max_pending {
            self.pending.pop_front();
            self.pending_dropped += 1;
        }
        self.pending.push_back((ip, claim));
    }

    /// All live names for `ip` (global — any client). Purges
    /// expired claims in place, so takes `&mut self`; LRU-promotes.
    pub fn names(&mut self, ip: IpAddr, now: Timestamp) -> &[NameClaim] {
        let default_ttl = self.default_ttl;
        let grace = self.grace;
        if let Some(claims) = self.inner.get_mut(&ip) {
            claims.retain(|c| !c.is_expired(now, default_ttl, grace));
            claims.as_slice()
        } else {
            &[]
        }
    }

    /// `&self` companion to [`Self::names`] — does not purge or
    /// promote. May include not-yet-swept expired claims; filter
    /// with [`NameClaim`] fields if that matters.
    pub fn peek_names(&self, ip: IpAddr, now: Timestamp) -> Vec<&NameClaim> {
        match self.inner.peek(&ip) {
            Some(claims) => claims
                .iter()
                .filter(|c| !c.is_expired(now, self.default_ttl, self.grace))
                .collect(),
            None => Vec::new(),
        }
    }

    /// Live names for `ip` scoped to `client` first, falling back
    /// to client-agnostic claims. Returns an iterator (a
    /// deliberate deviation from the issue's `&[NameClaim]` sketch:
    /// client filtering can't return a contiguous slice without a
    /// per-query allocation). Non-promoting (`&self`).
    pub fn names_for_client(
        &self,
        client: IpAddr,
        ip: IpAddr,
        now: Timestamp,
    ) -> impl Iterator<Item = &NameClaim> + '_ {
        self.inner
            .peek(&ip)
            .into_iter()
            .flatten()
            .filter(move |c| !c.is_expired(now, self.default_ttl, self.grace))
            .filter(move |c| c.client == Some(client) || c.client.is_none())
    }

    /// Drain the delta feed of genuinely-new mappings observed
    /// since the last drain. Each new `(ip, claim)` appears exactly
    /// once; refreshes of existing bindings are not included.
    pub fn drain_new(&mut self) -> Vec<(IpAddr, NameClaim)> {
        self.pending.drain(..).collect()
    }

    /// Drain into a caller-owned buffer (reuse across calls to
    /// avoid per-drain allocation). Returns the count moved.
    pub fn drain_new_into(&mut self, out: &mut Vec<(IpAddr, NameClaim)>) -> usize {
        let n = self.pending.len();
        out.extend(self.pending.drain(..));
        n
    }

    /// How many pending delta entries were dropped due to
    /// `max_pending` back-pressure (a non-zero value means the
    /// consumer isn't draining fast enough).
    pub fn pending_dropped(&self) -> u64 {
        self.pending_dropped
    }

    /// Drop all expired claims across every IP (and any IP left
    /// with none). Returns the number of claims removed.
    pub fn sweep(&mut self, now: Timestamp) -> usize {
        let default_ttl = self.default_ttl;
        let grace = self.grace;
        let mut removed = 0;
        let mut empty_ips: Vec<IpAddr> = Vec::new();
        for (ip, claims) in self.inner.iter_mut() {
            let before = claims.len();
            claims.retain(|c| !c.is_expired(now, default_ttl, grace));
            removed += before - claims.len();
            if claims.is_empty() {
                empty_ips.push(*ip);
            }
        }
        for ip in empty_ips {
            self.inner.pop(&ip);
        }
        removed
    }

    /// Distinct IPs currently tracked.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// `true` if no IPs are tracked.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl Default for NameMap {
    fn default() -> Self {
        Self::new()
    }
}

fn claim_from(
    name: &str,
    provenance: Provenance,
    client: IpAddr,
    now: Timestamp,
    ttl: Duration,
) -> NameClaim {
    NameClaim::new(name, provenance, now)
        .with_client(client)
        .with_ttl(ttl)
}

fn min_opt(current: Option<Duration>, candidate: Duration) -> Duration {
    match current {
        Some(c) => c.min(candidate),
        None => candidate,
    }
}

/// Lowercase ASCII, strip a single trailing dot (RFC 1035 §2.3.1).
fn canonicalize(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Parse an `in-addr.arpa` / `ip6.arpa` PTR owner name back to the
/// IP it points at. Returns `None` for malformed labels.
fn reverse_name_to_ip(name: &str) -> Option<IpAddr> {
    let lower = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some(rest) = lower.strip_suffix(".in-addr.arpa") {
        // Four reversed decimal octets.
        let octets: Vec<&str> = rest.split('.').collect();
        if octets.len() != 4 {
            return None;
        }
        let mut b = [0u8; 4];
        for (i, o) in octets.iter().enumerate() {
            b[3 - i] = o.parse().ok()?;
        }
        return Some(IpAddr::from(b));
    }
    if let Some(rest) = lower.strip_suffix(".ip6.arpa") {
        // 32 reversed nibbles.
        let nibbles: Vec<&str> = rest.split('.').collect();
        if nibbles.len() != 32 {
            return None;
        }
        let mut b = [0u8; 16];
        for (i, nib) in nibbles.iter().enumerate() {
            if nib.len() != 1 {
                return None;
            }
            let v = u8::from_str_radix(nib, 16).ok()?;
            // Nibble 0 is the lowest-order of the last byte.
            let byte = 15 - i / 2;
            if i % 2 == 0 {
                b[byte] |= v; // low nibble
            } else {
                b[byte] |= v << 4; // high nibble
            }
        }
        return Some(IpAddr::from(b));
    }
    None
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::dns::{DnsFlags, DnsQuestion, DnsRcode, DnsRecord, DnsResponse};

    fn t(secs: u32) -> Timestamp {
        Timestamp::new(secs, 0)
    }

    fn client() -> IpAddr {
        IpAddr::from(Ipv4Addr::new(10, 0, 0, 1))
    }

    fn response(qname: &str, answers: Vec<DnsRecord>) -> DnsResponse {
        DnsResponse::new(
            1,
            DnsFlags(0x8180),
            vec![DnsQuestion::new(qname, 1, 1)],
            answers,
            vec![],
            vec![],
            DnsRcode::NoError,
            t(0),
            None,
        )
    }

    fn a_record(name: &str, ip: Ipv4Addr, ttl: u32) -> DnsRecord {
        DnsRecord::new(name, 1, 1, ttl, DnsRdata::A(ip))
    }

    #[test]
    fn plural_names_with_distinct_provenance_coexist() {
        let mut m = NameMap::new();
        let ip = IpAddr::from(Ipv4Addr::new(93, 184, 216, 34));
        m.observe_response(
            client(),
            &response(
                "example.com",
                vec![a_record(
                    "example.com",
                    Ipv4Addr::new(93, 184, 216, 34),
                    300,
                )],
            ),
            t(0),
        );
        m.observe_claim(
            ip,
            NameClaim::new("example.org", Provenance::Sni, t(1)).with_client(client()),
        );
        let names = m.names(ip, t(2));
        assert_eq!(names.len(), 2);
        let provs: Vec<_> = names.iter().map(|c| c.provenance).collect();
        assert!(provs.contains(&Provenance::DnsA));
        assert!(provs.contains(&Provenance::Sni));
    }

    #[test]
    fn answer_ttl_drives_expiry() {
        let mut m = NameMap::new(); // grace 60 s
        let ip = IpAddr::from(Ipv4Addr::new(1, 2, 3, 4));
        m.observe_response(
            client(),
            &response(
                "short.example",
                vec![a_record("short.example", Ipv4Addr::new(1, 2, 3, 4), 30)],
            ),
            t(0),
        );
        // Within TTL(30)+grace(60)=90 → live.
        assert_eq!(m.names(ip, t(80)).len(), 1);
        // Past 90 → expired.
        assert_eq!(m.names(ip, t(100)).len(), 0);
    }

    #[test]
    fn cname_chain_binds_queried_name_to_terminal_ip() {
        let mut m = NameMap::new();
        // www.example.com CNAME cdn.example.net A 1.2.3.4
        let answers = vec![
            DnsRecord::new(
                "www.example.com",
                5,
                1,
                120,
                DnsRdata::CNAME("cdn.example.net".into()),
            ),
            a_record("cdn.example.net", Ipv4Addr::new(1, 2, 3, 4), 60),
        ];
        m.observe_response(client(), &response("www.example.com", answers), t(0));
        let ip = IpAddr::from(Ipv4Addr::new(1, 2, 3, 4));
        let names = m.names(ip, t(1));
        assert_eq!(names.len(), 1);
        // Bound under the QUERIED name, not the CNAME target.
        assert_eq!(names[0].name, "www.example.com");
        // Chain min TTL (60), not the CNAME's 120.
        assert_eq!(names[0].ttl, Some(Duration::from_secs(60)));
    }

    #[test]
    fn ptr_populates_reverse_claim_v4() {
        let mut m = NameMap::new();
        let answers = vec![DnsRecord::new(
            "4.3.2.1.in-addr.arpa",
            12,
            1,
            300,
            DnsRdata::PTR("host.example".into()),
        )];
        m.observe_response(client(), &response("4.3.2.1.in-addr.arpa", answers), t(0));
        let ip = IpAddr::from(Ipv4Addr::new(1, 2, 3, 4));
        let names = m.names(ip, t(1));
        assert_eq!(names.len(), 1);
        assert_eq!(names[0].name, "host.example");
        assert_eq!(names[0].provenance, Provenance::DnsPtr);
    }

    #[test]
    fn ptr_reverse_claim_v6() {
        // ::1 reverse name: nibbles are lowest-order-first, so the
        // "1" nibble leads, then 31 zero nibbles, then ip6.arpa.
        let ptr_name = {
            let mut s = String::from("1.");
            for _ in 0..31 {
                s.push_str("0.");
            }
            s.push_str("ip6.arpa");
            s
        };
        let ip = reverse_name_to_ip(&ptr_name).expect("v6 reverse parses");
        assert_eq!(ip, IpAddr::from(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn drain_new_yields_each_claim_exactly_once() {
        let mut m = NameMap::new();
        let ip = IpAddr::from(Ipv4Addr::new(1, 2, 3, 4));
        m.observe_response(
            client(),
            &response(
                "a.example",
                vec![a_record("a.example", Ipv4Addr::new(1, 2, 3, 4), 300)],
            ),
            t(0),
        );
        let first = m.drain_new();
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].0, ip);
        // Re-observe same binding — a refresh, not a new mapping.
        m.observe_response(
            client(),
            &response(
                "a.example",
                vec![a_record("a.example", Ipv4Addr::new(1, 2, 3, 4), 300)],
            ),
            t(10),
        );
        assert!(m.drain_new().is_empty(), "refresh is not a new mapping");
    }

    #[test]
    fn client_scoping_prefers_and_falls_back() {
        let mut m = NameMap::new();
        let ip = IpAddr::from(Ipv4Addr::new(1, 2, 3, 4));
        let c1 = IpAddr::from(Ipv4Addr::new(10, 0, 0, 1));
        let c2 = IpAddr::from(Ipv4Addr::new(10, 0, 0, 2));
        // Client-scoped claim from c1.
        m.observe_claim(
            ip,
            NameClaim::new("c1.example", Provenance::Sni, t(0)).with_client(c1),
        );
        // Client-agnostic claim (no client).
        m.observe_claim(
            ip,
            NameClaim::new("global.example", Provenance::Other, t(0)),
        );
        // c1 sees its own + the global.
        let c1_names: Vec<_> = m
            .names_for_client(c1, ip, t(1))
            .map(|c| c.name.clone())
            .collect();
        assert!(c1_names.contains(&"c1.example".to_string()));
        assert!(c1_names.contains(&"global.example".to_string()));
        // c2 sees only the global (not c1's client-scoped claim).
        let c2_names: Vec<_> = m
            .names_for_client(c2, ip, t(1))
            .map(|c| c.name.clone())
            .collect();
        assert_eq!(c2_names, vec!["global.example".to_string()]);
    }

    #[test]
    fn canonicalization_dedups() {
        let mut m = NameMap::new();
        let ip = IpAddr::from(Ipv4Addr::new(1, 2, 3, 4));
        m.observe_claim(ip, NameClaim::new("Example.COM.", Provenance::Sni, t(0)));
        m.observe_claim(ip, NameClaim::new("example.com", Provenance::Sni, t(1)));
        // Same canonical name+provenance+client → one claim.
        assert_eq!(m.names(ip, t(2)).len(), 1);
        assert_eq!(m.names(ip, t(2))[0].name, "example.com");
    }

    #[test]
    fn per_ip_cap_bounds_claims() {
        let mut m = NameMap::with_config(NameMapConfig {
            max_claims_per_ip: 3,
            ..NameMapConfig::default()
        });
        let ip = IpAddr::from(Ipv4Addr::new(1, 2, 3, 4));
        for i in 0..10 {
            m.observe_claim(
                ip,
                NameClaim::new(format!("n{i}.example"), Provenance::Other, t(i)),
            );
        }
        assert!(m.names(ip, t(11)).len() <= 3);
    }

    #[test]
    fn pending_overflow_drops_oldest() {
        let mut m = NameMap::with_config(NameMapConfig {
            max_pending: 4,
            ..NameMapConfig::default()
        });
        for i in 0..10u32 {
            let ip = IpAddr::from(Ipv4Addr::new(1, 2, 3, i as u8));
            m.observe_claim(ip, NameClaim::new("x.example", Provenance::Other, t(i)));
        }
        assert!(m.pending_dropped() >= 6);
        assert!(m.drain_new().len() <= 4);
    }

    #[test]
    fn cdn_heavy_stays_bounded() {
        let mut m = NameMap::with_config(NameMapConfig {
            max_ips: 100,
            max_claims_per_ip: 4,
            ..NameMapConfig::default()
        });
        // 1000 distinct IPs, several names each.
        for i in 0..1000u32 {
            let ip = IpAddr::from(Ipv4Addr::from(i.to_be_bytes()));
            for j in 0..6 {
                m.observe_claim(
                    ip,
                    NameClaim::new(format!("n{j}.cdn.example"), Provenance::Other, t(i)),
                );
            }
        }
        assert!(m.len() <= 100, "IP cap holds");
    }

    #[test]
    fn sweep_drops_expired() {
        let mut m = NameMap::new();
        m.observe_response(
            client(),
            &response(
                "s.example",
                vec![a_record("s.example", Ipv4Addr::new(1, 2, 3, 4), 10)],
            ),
            t(0),
        );
        assert_eq!(m.len(), 1);
        // Past TTL(10)+grace(60).
        let removed = m.sweep(t(100));
        assert_eq!(removed, 1);
        assert_eq!(m.len(), 0);
    }
}

//! [`IocSet`] — typed threat-intel indicator membership.
//!
//! A pure, bounded, no-async membership set for the indicator
//! types flowscope already produces: IPs (from flow keys), domains
//! (DNS / TLS SNI), URLs (HTTP), file hashes (from
//! [`crate::detect::file`]), and TLS fingerprints (`ja3` / `ja4`).
//! It answers "is this value on my watch-list?" with an optional
//! per-entry **reputation** score, modelled on Zeek's Intel
//! framework and Suricata's `dataset` / `datarep`.
//!
//! Domains match **subdomain-aware** (Zeek `Intel::DOMAIN`
//! semantics): an entry `evil.com` matches `a.b.evil.com`. All
//! other kinds are exact-match (case-insensitive for hashes and
//! fingerprints; verbatim for URLs).
//!
//! Memory is bounded by [`IocSet::with_capacity`]: once full,
//! further inserts are dropped (and reported via the `bool`
//! return) rather than growing without limit — the project's
//! bounded-memory rule.
//!
//! Issue #72 (child of #67).

use std::collections::HashMap;
use std::io::BufRead;
use std::net::IpAddr;

/// The kind of a threat-intel indicator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum IocKind {
    /// IPv4 address.
    Ipv4,
    /// IPv6 address.
    Ipv6,
    /// DNS domain (subdomain-aware match).
    Domain,
    /// URL (exact match).
    Url,
    /// SHA-256 file hash (hex, case-insensitive).
    Sha256,
    /// MD5 file hash (hex, case-insensitive).
    Md5,
    /// JA3 TLS client fingerprint (case-insensitive).
    Ja3,
    /// JA4 TLS client fingerprint (case-insensitive).
    Ja4,
}

impl IocKind {
    /// Stable lowercase slug (for metric labels / logs).
    pub fn as_str(&self) -> &'static str {
        match self {
            IocKind::Ipv4 => "ipv4",
            IocKind::Ipv6 => "ipv6",
            IocKind::Domain => "domain",
            IocKind::Url => "url",
            IocKind::Sha256 => "sha256",
            IocKind::Md5 => "md5",
            IocKind::Ja3 => "ja3",
            IocKind::Ja4 => "ja4",
        }
    }
}

/// A successful indicator lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct IocMatch {
    /// Which indicator kind matched.
    pub kind: IocKind,
    /// The stored indicator value that matched (for domains this
    /// is the watch-list suffix, not the queried FQDN).
    pub value: String,
    /// Optional reputation score (Suricata `datarep`-style). `None`
    /// for pure-membership entries.
    pub reputation: Option<i32>,
    /// Optional feed / category label the entry came from.
    pub source: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct Entry {
    reputation: Option<i32>,
    source: Option<String>,
}

/// Bounded typed threat-intel membership set.
#[derive(Debug, Clone)]
pub struct IocSet {
    max_entries: usize,
    len: usize,
    ips: HashMap<IpAddr, Entry>,
    /// Lowercased, trailing-dot-stripped registered domains.
    domains: HashMap<String, Entry>,
    /// `(kind, normalized value)` for url / sha256 / md5 / ja3 / ja4.
    strings: HashMap<(IocKind, String), Entry>,
}

impl Default for IocSet {
    fn default() -> Self {
        Self::new()
    }
}

impl IocSet {
    /// Unbounded set (cap = `usize::MAX`). Prefer
    /// [`Self::with_capacity`] in production.
    pub fn new() -> Self {
        Self::with_capacity(usize::MAX)
    }

    /// Set bounded to `max_entries` total indicators across all
    /// kinds. Inserts past the cap are dropped.
    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            max_entries,
            len: 0,
            ips: HashMap::new(),
            domains: HashMap::new(),
            strings: HashMap::new(),
        }
    }

    /// Total number of stored indicators.
    pub fn len(&self) -> usize {
        self.len
    }

    /// `true` if no indicators are stored.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn at_capacity(&self) -> bool {
        self.len >= self.max_entries
    }

    /// Insert an indicator with optional reputation + source.
    ///
    /// Returns `true` if stored, `false` if the value was invalid
    /// for its kind (e.g. an unparseable IP) or the set is full.
    /// Re-inserting an existing value updates its reputation/source
    /// and does not count against the cap.
    pub fn insert(
        &mut self,
        kind: IocKind,
        value: &str,
        reputation: Option<i32>,
        source: Option<&str>,
    ) -> bool {
        let entry = Entry {
            reputation,
            source: source.map(|s| s.to_owned()),
        };
        match kind {
            IocKind::Ipv4 | IocKind::Ipv6 => {
                let Ok(ip) = value.trim().parse::<IpAddr>() else {
                    return false;
                };
                // Guard kind/family agreement.
                let matches_kind = matches!(
                    (kind, ip),
                    (IocKind::Ipv4, IpAddr::V4(_)) | (IocKind::Ipv6, IpAddr::V6(_))
                );
                if !matches_kind {
                    return false;
                }
                self.insert_into_ips(ip, entry)
            }
            IocKind::Domain => {
                let norm = normalize_domain(value);
                if norm.is_empty() {
                    return false;
                }
                if !self.domains.contains_key(&norm) && self.at_capacity() {
                    return false;
                }
                if self.domains.insert(norm, entry).is_none() {
                    self.len += 1;
                }
                true
            }
            _ => {
                let norm = normalize_value(kind, value);
                if norm.is_empty() {
                    return false;
                }
                let k = (kind, norm);
                if !self.strings.contains_key(&k) && self.at_capacity() {
                    return false;
                }
                if self.strings.insert(k, entry).is_none() {
                    self.len += 1;
                }
                true
            }
        }
    }

    fn insert_into_ips(&mut self, ip: IpAddr, entry: Entry) -> bool {
        if !self.ips.contains_key(&ip) && self.at_capacity() {
            return false;
        }
        if self.ips.insert(ip, entry).is_none() {
            self.len += 1;
        }
        true
    }

    /// Look up an IP indicator.
    pub fn contains_ip(&self, ip: IpAddr) -> Option<IocMatch> {
        let entry = self.ips.get(&ip)?;
        let kind = match ip {
            IpAddr::V4(_) => IocKind::Ipv4,
            IpAddr::V6(_) => IocKind::Ipv6,
        };
        Some(self.to_match(kind, ip.to_string(), entry))
    }

    /// Look up a domain **subdomain-aware**: `a.b.evil.com`
    /// matches a stored `evil.com`. Returns the most specific
    /// (longest) matching suffix.
    pub fn contains_domain(&self, fqdn: &str) -> Option<IocMatch> {
        let norm = normalize_domain(fqdn);
        if norm.is_empty() || self.domains.is_empty() {
            return None;
        }
        // Walk suffixes from most specific (full fqdn) to least.
        let mut start = 0usize;
        loop {
            let suffix = &norm[start..];
            if let Some(entry) = self.domains.get(suffix) {
                return Some(self.to_match(IocKind::Domain, suffix.to_owned(), entry));
            }
            start += norm[start..].find('.')? + 1;
        }
    }

    /// Look up an exact-match indicator (URL / hash / fingerprint).
    /// For `Ipv4` / `Ipv6` / `Domain` use the dedicated methods.
    pub fn contains(&self, kind: IocKind, value: &str) -> Option<IocMatch> {
        match kind {
            IocKind::Ipv4 | IocKind::Ipv6 => value.parse().ok().and_then(|ip| self.contains_ip(ip)),
            IocKind::Domain => self.contains_domain(value),
            _ => {
                let norm = normalize_value(kind, value);
                let entry = self.strings.get(&(kind, norm.clone()))?;
                Some(self.to_match(kind, norm, entry))
            }
        }
    }

    /// `true` if `value` is present **and** its reputation exceeds
    /// `threshold` (Suricata `datarep` `> N`). Entries with no
    /// reputation never match a threshold query.
    pub fn matches_over(&self, kind: IocKind, value: &str, threshold: i32) -> bool {
        let m = match kind {
            IocKind::Domain => self.contains_domain(value),
            _ => self.contains(kind, value),
        };
        m.and_then(|m| m.reputation).is_some_and(|r| r > threshold)
    }

    /// Load indicators from a feed: one per line, `value`,
    /// `value,reputation`, or `value,reputation,source`. Blank
    /// lines and lines starting with `#` are skipped; malformed
    /// lines are skipped (not an error). Returns the count stored.
    pub fn load_feed<R: BufRead>(&mut self, kind: IocKind, reader: R) -> std::io::Result<usize> {
        let mut stored = 0;
        for line in reader.lines() {
            let line = line?;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut parts = line.splitn(3, ',');
            let value = parts.next().unwrap_or("").trim();
            if value.is_empty() {
                continue;
            }
            let reputation = parts.next().and_then(|s| s.trim().parse::<i32>().ok());
            let source = parts.next().map(|s| s.trim()).filter(|s| !s.is_empty());
            if self.insert(kind, value, reputation, source) {
                stored += 1;
            }
        }
        Ok(stored)
    }

    fn to_match(&self, kind: IocKind, value: String, entry: &Entry) -> IocMatch {
        IocMatch {
            kind,
            value,
            reputation: entry.reputation,
            source: entry.source.clone(),
        }
    }
}

// ── Adapter: check a parsed TLS handshake against the set ──────

#[cfg(feature = "tls")]
impl IocSet {
    /// Check every threat-intel-relevant field of a TLS handshake
    /// against this set in one call: the SNI (subdomain-aware
    /// domain match) and the JA3 / JA4 client fingerprints.
    /// Returns every hit (possibly empty), most-specific first per
    /// field. Pure; allocates only the result vec.
    ///
    /// The missing "verb" that lets a consumer screen TLS traffic
    /// against an intel feed without hand-rolling the three
    /// per-field lookups (#83).
    pub fn check_tls(&self, hs: &crate::tls::TlsHandshake) -> Vec<IocMatch> {
        let mut hits = Vec::new();
        if let Some(sni) = hs.sni.as_deref()
            && let Some(m) = self.contains_domain(sni)
        {
            hits.push(m);
        }
        if let Some(ja3) = hs.ja3.as_deref()
            && let Some(m) = self.contains(IocKind::Ja3, ja3)
        {
            hits.push(m);
        }
        if let Some(ja4) = hs.ja4.as_deref()
            && let Some(m) = self.contains(IocKind::Ja4, ja4)
        {
            hits.push(m);
        }
        hits
    }
}

/// Lowercase, strip a single trailing dot, trim. Empty if blank.
fn normalize_domain(d: &str) -> String {
    d.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Hashes / fingerprints are case-insensitive; URLs verbatim.
fn normalize_value(kind: IocKind, v: &str) -> String {
    match kind {
        IocKind::Sha256 | IocKind::Md5 | IocKind::Ja3 | IocKind::Ja4 => {
            v.trim().to_ascii_lowercase()
        }
        _ => v.trim().to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_membership() {
        let mut s = IocSet::new();
        assert!(s.insert(IocKind::Ipv4, "1.2.3.4", Some(80), Some("feed-a")));
        let m = s.contains_ip("1.2.3.4".parse().unwrap()).unwrap();
        assert_eq!(m.kind, IocKind::Ipv4);
        assert_eq!(m.reputation, Some(80));
        assert_eq!(m.source.as_deref(), Some("feed-a"));
        assert!(s.contains_ip("5.6.7.8".parse().unwrap()).is_none());
    }

    #[test]
    fn ip_kind_family_mismatch_rejected() {
        let mut s = IocSet::new();
        assert!(!s.insert(IocKind::Ipv4, "::1", None, None)); // v6 under Ipv4
        assert!(!s.insert(IocKind::Ipv6, "1.2.3.4", None, None));
        assert!(!s.insert(IocKind::Ipv4, "not-an-ip", None, None));
    }

    #[test]
    fn domain_is_subdomain_aware() {
        let mut s = IocSet::new();
        s.insert(IocKind::Domain, "evil.com", Some(100), None);
        assert!(s.contains_domain("evil.com").is_some());
        assert!(s.contains_domain("a.b.evil.com").is_some());
        assert!(s.contains_domain("notevil.com").is_none());
        assert!(s.contains_domain("evil.com.").is_some()); // trailing dot
        assert!(s.contains_domain("EVIL.COM").is_some()); // case
    }

    #[test]
    fn domain_returns_most_specific_suffix() {
        let mut s = IocSet::new();
        s.insert(IocKind::Domain, "evil.com", Some(1), None);
        s.insert(IocKind::Domain, "bad.evil.com", Some(2), None);
        let m = s.contains_domain("x.bad.evil.com").unwrap();
        assert_eq!(m.value, "bad.evil.com");
        assert_eq!(m.reputation, Some(2));
    }

    #[test]
    fn hash_and_fingerprint_case_insensitive() {
        let mut s = IocSet::new();
        s.insert(IocKind::Sha256, "ABCdef123", None, None);
        assert!(s.contains(IocKind::Sha256, "abcDEF123").is_some());
        s.insert(IocKind::Ja4, "T13D1516H2_X", None, None);
        assert!(s.contains(IocKind::Ja4, "t13d1516h2_x").is_some());
    }

    #[test]
    fn matches_over_threshold() {
        let mut s = IocSet::new();
        s.insert(IocKind::Domain, "evil.com", Some(75), None);
        s.insert(IocKind::Domain, "meh.com", None, None);
        assert!(s.matches_over(IocKind::Domain, "x.evil.com", 50));
        assert!(!s.matches_over(IocKind::Domain, "x.evil.com", 80));
        assert!(!s.matches_over(IocKind::Domain, "meh.com", 0)); // no reputation
    }

    #[test]
    fn capacity_is_bounded() {
        let mut s = IocSet::with_capacity(2);
        assert!(s.insert(IocKind::Ipv4, "1.1.1.1", None, None));
        assert!(s.insert(IocKind::Ipv4, "2.2.2.2", None, None));
        assert!(!s.insert(IocKind::Ipv4, "3.3.3.3", None, None)); // full
        assert_eq!(s.len(), 2);
        // Updating an existing entry still works at capacity.
        assert!(s.insert(IocKind::Ipv4, "1.1.1.1", Some(9), None));
        assert_eq!(s.len(), 2);
        assert_eq!(
            s.contains_ip("1.1.1.1".parse().unwrap())
                .unwrap()
                .reputation,
            Some(9)
        );
    }

    #[cfg(feature = "tls")]
    #[test]
    fn check_tls_screens_sni_ja3_ja4() {
        use crate::tls::TlsHandshake;

        let mut s = IocSet::new();
        s.insert(IocKind::Domain, "evil.com", Some(90), Some("intel"));
        s.insert(
            IocKind::Ja4,
            "t13d1516h2_8daaf6152771_b186095e22b6",
            None,
            None,
        );

        let hs = TlsHandshake {
            sni: Some("cdn.evil.com".to_string()),
            ja3: Some("769,4-5-10".to_string()), // not on the list
            ja4: Some("t13d1516h2_8daaf6152771_b186095e22b6".to_string()),
            ..Default::default()
        };
        let hits = s.check_tls(&hs);
        assert_eq!(hits.len(), 2, "SNI + JA4 should hit, JA3 should not");
        assert!(
            hits.iter()
                .any(|m| m.kind == IocKind::Domain && m.value == "evil.com")
        );
        assert!(hits.iter().any(|m| m.kind == IocKind::Ja4));

        // A clean handshake yields no hits.
        let clean = TlsHandshake {
            sni: Some("good.example".to_string()),
            ..Default::default()
        };
        assert!(s.check_tls(&clean).is_empty());
    }

    #[test]
    fn load_feed_parses_variants() {
        let feed = "\
# a comment
1.2.3.4
5.6.7.8,90
9.9.9.9,42,abuse-ch

bad,line,with,too,many → still takes first 3 fields as value,rep,source
";
        let mut s = IocSet::new();
        let n = s.load_feed(IocKind::Ipv4, feed.as_bytes()).unwrap();
        // 3 valid IPs; the "bad" line's value isn't an IP → skipped.
        assert_eq!(n, 3);
        assert_eq!(
            s.contains_ip("9.9.9.9".parse().unwrap())
                .unwrap()
                .source
                .as_deref(),
            Some("abuse-ch")
        );
        assert_eq!(
            s.contains_ip("5.6.7.8".parse().unwrap())
                .unwrap()
                .reputation,
            Some(90)
        );
    }
}

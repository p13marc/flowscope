//! [`FlowRisk`] — an nDPI-style flow-risk taxonomy.
//!
//! A bitset of risk flags plus an aggregate severity and numeric
//! score, modelled on [ntop nDPI's flow-risk
//! framework](https://www.ntop.org/guides/nDPI/flow_risks.html)
//! — a **native re-implementation of the model**, not an FFI
//! binding. Each flag is computed from fields flowscope has already
//! parsed (TLS handshake, DNS qname, cleartext-cred parsers, flow
//! key), so a consumer ORs in the flags it can prove and reads back
//! a severity/score.
//!
//! Philosophy (shared with the rest of `detect`): emit
//! *features/scores*, not verdicts. `FlowRisk` tells you "this flow
//! has a self-signed cert and a DGA-looking qname, aggregate score
//! 150, max severity High" — the policy decision stays app-side.
//!
//! ```
//! use flowscope::detect::{FlowRisk, RiskSeverity};
//!
//! let mut risk = FlowRisk::empty();
//! risk |= FlowRisk::TLS_SELF_SIGNED;       // from your TLS parse
//! risk |= FlowRisk::DGA_DOMAIN;            // from DgaScorer
//!
//! assert_eq!(risk.max_severity(), Some(RiskSeverity::High));
//! assert_eq!(risk.score(), 150);           // 50 + 100
//! assert!(risk.as_slugs().any(|s| s == "dga_domain"));
//! ```
//!
//! Issue #73 (child of #67).

bitflags::bitflags! {
    /// Set of risk indicators observed on a flow. Additive — new
    /// flags may be added in minor releases (treat the value as
    /// opaque bits + the accessor methods, not an exhaustive match).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct FlowRisk: u64 {
        /// A known L7 protocol on a non-standard port.
        const KNOWN_PROTO_NONSTD_PORT = 1 << 0;
        /// The port and the detected protocol disagree.
        const PORT_PROTO_MISMATCH     = 1 << 1;
        /// TLS server presented a self-signed certificate.
        const TLS_SELF_SIGNED         = 1 << 2;
        /// TLS certificate is expired or not yet valid.
        const TLS_EXPIRED_CERT        = 1 << 3;
        /// TLS negotiated a weak/deprecated cipher suite.
        const TLS_WEAK_CIPHER         = 1 << 4;
        /// TLS version below 1.2 (obsolete).
        const TLS_OBSOLETE_VERSION    = 1 << 5;
        /// TLS SNI does not match the resolved DNS name for the dst.
        const SNI_DNS_MISMATCH        = 1 << 6;
        /// Domain looks algorithmically generated (DGA).
        const DGA_DOMAIN              = 1 << 7;
        /// Credentials observed in cleartext (FTP/HTTP/SMTP/SNMP/…).
        const CLEARTEXT_CREDENTIALS   = 1 << 8;
        /// Obsolete/insecure protocol in use (Telnet, SMBv1, …).
        const OBSOLETE_PROTOCOL       = 1 << 9;
        /// A JA3/JA4 fingerprint matched a threat-intel watch-list.
        const SUSPICIOUS_JA4          = 1 << 10;
        /// A binary/executable transfer was observed.
        const BINARY_TRANSFER         = 1 << 11;
        /// Punycode / mixed-script (IDN homograph) domain.
        const PUNYCODE_IDN            = 1 << 12;
        /// Malformed packet / parser integrity anomaly.
        const MALFORMED_PACKET        = 1 << 13;
    }
}

/// Severity tier for a risk flag — the nDPI ladder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum RiskSeverity {
    /// Informational / low concern.
    Low,
    /// Notable; worth a dashboard.
    Medium,
    /// Likely malicious / strong signal.
    High,
    /// Critical — near-certain compromise indicator.
    Severe,
}

impl RiskSeverity {
    /// Stable lowercase slug.
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskSeverity::Low => "low",
            RiskSeverity::Medium => "medium",
            RiskSeverity::High => "high",
            RiskSeverity::Severe => "severe",
        }
    }
}

impl FlowRisk {
    /// Per-flag attributes: (slug, severity, score). Scores follow
    /// nDPI's weighting convention (low ≈ 10, medium ≈ 50, high ≈
    /// 100, severe ≈ 250). `self` must be a single flag.
    fn attrs(self) -> (&'static str, RiskSeverity, u16) {
        use RiskSeverity::*;
        match self {
            FlowRisk::KNOWN_PROTO_NONSTD_PORT => ("known_proto_nonstd_port", Low, 10),
            FlowRisk::PORT_PROTO_MISMATCH => ("port_proto_mismatch", Medium, 50),
            FlowRisk::TLS_SELF_SIGNED => ("tls_self_signed", Medium, 50),
            FlowRisk::TLS_EXPIRED_CERT => ("tls_expired_cert", Medium, 50),
            FlowRisk::TLS_WEAK_CIPHER => ("tls_weak_cipher", Medium, 60),
            FlowRisk::TLS_OBSOLETE_VERSION => ("tls_obsolete_version", Medium, 50),
            FlowRisk::SNI_DNS_MISMATCH => ("sni_dns_mismatch", Medium, 50),
            FlowRisk::DGA_DOMAIN => ("dga_domain", High, 100),
            FlowRisk::CLEARTEXT_CREDENTIALS => ("cleartext_credentials", High, 100),
            FlowRisk::OBSOLETE_PROTOCOL => ("obsolete_protocol", Medium, 50),
            FlowRisk::SUSPICIOUS_JA4 => ("suspicious_ja4", High, 100),
            FlowRisk::BINARY_TRANSFER => ("binary_transfer", Medium, 60),
            FlowRisk::PUNYCODE_IDN => ("punycode_idn", Low, 10),
            FlowRisk::MALFORMED_PACKET => ("malformed_packet", Low, 10),
            // Multi-bit / unknown — neutral.
            _ => ("unknown", Low, 0),
        }
    }

    /// Stable lowercase slug for a **single** flag (e.g. for metric
    /// labels). Returns `"unknown"` for empty or multi-bit values —
    /// use [`Self::as_slugs`] to enumerate a set.
    pub fn slug(self) -> &'static str {
        self.attrs().0
    }

    /// Severity of a **single** flag.
    pub fn severity(self) -> RiskSeverity {
        self.attrs().1
    }

    /// nDPI-style aggregate score: the sum of the per-flag scores
    /// for every flag set. Higher = riskier.
    pub fn score(self) -> u16 {
        self.iter()
            .map(|f| f.attrs().2)
            .fold(0u16, u16::saturating_add)
    }

    /// The highest severity among the flags set, or `None` if empty.
    pub fn max_severity(self) -> Option<RiskSeverity> {
        self.iter().map(|f| f.attrs().1).max()
    }

    /// Iterator over the stable slugs of every flag set.
    pub fn as_slugs(self) -> impl Iterator<Item = &'static str> {
        self.iter().map(|f| f.attrs().0)
    }

    /// Number of distinct risk flags set.
    pub fn count(self) -> u32 {
        self.bits().count_ones()
    }
}

// ── Adapters: derive risk flags from parsed protocol data ──────
//
// The pure "verbs" that turn flowscope's parser output into risk
// flags — the missing half of #73 (the flags existed; nothing
// computed them). Each computes only the flags it can *prove*
// from its input; OR several together for a flow's total risk.
// Cert-based flags (self-signed / expired) need X.509 validation
// the caller performs and ORs in.

impl FlowRisk {
    /// Risk flags derivable from a completed TLS handshake's
    /// plaintext-observable fields: an obsolete negotiated version
    /// (below TLS 1.2 → [`Self::TLS_OBSOLETE_VERSION`]) and a
    /// weak / EXPORT / NULL / RC4 / DES cipher suite
    /// (→ [`Self::TLS_WEAK_CIPHER`], via [`is_weak_cipher`]).
    ///
    /// Does **not** set [`Self::TLS_SELF_SIGNED`] /
    /// [`Self::TLS_EXPIRED_CERT`] — those require validating the
    /// X.509 chain ([`crate::tls::TlsHandshake::certificate_chain`]),
    /// which the caller does and ORs in. Pure; no allocation.
    #[cfg(feature = "tls")]
    pub fn from_tls(hs: &crate::tls::TlsHandshake) -> FlowRisk {
        use crate::tls::TlsVersion;
        let mut r = FlowRisk::empty();
        if let Some(v) = hs.version {
            let obsolete = matches!(
                v,
                TlsVersion::Ssl3_0 | TlsVersion::Tls1_0 | TlsVersion::Tls1_1
            ) || matches!(v, TlsVersion::Other(raw) if raw < 0x0303);
            if obsolete {
                r |= FlowRisk::TLS_OBSOLETE_VERSION;
            }
        }
        if let Some(cs) = hs.cipher_suite
            && is_weak_cipher(cs)
        {
            r |= FlowRisk::TLS_WEAK_CIPHER;
        }
        r
    }

    /// Risk flags derivable from a DNS query name: a DGA-looking
    /// registrable label (scored with [`crate::detect::patterns::DgaScorer`]
    /// → [`Self::DGA_DOMAIN`]) and any Punycode / IDN (`xn--`)
    /// label (homograph-attack surface → [`Self::PUNYCODE_IDN`]).
    ///
    /// The label fed to the scorer is approximated as the
    /// second-to-last dot-label (no embedded public-suffix list,
    /// so multi-part suffixes like `co.uk` are scored
    /// imperfectly). For precise control extract the SLD yourself
    /// and call [`crate::detect::patterns::DgaScorer::is_dga`]
    /// directly. Pure; no allocation beyond a lowercased copy.
    pub fn from_dns(qname: &str, scorer: &crate::detect::patterns::DgaScorer) -> FlowRisk {
        let mut r = FlowRisk::empty();
        let trimmed = qname.trim().trim_end_matches('.');
        if trimmed.is_empty() {
            return r;
        }
        let lower = trimmed.to_ascii_lowercase();
        if lower.split('.').any(|l| l.starts_with("xn--")) {
            r |= FlowRisk::PUNYCODE_IDN;
        }
        let labels: Vec<&str> = lower.split('.').collect();
        let sld = match labels.len() {
            0 => return r,
            1 => labels[0],
            n => labels[n - 2],
        };
        if !sld.is_empty() && scorer.is_dga(sld) {
            r |= FlowRisk::DGA_DOMAIN;
        }
        r
    }

    /// Port / protocol-consistency flags from a flow's 5-tuple and
    /// the L7 protocol actually detected on it (an app-label slug
    /// such as `"http"` / `"ssh"` — e.g. from a parser's
    /// `parser_kind()` or [`crate::extract::FiveTupleKey::app_label`]).
    ///
    /// - [`Self::PORT_PROTO_MISMATCH`] — the port maps to a
    ///   *different* well-known protocol than the one detected.
    /// - [`Self::KNOWN_PROTO_NONSTD_PORT`] — a protocol was
    ///   detected on a port with no well-known mapping (nDPI's
    ///   "known protocol, non-standard port").
    ///
    /// No risk when the detected protocol matches the port's
    /// well-known label. Pure; no allocation.
    #[cfg(feature = "extractors")]
    pub fn from_port_proto(key: &crate::extract::FiveTupleKey, detected: &str) -> FlowRisk {
        let detected = detected.trim();
        if detected.is_empty() {
            return FlowRisk::empty();
        }
        match key.protocol_label() {
            Some(label) if label_matches(label, detected) => FlowRisk::empty(),
            Some(_) => FlowRisk::PORT_PROTO_MISMATCH,
            None => FlowRisk::KNOWN_PROTO_NONSTD_PORT,
        }
    }
}

/// Does a well-known port label (e.g. `"tls/https"`) name the
/// detected protocol slug (e.g. `"tls"`)?
///
/// Labels in [`crate::well_known`] are slash-delimited alias lists
/// (`"tls/https"`, `"quic/http3"`); a parser's app slug is a
/// single token (`"tls"`). Match if `detected` equals any
/// alias token (case-insensitive) — otherwise TLS on 443 would
/// read as a port/protocol mismatch against its own `"tls/https"`
/// label.
///
/// Used by [`FlowRisk::from_port_proto`] (`extractors`) and the
/// `analysis` layer's risk computation — gated to match so it
/// isn't dead code in builds with neither.
#[cfg(any(feature = "extractors", feature = "analysis"))]
pub(crate) fn label_matches(label: &str, detected: &str) -> bool {
    label
        .split('/')
        .any(|tok| tok.eq_ignore_ascii_case(detected))
}

/// Heuristic weak / deprecated TLS cipher-suite test
/// (NULL / EXPORT / RC4 / DES / 3DES / anonymous).
///
/// Conservative and **non-exhaustive** — a curated set of the
/// canonical weak suite code points from the IANA TLS registry.
/// OR in your own policy for site-specific bans (e.g. CBC-mode
/// or SHA-1 MACs, which are deprecated but too common to flag by
/// default).
pub fn is_weak_cipher(suite: u16) -> bool {
    matches!(
        suite,
        // NULL ciphers (no encryption)
        0x0000 | 0x0001 | 0x0002 | 0x003B
        // RC4
        | 0x0004 | 0x0005 | 0x0018 | 0xC002 | 0xC007 | 0xC00C | 0xC011 | 0xC016
        // DES / 3DES
        | 0x000A | 0x0013 | 0x0016 | 0x001A | 0x001B | 0xC003 | 0xC008 | 0xC012
        // EXPORT (40-bit) grade
        | 0x0003 | 0x0006 | 0x0008 | 0x0014 | 0x0017 | 0x0019
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_has_no_severity_and_zero_score() {
        let r = FlowRisk::empty();
        assert_eq!(r.score(), 0);
        assert_eq!(r.max_severity(), None);
        assert_eq!(r.count(), 0);
        assert_eq!(r.as_slugs().count(), 0);
    }

    #[test]
    fn score_sums_and_severity_maxes() {
        let r =
            FlowRisk::TLS_SELF_SIGNED | FlowRisk::DGA_DOMAIN | FlowRisk::KNOWN_PROTO_NONSTD_PORT;
        assert_eq!(r.score(), 50 + 100 + 10);
        assert_eq!(r.max_severity(), Some(RiskSeverity::High));
        assert_eq!(r.count(), 3);
    }

    #[test]
    fn severity_ordering_is_low_to_severe() {
        assert!(RiskSeverity::Low < RiskSeverity::Medium);
        assert!(RiskSeverity::Medium < RiskSeverity::High);
        assert!(RiskSeverity::High < RiskSeverity::Severe);
    }

    #[test]
    fn single_flag_slug_and_severity() {
        assert_eq!(FlowRisk::DGA_DOMAIN.slug(), "dga_domain");
        assert_eq!(FlowRisk::DGA_DOMAIN.severity(), RiskSeverity::High);
        assert_eq!(
            FlowRisk::CLEARTEXT_CREDENTIALS.slug(),
            "cleartext_credentials"
        );
    }

    #[test]
    fn as_slugs_enumerates_set_flags() {
        let r = FlowRisk::TLS_WEAK_CIPHER | FlowRisk::CLEARTEXT_CREDENTIALS;
        let slugs: Vec<_> = r.as_slugs().collect();
        assert!(slugs.contains(&"tls_weak_cipher"));
        assert!(slugs.contains(&"cleartext_credentials"));
        assert_eq!(slugs.len(), 2);
    }

    #[test]
    fn score_saturates() {
        // All flags set must not overflow u16.
        let r = FlowRisk::all();
        let _ = r.score(); // no panic / wrap
        assert!(r.score() > 0);
    }

    #[test]
    fn weak_cipher_table() {
        assert!(is_weak_cipher(0x0005)); // RSA_WITH_RC4_128_SHA
        assert!(is_weak_cipher(0x000A)); // RSA_WITH_3DES_EDE_CBC_SHA
        assert!(is_weak_cipher(0x0003)); // RSA_EXPORT_WITH_RC4_40_MD5
        assert!(is_weak_cipher(0x0000)); // NULL_WITH_NULL_NULL
        assert!(is_weak_cipher(0xC011)); // ECDHE_RSA_WITH_RC4_128_SHA
        assert!(!is_weak_cipher(0x1301)); // TLS_AES_128_GCM_SHA256
        assert!(!is_weak_cipher(0xC02F)); // ECDHE_RSA_WITH_AES_128_GCM_SHA256
    }

    #[cfg(feature = "tls")]
    #[test]
    fn from_tls_flags_obsolete_version_and_weak_cipher() {
        use crate::tls::{TlsHandshake, TlsVersion};

        let hs = TlsHandshake {
            version: Some(TlsVersion::Tls1_0),
            cipher_suite: Some(0x0005), // RC4
            ..Default::default()
        };
        let r = FlowRisk::from_tls(&hs);
        assert!(r.contains(FlowRisk::TLS_OBSOLETE_VERSION));
        assert!(r.contains(FlowRisk::TLS_WEAK_CIPHER));

        let modern = TlsHandshake {
            version: Some(TlsVersion::Tls1_3),
            cipher_suite: Some(0x1301), // AES-128-GCM
            ..Default::default()
        };
        assert!(FlowRisk::from_tls(&modern).is_empty());
    }

    #[test]
    fn from_dns_flags_dga_and_punycode() {
        let scorer = crate::detect::patterns::DgaScorer::new();

        // A clearly random-looking SLD trips DGA; a known good one doesn't.
        let dga = FlowRisk::from_dns("kq3v9z7xj2wq.com", &scorer);
        assert!(dga.contains(FlowRisk::DGA_DOMAIN));
        let benign = FlowRisk::from_dns("www.google.com", &scorer);
        assert!(!benign.contains(FlowRisk::DGA_DOMAIN));

        // Punycode label.
        let idn = FlowRisk::from_dns("xn--80ak6aa92e.com", &scorer);
        assert!(idn.contains(FlowRisk::PUNYCODE_IDN));

        // Empty / trivial input doesn't panic.
        assert!(FlowRisk::from_dns("", &scorer).is_empty());
        assert!(FlowRisk::from_dns(".", &scorer).is_empty());
    }

    #[cfg(feature = "extractors")]
    #[test]
    fn from_port_proto_mismatch_and_nonstd() {
        use crate::extract::FiveTupleKey;
        use std::net::SocketAddr;

        let mk = |dport: u16| FiveTupleKey {
            proto: crate::L4Proto::Tcp,
            a: "10.0.0.1:54321".parse::<SocketAddr>().unwrap(),
            b: format!("10.0.0.2:{dport}").parse::<SocketAddr>().unwrap(),
        };

        // SSH detected on port 443 (well-known https) → mismatch.
        let mismatch = FlowRisk::from_port_proto(&mk(443), "ssh");
        assert!(mismatch.contains(FlowRisk::PORT_PROTO_MISMATCH));

        // HTTP detected on port 80 → consistent, no risk.
        assert!(FlowRisk::from_port_proto(&mk(80), "http").is_empty());

        // TLS detected on port 443 (label "tls/https") must NOT
        // read as a mismatch — alias-token match.
        assert!(FlowRisk::from_port_proto(&mk(443), "tls").is_empty());

        // SSH on a random high port (no well-known mapping) → nonstd.
        let nonstd = FlowRisk::from_port_proto(&mk(51000), "ssh");
        assert!(nonstd.contains(FlowRisk::KNOWN_PROTO_NONSTD_PORT));
    }
}

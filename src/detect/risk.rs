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
        self.iter().map(|f| f.attrs().2).fold(0u16, u16::saturating_add)
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
        let r = FlowRisk::TLS_SELF_SIGNED | FlowRisk::DGA_DOMAIN | FlowRisk::KNOWN_PROTO_NONSTD_PORT;
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
        assert_eq!(FlowRisk::CLEARTEXT_CREDENTIALS.slug(), "cleartext_credentials");
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
}

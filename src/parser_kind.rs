//! [`ParserKind`] — typed parser identity.
//!
//! Replaces the stringly-typed `parser_kind() -> &'static str`
//! shape that shipped through 0.17. Routing on the enum at sink
//! / emit / consumer sites is now compile-checked — typos fail
//! to resolve, and `match` arms enforce exhaustiveness against
//! the standard variants.
//!
//! The enum is `#[non_exhaustive]` and includes an
//! `Other(&'static str)` variant so downstream crates can register
//! their own parser kinds without flowscope code changes.
//!
//! Issue #21 part 2/2 (Release A).

/// Which parser produced a session / datagram message.
///
/// Built-in variants cover every parser shipped under a flowscope
/// feature gate. Downstream crates register their own kinds via
/// [`Self::Other`].
///
/// `#[non_exhaustive]` — future protocol features (SSH / SMB /
/// QUIC / etc.) will add variants; matching on this enum should
/// always include a wildcard arm.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "kind", content = "value", rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum ParserKind {
    /// HTTP/1.x ([`crate::http`]).
    Http1,
    /// TLS ClientHello / ServerHello / Alert / ApplicationData
    /// ([`crate::tls`]).
    Tls,
    /// TLS handshake aggregator
    /// ([`crate::tls::TlsHandshakeParser`]).
    TlsHandshake,
    /// DNS-over-UDP ([`crate::dns::DnsUdpParser`]).
    DnsUdp,
    /// DNS-over-TCP ([`crate::dns::DnsTcpParser`]).
    DnsTcp,
    /// ICMP v4 / v6 ([`crate::icmp::IcmpParser`]).
    Icmp,
    /// Downstream-registered parser kind. The `&'static str`
    /// label should be a unique stable slug — typical convention
    /// is `"crate-name/protocol"` (e.g. `"netring/syslog"`).
    Other(&'static str),
    /// Parser didn't identify itself (e.g. a test stub). The
    /// default returned by the [`crate::SessionParser`] /
    /// [`crate::DatagramParser`] traits when not overridden.
    #[default]
    Unspecified,
}

impl ParserKind {
    /// Stable slug — same vocabulary the 0.17-and-earlier
    /// `parser_kind() -> &'static str` returned. Use for metric
    /// labels and JSON `parser_kind` field emission.
    ///
    /// Vocabulary (locked):
    ///
    /// | Variant | Slug |
    /// |---------|------|
    /// | [`Self::Http1`] | `"http/1"` |
    /// | [`Self::Tls`] | `"tls"` |
    /// | [`Self::TlsHandshake`] | `"tls-handshake"` |
    /// | [`Self::DnsUdp`] | `"dns-udp"` |
    /// | [`Self::DnsTcp`] | `"dns-tcp"` |
    /// | [`Self::Icmp`] | `"icmp"` |
    /// | [`Self::Other`] | the wrapped `&'static str` (caller-supplied) |
    /// | [`Self::Unspecified`] | `""` |
    pub fn as_str(&self) -> &'static str {
        match self {
            ParserKind::Http1 => "http/1",
            ParserKind::Tls => "tls",
            ParserKind::TlsHandshake => "tls-handshake",
            ParserKind::DnsUdp => "dns-udp",
            ParserKind::DnsTcp => "dns-tcp",
            ParserKind::Icmp => "icmp",
            ParserKind::Other(s) => s,
            ParserKind::Unspecified => "",
        }
    }
}

impl std::fmt::Display for ParserKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_vocabulary_locked() {
        // Regression-pin the slugs — downstream metric pipelines
        // depend on these.
        assert_eq!(ParserKind::Http1.as_str(), "http/1");
        assert_eq!(ParserKind::Tls.as_str(), "tls");
        assert_eq!(ParserKind::TlsHandshake.as_str(), "tls-handshake");
        assert_eq!(ParserKind::DnsUdp.as_str(), "dns-udp");
        assert_eq!(ParserKind::DnsTcp.as_str(), "dns-tcp");
        assert_eq!(ParserKind::Icmp.as_str(), "icmp");
        assert_eq!(ParserKind::Unspecified.as_str(), "");
        assert_eq!(
            ParserKind::Other("netring/syslog").as_str(),
            "netring/syslog"
        );
    }

    #[test]
    fn default_is_unspecified() {
        assert_eq!(ParserKind::default(), ParserKind::Unspecified);
    }

    #[test]
    fn display_uses_slug() {
        assert_eq!(ParserKind::Http1.to_string(), "http/1");
        assert_eq!(ParserKind::Other("custom").to_string(), "custom");
    }
}

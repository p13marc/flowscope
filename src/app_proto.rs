//! `flowscope::app_proto` — identify the application protocol
//! riding an **encrypted** transport from passively-observable
//! signals: ALPN, SNI, and the L4 port (issue #138).
//!
//! TLS and QUIC hide the application, but the handshake still
//! leaks enough to name it without decryption:
//!
//! - **ALPN** is authoritative — `h2` / `h3` / `dot` / `doq` /
//!   `http/1.1` are negotiated in the clear.
//! - **Port 853** is the reserved DNS-over-TLS / DNS-over-QUIC
//!   port (a fallback when ALPN is absent).
//! - **SNI** disambiguates DNS-over-HTTPS: DoH looks exactly like
//!   HTTPS on the wire (ALPN `h2`/`h3`, port 443), so the only
//!   passive tell is the resolver's hostname
//!   ([`is_known_doh_host`]).
//!
//! This closes the "encrypted DNS is invisible" and "no HTTP/2·3
//! visibility" NDR gaps without a full H2/H3 parser — detection,
//! not decode.
//!
//! # Example
//!
//! ```
//! use flowscope::app_proto::{classify, AppProtocol, Transport};
//!
//! // h2 to a normal host is HTTP/2…
//! let p = classify(&["h2"], Some("example.com"), Transport::Tls, 443);
//! assert_eq!(p, AppProtocol::Http2);
//!
//! // …but h2 to a known DoH resolver is DNS-over-HTTPS.
//! let p = classify(&["h2"], Some("cloudflare-dns.com"), Transport::Tls, 443);
//! assert_eq!(p, AppProtocol::DnsOverHttps);
//! assert!(p.is_encrypted_dns());
//!
//! // Port 853 with no ALPN still resolves to DoT / DoQ.
//! let none: &[&str] = &[];
//! assert_eq!(
//!     classify(none, None, Transport::Quic, 853),
//!     AppProtocol::DnsOverQuic,
//! );
//! ```

/// Transport an application protocol is riding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum Transport {
    /// TLS over TCP.
    Tls,
    /// QUIC over UDP.
    Quic,
}

/// Identified application protocol over an encrypted transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum AppProtocol {
    /// HTTP/1.1 (ALPN `http/1.1`).
    Http1,
    /// HTTP/2 (ALPN `h2`).
    Http2,
    /// HTTP/3 (ALPN `h3` / `h3-NN` draft tokens).
    Http3,
    /// DNS-over-TLS, RFC 7858 (ALPN `dot`, or TCP/853).
    DnsOverTls,
    /// DNS-over-QUIC, RFC 9250 (ALPN `doq` / `doq-iNN`, or UDP/853).
    DnsOverQuic,
    /// DNS-over-HTTPS, RFC 8484 (HTTP/2·3 to a known resolver
    /// host — indistinguishable from plain HTTPS but for the SNI).
    DnsOverHttps,
    /// None of the recognised protocols matched.
    #[default]
    Unknown,
}

impl AppProtocol {
    /// Stable lowercase slug for logs / metric labels.
    pub fn as_str(&self) -> &'static str {
        match self {
            AppProtocol::Http1 => "http/1.1",
            AppProtocol::Http2 => "h2",
            AppProtocol::Http3 => "h3",
            AppProtocol::DnsOverTls => "dot",
            AppProtocol::DnsOverQuic => "doq",
            AppProtocol::DnsOverHttps => "doh",
            AppProtocol::Unknown => "unknown",
        }
    }

    /// `true` if this is any form of encrypted DNS (DoT / DoQ / DoH).
    pub fn is_encrypted_dns(&self) -> bool {
        matches!(
            self,
            AppProtocol::DnsOverTls | AppProtocol::DnsOverQuic | AppProtocol::DnsOverHttps
        )
    }

    /// `true` if this is any HTTP version.
    pub fn is_http(&self) -> bool {
        matches!(
            self,
            AppProtocol::Http1 | AppProtocol::Http2 | AppProtocol::Http3
        )
    }
}

/// Classify a single ALPN token. Returns `None` for tokens that
/// don't map to a recognised protocol (so a caller can keep
/// scanning a list).
pub fn classify_alpn_token(token: &str) -> Option<AppProtocol> {
    // h3 drafts: "h3", "h3-29", "h3-32", … ; doq drafts likewise.
    if token == "h2" {
        Some(AppProtocol::Http2)
    } else if token == "h3" || token.starts_with("h3-") {
        Some(AppProtocol::Http3)
    } else if token == "http/1.1" || token == "http/1.0" {
        Some(AppProtocol::Http1)
    } else if token == "dot" {
        Some(AppProtocol::DnsOverTls)
    } else if token == "doq" || token.starts_with("doq-") {
        Some(AppProtocol::DnsOverQuic)
    } else {
        None
    }
}

/// Classify from the full signal set: the ALPN list (in offer /
/// selection order — the first recognised token wins), the SNI,
/// the transport, and the server L4 port.
///
/// Precedence: ALPN → port-853 fallback → DoH-by-SNI refinement.
/// An `h2`/`h3` flow to a [known DoH resolver host](is_known_doh_host)
/// is reclassified from `Http2`/`Http3` to `DnsOverHttps`.
pub fn classify<S: AsRef<str>>(
    alpn: &[S],
    sni: Option<&str>,
    transport: Transport,
    port: u16,
) -> AppProtocol {
    // 1. ALPN is authoritative for the base protocol.
    let mut proto = alpn
        .iter()
        .find_map(|t| classify_alpn_token(t.as_ref()))
        .unwrap_or(AppProtocol::Unknown);

    // 2. Port 853 is reserved for DoT (TLS) / DoQ (QUIC) — use it
    //    when ALPN didn't already name an encrypted-DNS protocol.
    if port == 853 && !proto.is_encrypted_dns() {
        proto = match transport {
            Transport::Tls => AppProtocol::DnsOverTls,
            Transport::Quic => AppProtocol::DnsOverQuic,
        };
    }

    // 3. DoH refinement: HTTP/2·3 to a known resolver host is DoH.
    if proto.is_http()
        && let Some(host) = sni
        && is_known_doh_host(host)
    {
        proto = AppProtocol::DnsOverHttps;
    }

    proto
}

/// `true` if `sni` is a well-known public DNS-over-HTTPS resolver
/// hostname. DoH is wire-identical to HTTPS, so the hostname is
/// the only passive signal; this is a curated (non-exhaustive)
/// list of the major public resolvers. A site-specific resolver
/// won't match — pair with a config allowlist when it matters.
pub fn is_known_doh_host(sni: &str) -> bool {
    let host = sni.trim_end_matches('.').to_ascii_lowercase();
    KNOWN_DOH_HOSTS.contains(&host.as_str())
}

/// Curated public DoH resolver hostnames (2026).
const KNOWN_DOH_HOSTS: &[&str] = &[
    "dns.google",
    "dns.google.com",
    "cloudflare-dns.com",
    "mozilla.cloudflare-dns.com",
    "security.cloudflare-dns.com",
    "family.cloudflare-dns.com",
    "one.one.one.one",
    "dns.quad9.net",
    "dns9.quad9.net",
    "dns10.quad9.net",
    "dns11.quad9.net",
    "doh.opendns.com",
    "dns.nextdns.io",
    "doh.cleanbrowsing.org",
    "dns.adguard-dns.com",
    "dns.adguard.com",
    "doh.dns.sb",
    "dns.controld.com",
];

/// Convenience adapters from the parsed handshake types.
impl AppProtocol {
    /// Classify from a completed [`TlsHandshake`](crate::tls::TlsHandshake)
    /// and the server L4 port. Prefers the server-selected ALPN
    /// (authoritative); falls back to the client's offered list.
    #[cfg(feature = "tls")]
    pub fn from_tls_handshake(hs: &crate::tls::TlsHandshake, port: u16) -> AppProtocol {
        // Server's single selection wins; else scan the client offer.
        let alpn: Vec<&str> = match hs.server_alpn.as_deref() {
            Some(s) => vec![s],
            None => hs.client_alpn.iter().map(String::as_str).collect(),
        };
        classify(&alpn, hs.sni.as_deref(), Transport::Tls, port)
    }

    /// Classify from a [`QuicInitial`](crate::quic::QuicInitial) and
    /// the server UDP port (QUIC transport is implied).
    #[cfg(feature = "quic")]
    pub fn from_quic_initial(qi: &crate::quic::QuicInitial, port: u16) -> AppProtocol {
        classify(&qi.alpn, qi.sni.as_deref(), Transport::Quic, port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alpn_h2_h3_http1() {
        assert_eq!(classify_alpn_token("h2"), Some(AppProtocol::Http2));
        assert_eq!(classify_alpn_token("h3"), Some(AppProtocol::Http3));
        assert_eq!(classify_alpn_token("h3-29"), Some(AppProtocol::Http3));
        assert_eq!(classify_alpn_token("http/1.1"), Some(AppProtocol::Http1));
        assert_eq!(classify_alpn_token("spdy/3"), None);
    }

    #[test]
    fn alpn_encrypted_dns_tokens() {
        assert_eq!(classify_alpn_token("dot"), Some(AppProtocol::DnsOverTls));
        assert_eq!(classify_alpn_token("doq"), Some(AppProtocol::DnsOverQuic));
        assert_eq!(
            classify_alpn_token("doq-i03"),
            Some(AppProtocol::DnsOverQuic)
        );
    }

    #[test]
    fn port_853_fallback_without_alpn() {
        let none: &[&str] = &[];
        assert_eq!(
            classify(none, None, Transport::Tls, 853),
            AppProtocol::DnsOverTls
        );
        assert_eq!(
            classify(none, None, Transport::Quic, 853),
            AppProtocol::DnsOverQuic
        );
    }

    #[test]
    fn doh_reclassifies_http_to_known_resolver() {
        // h2 to a normal site stays Http2…
        assert_eq!(
            classify(&["h2"], Some("example.com"), Transport::Tls, 443),
            AppProtocol::Http2
        );
        // …but h2 to a known DoH host is DoH.
        assert_eq!(
            classify(&["h2"], Some("cloudflare-dns.com"), Transport::Tls, 443),
            AppProtocol::DnsOverHttps
        );
        // h3/QUIC DoH too.
        assert_eq!(
            classify(&["h3"], Some("dns.google"), Transport::Quic, 443),
            AppProtocol::DnsOverHttps
        );
    }

    #[test]
    fn alpn_beats_port_for_dot() {
        // ALPN dot on the standard port.
        assert_eq!(
            classify(&["dot"], None, Transport::Tls, 853),
            AppProtocol::DnsOverTls
        );
    }

    #[test]
    fn doh_host_canonicalisation() {
        assert!(is_known_doh_host("Cloudflare-DNS.com."));
        assert!(is_known_doh_host("dns.google"));
        assert!(!is_known_doh_host("example.com"));
    }

    #[test]
    fn slugs_and_predicates() {
        assert_eq!(AppProtocol::DnsOverHttps.as_str(), "doh");
        assert!(AppProtocol::DnsOverQuic.is_encrypted_dns());
        assert!(AppProtocol::Http3.is_http());
        assert!(!AppProtocol::Http2.is_encrypted_dns());
    }
}

//! [`L7Summary`] — the curated, security-relevant L7 facts
//! observed on a single flow.
//!
//! A flow can carry many parser messages (a TLS handshake, several
//! HTTP requests, a burst of DNS queries). `L7Summary` is the
//! distilled "what mattered" view: the fields a risk engine or a
//! SIEM record actually consumes. It is populated incrementally by
//! the `observe_*` mutators (each gated by its parser's feature)
//! and then folded into an [`crate::analysis::AnalyzedFlow`].

/// Upper bound on stored DNS query names per flow — keeps a
/// chatty resolver flow from growing the summary without limit
/// (the project's bounded-memory rule).
pub const MAX_DNS_QUERIES: usize = 16;

/// Curated security-relevant L7 facts observed on a flow.
///
/// Every field is optional / additive; a flow with no observed L7
/// yields the [`Default`] (all-empty) summary. `#[non_exhaustive]`
/// — future protocols add fields without breaking construction
/// (build via [`Default`] and the `observe_*` mutators).
#[derive(Debug, Clone, Default, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct L7Summary {
    /// Detected application protocol label (`"tls"` / `"http"` /
    /// `"dns"`). Last writer wins when a flow upgrades (e.g.
    /// HTTP CONNECT → TLS).
    pub app_proto: Option<&'static str>,
    /// The server name the client asked for — TLS SNI or HTTP
    /// `Host`. The single most useful pivot field.
    pub server_name: Option<String>,
    /// JA3 TLS client fingerprint (MD5 hex), if observed.
    pub ja3: Option<String>,
    /// JA4 TLS client fingerprint (FoxIO format), if observed.
    pub ja4: Option<String>,
    /// Negotiated TLS version as the raw 16-bit code point
    /// (e.g. `0x0303` = TLS 1.2).
    pub tls_version: Option<u16>,
    /// Negotiated TLS cipher suite code point.
    pub tls_cipher: Option<u16>,
    /// HTTP `User-Agent` header value.
    pub user_agent: Option<String>,
    /// HTTP request method (`GET` / `POST` / …).
    pub http_method: Option<String>,
    /// HTTP request path / URI.
    pub http_uri: Option<String>,
    /// DNS query names observed on the flow (bounded to
    /// [`MAX_DNS_QUERIES`]).
    pub dns_queries: Vec<String>,
}

impl L7Summary {
    /// `true` if nothing L7 was observed (the default state).
    pub fn is_empty(&self) -> bool {
        *self == L7Summary::default()
    }

    /// Fold the facts from a completed TLS handshake into the
    /// summary: SNI → [`Self::server_name`], JA3/JA4, negotiated
    /// version + cipher.
    #[cfg(feature = "tls")]
    pub fn observe_tls(&mut self, hs: &crate::tls::TlsHandshake) {
        self.app_proto = Some("tls");
        if let Some(sni) = &hs.sni {
            self.server_name = Some(sni.clone());
        }
        if let Some(ja3) = &hs.ja3 {
            self.ja3 = Some(ja3.clone());
        }
        if let Some(ja4) = &hs.ja4 {
            self.ja4 = Some(ja4.clone());
        }
        if let Some(v) = hs.version {
            self.tls_version = Some(v.to_raw());
        }
        if let Some(c) = hs.cipher_suite {
            self.tls_cipher = Some(c);
        }
    }

    /// Fold the facts from an HTTP message into the summary. Only
    /// requests carry security-relevant identity (Host / UA /
    /// method / path); responses are ignored here.
    #[cfg(feature = "http")]
    pub fn observe_http(&mut self, msg: &crate::http::HttpMessage) {
        if let crate::http::HttpMessage::Request(req) = msg {
            self.app_proto = Some("http");
            // Don't clobber a TLS SNI already set on an upgraded flow.
            if self.server_name.is_none()
                && let Some(host) = req.host()
            {
                self.server_name = Some(host.to_owned());
            }
            if let Some(ua) = req.user_agent() {
                self.user_agent = Some(ua.to_owned());
            }
            if let Some(m) = req.method_str() {
                self.http_method = Some(m.to_owned());
            }
            if let Some(p) = req.path_str() {
                self.http_uri = Some(p.to_owned());
            }
        }
    }

    /// Record the query names from a parsed DNS query, bounded to
    /// [`MAX_DNS_QUERIES`].
    #[cfg(feature = "dns")]
    pub fn observe_dns_query(&mut self, q: &crate::dns::DnsQuery) {
        self.app_proto = Some("dns");
        self.push_dns_names(q.questions.iter().map(|q| q.name.as_str()));
    }

    /// Record the query names from a parsed DNS response, bounded
    /// to [`MAX_DNS_QUERIES`].
    #[cfg(feature = "dns")]
    pub fn observe_dns_response(&mut self, r: &crate::dns::DnsResponse) {
        self.app_proto = Some("dns");
        self.push_dns_names(r.questions.iter().map(|q| q.name.as_str()));
    }

    #[cfg(feature = "dns")]
    fn push_dns_names<'a>(&mut self, names: impl Iterator<Item = &'a str>) {
        for name in names {
            if self.dns_queries.len() >= MAX_DNS_QUERIES {
                break;
            }
            if !name.is_empty() && !self.dns_queries.iter().any(|q| q == name) {
                self.dns_queries.push(name.to_owned());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_empty() {
        assert!(L7Summary::default().is_empty());
    }

    #[cfg(feature = "tls")]
    #[test]
    fn observe_tls_extracts_fields() {
        use crate::tls::{TlsHandshake, TlsVersion};
        let hs = TlsHandshake {
            sni: Some("example.com".into()),
            ja4: Some("t13d1516h2_x_y".into()),
            version: Some(TlsVersion::Tls1_2),
            cipher_suite: Some(0x1301),
            ..Default::default()
        };
        let mut s = L7Summary::default();
        s.observe_tls(&hs);
        assert!(!s.is_empty());
        assert_eq!(s.app_proto, Some("tls"));
        assert_eq!(s.server_name.as_deref(), Some("example.com"));
        assert_eq!(s.ja4.as_deref(), Some("t13d1516h2_x_y"));
        assert_eq!(s.tls_version, Some(0x0303));
        assert_eq!(s.tls_cipher, Some(0x1301));
    }

    #[cfg(feature = "dns")]
    #[test]
    fn dns_queries_are_bounded_and_deduped() {
        use crate::dns::{DnsFlags, DnsQuery, DnsQuestion};
        let mk = |name: &str| DnsQuery {
            transaction_id: 0,
            flags: DnsFlags(0),
            questions: vec![DnsQuestion {
                name: name.to_owned(),
                qtype: 1,
                qclass: 1,
            }],
            timestamp: crate::Timestamp::default(),
        };
        let mut s = L7Summary::default();
        // Build > MAX distinct names; only MAX should survive.
        for i in 0..(MAX_DNS_QUERIES + 5) {
            s.observe_dns_query(&mk(&format!("h{i}.example.com")));
        }
        assert_eq!(s.dns_queries.len(), MAX_DNS_QUERIES);
        // Duplicate name doesn't grow the vec.
        s.observe_dns_query(&mk("h0.example.com"));
        assert_eq!(s.dns_queries.len(), MAX_DNS_QUERIES);
    }
}

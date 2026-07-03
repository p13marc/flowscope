//! Plan 86 — `PARSER_KIND_*` constants per parser module. Verify
//! that each parser's `parser_kind().as_str()` returns its module
//! constant and that the slug vocabulary is byte-stable.
//!
//! Issue #139 (0.22): the deprecated `flowscope::parser_kinds`
//! umbrella re-export was removed — the typed
//! [`flowscope::ParserKind`] enum (`.as_str()`) is the single
//! source of the slug vocabulary. These tests pin the module
//! constants against it.

#![cfg(any(feature = "http", feature = "tls", feature = "dns", feature = "icmp"))]

#[cfg(feature = "http")]
#[test]
fn http_constant_matches_parser_kind() {
    use flowscope::{
        SessionParser,
        http::{HttpParser, PARSER_KIND},
    };
    let p = HttpParser::default();
    assert_eq!(p.parser_kind().as_str(), PARSER_KIND);
    assert_eq!(PARSER_KIND, "http/1");
}

#[cfg(feature = "dns")]
#[test]
fn dns_udp_constant_matches_parser_kind() {
    use flowscope::{
        DatagramParser,
        dns::{DnsUdpParser, PARSER_KIND_UDP},
    };
    let p = DnsUdpParser::default();
    assert_eq!(p.parser_kind().as_str(), PARSER_KIND_UDP);
    assert_eq!(PARSER_KIND_UDP, "dns-udp");
}

#[cfg(feature = "dns")]
#[test]
fn dns_tcp_constant_matches_parser_kind() {
    use flowscope::{
        SessionParser,
        dns::{DnsTcpParser, PARSER_KIND_TCP},
    };
    let p = DnsTcpParser::default();
    assert_eq!(p.parser_kind().as_str(), PARSER_KIND_TCP);
    assert_eq!(PARSER_KIND_TCP, "dns-tcp");
}

#[cfg(feature = "tls")]
#[test]
fn tls_constant_matches_parser_kind() {
    use flowscope::{
        SessionParser,
        tls::{PARSER_KIND, TlsParser},
    };
    let p = TlsParser::default();
    assert_eq!(p.parser_kind().as_str(), PARSER_KIND);
    assert_eq!(PARSER_KIND, "tls");
}

#[cfg(feature = "icmp")]
#[test]
fn icmp_constant_matches_parser_kind() {
    use flowscope::{
        DatagramParser,
        icmp::{IcmpParser, PARSER_KIND},
    };
    let p = IcmpParser::new();
    assert_eq!(p.parser_kind().as_str(), PARSER_KIND);
    assert_eq!(PARSER_KIND, "icmp");
}

/// Sanity check that constants work in `&'static str` contexts —
/// e.g. as `metrics::counter!` labels with zero allocation.
#[cfg(feature = "http")]
#[test]
fn constants_are_static_str() {
    let _s: &'static str = flowscope::http::PARSER_KIND;
}

//! Plan 86 — `PARSER_KIND_*` constants per parser module + the
//! `flowscope::parser_kinds` umbrella re-export. Verify that
//! each parser's `parser_kind()` returns the module constant
//! and that the umbrella re-exports match.

#![cfg(any(feature = "http", feature = "tls", feature = "dns", feature = "icmp"))]

#[cfg(feature = "http")]
#[test]
fn http_constant_matches_parser_kind() {
    use flowscope::SessionParser;
    use flowscope::http::{HttpParser, PARSER_KIND};
    let p = HttpParser::default();
    assert_eq!(p.parser_kind(), PARSER_KIND);
    assert_eq!(PARSER_KIND, "http/1");
}

#[cfg(feature = "dns")]
#[test]
fn dns_udp_constant_matches_parser_kind() {
    use flowscope::DatagramParser;
    use flowscope::dns::{DnsUdpParser, PARSER_KIND_UDP};
    let p = DnsUdpParser::default();
    assert_eq!(p.parser_kind(), PARSER_KIND_UDP);
    assert_eq!(PARSER_KIND_UDP, "dns-udp");
}

#[cfg(feature = "dns")]
#[test]
fn dns_tcp_constant_matches_parser_kind() {
    use flowscope::SessionParser;
    use flowscope::dns::{DnsTcpParser, PARSER_KIND_TCP};
    let p = DnsTcpParser::default();
    assert_eq!(p.parser_kind(), PARSER_KIND_TCP);
    assert_eq!(PARSER_KIND_TCP, "dns-tcp");
}

#[cfg(feature = "tls")]
#[test]
fn tls_constant_matches_parser_kind() {
    use flowscope::SessionParser;
    use flowscope::tls::{PARSER_KIND, TlsParser};
    let p = TlsParser::default();
    assert_eq!(p.parser_kind(), PARSER_KIND);
    assert_eq!(PARSER_KIND, "tls");
}

#[cfg(feature = "icmp")]
#[test]
fn icmp_constant_matches_parser_kind() {
    use flowscope::DatagramParser;
    use flowscope::icmp::{IcmpParser, PARSER_KIND};
    let p = IcmpParser::new();
    assert_eq!(p.parser_kind(), PARSER_KIND);
    assert_eq!(PARSER_KIND, "icmp");
}

#[cfg(feature = "http")]
#[test]
fn parser_kinds_umbrella_http() {
    use flowscope::http;
    use flowscope::parser_kinds;
    assert_eq!(parser_kinds::HTTP, http::PARSER_KIND);
}

#[cfg(feature = "dns")]
#[test]
fn parser_kinds_umbrella_dns() {
    use flowscope::dns;
    use flowscope::parser_kinds;
    assert_eq!(parser_kinds::DNS_UDP, dns::PARSER_KIND_UDP);
    assert_eq!(parser_kinds::DNS_TCP, dns::PARSER_KIND_TCP);
}

#[cfg(feature = "tls")]
#[test]
fn parser_kinds_umbrella_tls() {
    use flowscope::parser_kinds;
    use flowscope::tls;
    assert_eq!(parser_kinds::TLS, tls::PARSER_KIND);
}

#[cfg(feature = "icmp")]
#[test]
fn parser_kinds_umbrella_icmp() {
    use flowscope::icmp;
    use flowscope::parser_kinds;
    assert_eq!(parser_kinds::ICMP, icmp::PARSER_KIND);
}

/// Sanity check that constants work in `&'static str` contexts —
/// e.g. as `metrics::counter!` labels with zero allocation.
#[cfg(feature = "http")]
#[test]
fn constants_are_static_str() {
    let _s: &'static str = flowscope::http::PARSER_KIND;
    let _u: &'static str = flowscope::parser_kinds::HTTP;
}

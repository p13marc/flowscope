//! Identify the application protocol riding an encrypted transport
//! (issue #138) — HTTP/2·3 and DNS-over-{TLS,QUIC,HTTPS} — from
//! only the ALPN, SNI, and L4 port. No decryption.
//!
//! Encrypted DNS is deliberately camouflaged: DoH is wire-identical
//! to HTTPS, DoT/DoQ hide on 443-adjacent infrastructure. The
//! passive tells are the negotiated ALPN token, the reserved
//! port 853, and — for DoH — the resolver's SNI hostname.
//!
//! Usage:
//!     cargo run --example encrypted_app_classify

use flowscope::app_proto::{Transport, classify};

/// (label, ALPN tokens, SNI, transport, server port)
type Case = (
    &'static str,
    &'static [&'static str],
    Option<&'static str>,
    Transport,
    u16,
);

fn main() {
    let cases: &[Case] = &[
        (
            "browser HTTPS",
            &["h2", "http/1.1"],
            Some("example.com"),
            Transport::Tls,
            443,
        ),
        (
            "HTTP/3",
            &["h3"],
            Some("cdn.example.com"),
            Transport::Quic,
            443,
        ),
        (
            "DoH (Cloudflare)",
            &["h2"],
            Some("cloudflare-dns.com"),
            Transport::Tls,
            443,
        ),
        (
            "DoH/3 (Google)",
            &["h3"],
            Some("dns.google"),
            Transport::Quic,
            443,
        ),
        ("DoT (ALPN)", &["dot"], None, Transport::Tls, 853),
        ("DoT (port only)", &[], None, Transport::Tls, 853),
        ("DoQ", &["doq"], None, Transport::Quic, 853),
        (
            "unknown TLS",
            &[],
            Some("internal.corp"),
            Transport::Tls,
            8443,
        ),
    ];

    println!("flow                 app_proto      encrypted-DNS?");
    println!("{}", "-".repeat(52));
    for (label, alpn, sni, transport, port) in cases {
        let proto = classify(alpn, *sni, *transport, *port);
        let dns_flag = if proto.is_encrypted_dns() {
            "yes ⚠"
        } else {
            ""
        };
        println!("{label:<20} {:<14} {dns_flag}", proto.as_str());
    }
}

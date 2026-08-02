//! Decide what protocol a connection is speaking from its first
//! bytes, without ever guessing on a short read.
//!
//! A router that terminates or forwards arbitrary TCP has to answer
//! "what is this?" before it can answer "where does it go?". The
//! answer has to be incremental: a peek that has not yet arrived in
//! full must produce [`Classify::NeedMore`], never a wrong
//! [`Decided`](Classify::Decided) that routes the connection to the
//! wrong backend.
//!
//! ```
//! use flowscope::classify::{Classify, WireProtocol, classify_first_bytes};
//!
//! // Enough of a TLS record header to be sure.
//! assert_eq!(
//!     classify_first_bytes(&[0x16, 0x03, 0x01, 0x02, 0x00, 0x01]),
//!     Classify::Decided(WireProtocol::Tls),
//! );
//!
//! // "GE" is still a prefix of several method tokens — wait.
//! assert_eq!(classify_first_bytes(b"GE"), Classify::NeedMore);
//! // A complete method token settles it; the rest of the request
//! // line adds nothing.
//! assert_eq!(
//!     classify_first_bytes(b"GET "),
//!     Classify::Decided(WireProtocol::Http1),
//! );
//!
//! // Nothing this could grow into is a protocol we know.
//! assert_eq!(
//!     classify_first_bytes(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08"),
//!     Classify::Decided(WireProtocol::Raw),
//! );
//! ```
//!
//! # Server-speaks-first protocols
//!
//! Some protocols (SSH, SMTP, and friends) have the *server* send the
//! first bytes, so a client-side peek stays empty however long you
//! wait. That timeout belongs to the caller: this function keeps
//! answering [`NeedMore`](Classify::NeedMore) while the peek is
//! short, and the caller decides when to give up and treat the
//! connection as [`Raw`](WireProtocol::Raw).
//!
//! # Binding the decision (ALPACA)
//!
//! First bytes say what the client *speaks*, not what it *intends*.
//! The ALPACA cross-protocol attack abuses exactly that gap: a
//! browser is steered into a TLS connection with a server expecting a
//! different application protocol. Bind the backend choice to the
//! negotiated ALPN and SNI (or `Host`) as well, and refuse
//! mismatches; treat this classification as a routing hint, never as
//! an authorization decision.

/// A protocol recognisable from the first bytes of a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum WireProtocol {
    /// A TLS record carrying a handshake — parse it with
    /// `flowscope::tls` for the SNI and ALPN.
    Tls,
    /// An HTTP/1.x request line.
    Http1,
    /// The HTTP/2 client connection preface: a prior-knowledge h2
    /// client, or h2c after an upgrade.
    Http2Preface,
    /// An SSH identification string.
    Ssh,
    /// Nothing recognised. Pass it through untouched.
    Raw,
}

impl WireProtocol {
    /// Stable, lowercase slug — safe as a metric label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tls => "tls",
            Self::Http1 => "http1",
            Self::Http2Preface => "http2-preface",
            Self::Ssh => "ssh",
            Self::Raw => "raw",
        }
    }
}

impl std::fmt::Display for WireProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The outcome of looking at a peek.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Classify {
    /// Settled. More bytes will not change this.
    Decided(WireProtocol),
    /// The peek is a prefix of something recognisable but is not yet
    /// long enough to be sure. Read more and ask again.
    NeedMore,
}

/// The HTTP/2 client connection preface, RFC 9113 §3.4.
pub const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// SSH identification-string prefixes, RFC 4253 §4.2.
const SSH_PREFIXES: &[&[u8]] = &[b"SSH-2.0-", b"SSH-1.99-"];

/// HTTP/1 request-line prefixes. Methods are case-sensitive
/// (RFC 9110 §9.1), and every registered one is uppercase.
const HTTP_METHODS: &[&[u8]] = &[
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"TRACE ",
    b"CONNECT ",
];

/// Longest prefix any recogniser needs before it can rule itself out.
const MAX_PREFIX: usize = HTTP2_PREFACE.len();

/// Classify the first bytes of a connection.
///
/// Never returns a wrong [`Decided`](Classify::Decided) for a short
/// peek: anything that is still a viable prefix of a known protocol
/// yields [`NeedMore`](Classify::NeedMore). Once nothing can match,
/// the answer is [`Raw`](WireProtocol::Raw) — which is a decision,
/// not a failure.
///
/// The peek should be the first bytes the *client* sent, in order.
pub fn classify_first_bytes(peek: &[u8]) -> Classify {
    if peek.is_empty() {
        return Classify::NeedMore;
    }

    // HTTP/2 is checked first, and deliberately: "PRI " is also a
    // plausible HTTP/1 method token, so testing HTTP/1 first would
    // misroute a prior-knowledge h2 connection.
    match prefix_of(peek, HTTP2_PREFACE) {
        Prefix::Full => return Classify::Decided(WireProtocol::Http2Preface),
        Prefix::Partial => return Classify::NeedMore,
        Prefix::No => {}
    }

    // TLS: a handshake record — 0x16, a plausible legacy version,
    // then (once the body starts) the ClientHello message type.
    // RFC 8446 §5.1.
    if peek[0] == 0x16 {
        if peek.len() < 6 {
            return Classify::NeedMore;
        }
        if peek[1] == 0x03 && peek[2] <= 0x04 && peek[5] == 0x01 {
            return Classify::Decided(WireProtocol::Tls);
        }
        return Classify::Decided(WireProtocol::Raw);
    }

    for prefix in SSH_PREFIXES {
        match prefix_of(peek, prefix) {
            Prefix::Full => return Classify::Decided(WireProtocol::Ssh),
            Prefix::Partial => return Classify::NeedMore,
            Prefix::No => {}
        }
    }

    // HTTP/1: an uppercase method token followed by a space. Longest
    // is "CONNECT " at 8 bytes. A lowercase method is not valid
    // HTTP (methods are case-sensitive), so it stays Raw rather than
    // being quietly accepted — a proxy that normalizes case here and
    // a backend that does not would disagree about the request.
    for method in HTTP_METHODS {
        match prefix_of(peek, method) {
            Prefix::Full => return Classify::Decided(WireProtocol::Http1),
            Prefix::Partial => return Classify::NeedMore,
            Prefix::No => {}
        }
    }

    // Nothing matched. If the peek is still shorter than the longest
    // prefix any recogniser needs, it cannot yet be ruled out.
    if peek.len() < MAX_PREFIX && could_still_grow(peek) {
        return Classify::NeedMore;
    }
    Classify::Decided(WireProtocol::Raw)
}

/// Whether `peek` matches `needle`, is a proper prefix of it, or
/// neither.
enum Prefix {
    Full,
    Partial,
    No,
}

fn prefix_of(peek: &[u8], needle: &[u8]) -> Prefix {
    if peek.len() >= needle.len() {
        if peek.starts_with(needle) {
            Prefix::Full
        } else {
            Prefix::No
        }
    } else if needle.starts_with(peek) {
        Prefix::Partial
    } else {
        Prefix::No
    }
}

/// Could a longer peek starting with these bytes still match
/// something? Used only to decide between `NeedMore` and `Raw`.
fn could_still_grow(peek: &[u8]) -> bool {
    if HTTP2_PREFACE.starts_with(peek) {
        return true;
    }
    if peek[0] == 0x16 {
        return true;
    }
    SSH_PREFIXES.iter().any(|p| p.starts_with(peek))
        || HTTP_METHODS.iter().any(|m| m.starts_with(peek))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decided(bytes: &[u8]) -> WireProtocol {
        match classify_first_bytes(bytes) {
            Classify::Decided(p) => p,
            Classify::NeedMore => panic!("expected a decision for {bytes:?}"),
        }
    }

    #[test]
    fn recognises_each_protocol() {
        assert_eq!(decided(b"GET / HTTP/1.1\r\n"), WireProtocol::Http1);
        assert_eq!(decided(b"CONNECT h:443 HTTP/1.1\r\n"), WireProtocol::Http1);
        assert_eq!(decided(HTTP2_PREFACE), WireProtocol::Http2Preface);
        assert_eq!(decided(b"SSH-2.0-OpenSSH_9.6\r\n"), WireProtocol::Ssh);
        assert_eq!(decided(b"SSH-1.99-Cisco\r\n"), WireProtocol::Ssh);
        assert_eq!(
            decided(&[0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00]),
            WireProtocol::Tls
        );
    }

    #[test]
    fn h2_preface_wins_over_the_http1_reading() {
        // "PRI " looks like an HTTP/1 method token. Checking HTTP/1
        // first would misroute every prior-knowledge h2 connection.
        assert_eq!(decided(HTTP2_PREFACE), WireProtocol::Http2Preface);
        // A prefix of the preface must not be decided either way.
        assert_eq!(
            classify_first_bytes(b"PRI * HTTP/2.0\r\n"),
            Classify::NeedMore
        );
    }

    #[test]
    fn short_peeks_never_decide_wrongly() {
        // Every prefix of a valid input either waits or agrees with
        // the full input's answer.
        let inputs: &[&[u8]] = &[
            b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n",
            b"CONNECT example.com:443 HTTP/1.1\r\n\r\n",
            HTTP2_PREFACE,
            b"SSH-2.0-OpenSSH_9.6\r\n",
            &[0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc],
        ];
        for full in inputs {
            let answer = decided(full);
            for n in 1..full.len() {
                match classify_first_bytes(&full[..n]) {
                    Classify::NeedMore => {}
                    Classify::Decided(p) => assert_eq!(
                        p, answer,
                        "prefix of length {n} of {full:?} decided differently"
                    ),
                }
            }
        }
    }

    #[test]
    fn empty_peek_waits() {
        assert_eq!(classify_first_bytes(b""), Classify::NeedMore);
    }

    #[test]
    fn unrecognised_bytes_settle_on_raw() {
        assert_eq!(
            decided(b"\x00\x01\x02\x03\x04\x05\x06\x07\x08"),
            WireProtocol::Raw
        );
        assert_eq!(decided(b"HELO mail.example.com\r\n"), WireProtocol::Raw);
        // A single byte that cannot start anything known is settled.
        assert_eq!(decided(b"\xff"), WireProtocol::Raw);
    }

    #[test]
    fn lowercase_methods_are_not_http() {
        // RFC 9110 §9.1: methods are case-sensitive. Accepting
        // lowercase here would disagree with a backend that does not.
        assert_eq!(decided(b"get / HTTP/1.1\r\n"), WireProtocol::Raw);
    }

    #[test]
    fn non_handshake_tls_record_is_raw() {
        // 0x16 is handshake; anything else on a first byte is not a
        // ClientHello, and a handshake record whose body does not
        // start with ClientHello is not one either.
        assert_eq!(
            decided(&[0x16, 0x03, 0x01, 0x00, 0x10, 0x02]),
            WireProtocol::Raw
        );
        assert_eq!(
            decided(&[0x17, 0x03, 0x03, 0x00, 0x10, 0x01]),
            WireProtocol::Raw
        );
    }

    #[test]
    fn slugs_are_stable() {
        assert_eq!(WireProtocol::Tls.as_str(), "tls");
        assert_eq!(WireProtocol::Http1.as_str(), "http1");
        assert_eq!(WireProtocol::Http2Preface.as_str(), "http2-preface");
        assert_eq!(WireProtocol::Ssh.as_str(), "ssh");
        assert_eq!(WireProtocol::Raw.as_str(), "raw");
    }

    #[test]
    fn never_panics_on_arbitrary_input() {
        for len in 0..40usize {
            for seed in 0..8u8 {
                let bytes: Vec<u8> = (0..len).map(|i| (i as u8).wrapping_mul(seed)).collect();
                let _ = classify_first_bytes(&bytes);
            }
        }
    }
}

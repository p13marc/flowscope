//! Magic-byte protocol recognizers for the protocols flowscope
//! ships parsers for + the handful of widely-deployed text /
//! framed protocols beyond.
//!
//! Each signature has the shape:
//!
//! ```rust,ignore
//! fn http_request(bytes: &[u8]) -> SignatureMatch;
//! ```
//!
//! and returns one of [`SignatureMatch::Match`] /
//! [`SignatureMatch::NoMatch`] / [`SignatureMatch::NeedMoreData`].
//! Pure functions, no state, no allocation — suitable for
//! hot-path dispatch.
//!
//! Each signature is intentionally strict — multiple
//! discriminator bytes per protocol, false-positive resistant.
//! Wireshark-style: "use strict signatures with multiple
//! confirmation bytes."
//!
//! New in 0.10.0 (plan 113 sub-A).
//!
//! ```
//! use flowscope::detect::signatures::{http_request, SignatureMatch};
//!
//! assert_eq!(http_request(b"GET / HTTP/1.1\r\n"), SignatureMatch::Match);
//! assert_eq!(http_request(b"GET "), SignatureMatch::NeedMoreData);
//! assert_eq!(http_request(b"XYZ"), SignatureMatch::NoMatch);
//! ```

/// Result of a signature evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureMatch {
    /// Bytes definitively match this protocol.
    Match,
    /// Bytes definitively do not match.
    NoMatch,
    /// Not enough bytes to decide — re-check with more. Bytes
    /// seen so far are a valid prefix of a match.
    NeedMoreData,
}

/// Signature function type — `fn(&[u8]) -> SignatureMatch`.
pub type SignatureFn = fn(&[u8]) -> SignatureMatch;

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

/// The HTTP/2 client connection preface (RFC 9113 §3.4).
///
/// A client opens every h2 connection with the same 24 bytes, so this
/// is the one signature in this module that is exact rather than
/// heuristic — either the bytes are the preface or they are not.
///
/// Pair it with [`Http2Session`](crate::http2::Http2Session) on a
/// heuristic slot: the session tolerates a *missing* preface
/// precisely so a flow pinned this way still parses if the driver
/// only saw the tail of it.
///
/// Ordering note for a router that tries several signatures: check
/// this before [`http_request`]. `PRI` is a syntactically valid
/// HTTP/1 method token, and although [`http_request`] does not list
/// it, a looser HTTP/1 matcher would claim the preface.
///
/// ```
/// use flowscope::detect::signatures::{http2_preface, SignatureMatch};
///
/// let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
/// assert_eq!(http2_preface(preface), SignatureMatch::Match);
/// assert_eq!(http2_preface(b"PRI * HTTP/2"), SignatureMatch::NeedMoreData);
/// assert_eq!(http2_preface(b"GET / HTTP/1.1"), SignatureMatch::NoMatch);
/// ```
pub fn http2_preface(bytes: &[u8]) -> SignatureMatch {
    let preface = crate::classify::HTTP2_PREFACE;
    let n = bytes.len().min(preface.len());
    if bytes[..n] != preface[..n] {
        // Definitive, at the first differing byte — a heuristic slot
        // can stop probing rather than burn its whole budget.
        return SignatureMatch::NoMatch;
    }
    if bytes.len() < preface.len() {
        // A valid prefix. The preface is 24 bytes and routinely
        // splits across segments.
        return SignatureMatch::NeedMoreData;
    }
    SignatureMatch::Match
}

/// HTTP/1.x request: method + path + `HTTP/1.` within first 256 B.
pub fn http_request(bytes: &[u8]) -> SignatureMatch {
    if bytes.is_empty() {
        return SignatureMatch::NeedMoreData;
    }
    // If we have at least the longest method header, check whether
    // we start with one. Otherwise, we may still be a valid prefix.
    let prefix_compatible = HTTP_METHODS.iter().any(|m| {
        if bytes.len() >= m.len() {
            bytes.starts_with(m)
        } else {
            m.starts_with(bytes)
        }
    });
    if !prefix_compatible {
        return SignatureMatch::NoMatch;
    }
    // Need at least "GET / HTTP/1.0\r\n" worth of bytes to confirm.
    if bytes.len() < 16 {
        return SignatureMatch::NeedMoreData;
    }
    if !HTTP_METHODS.iter().any(|m| bytes.starts_with(m)) {
        return SignatureMatch::NoMatch;
    }
    let scan_limit = bytes.len().min(256);
    if bytes[..scan_limit].windows(7).any(|w| w == b"HTTP/1.") {
        SignatureMatch::Match
    } else {
        SignatureMatch::NeedMoreData
    }
}

/// HTTP/1.x response: starts with `HTTP/1.` + space + 3-digit code.
pub fn http_response(bytes: &[u8]) -> SignatureMatch {
    if bytes.is_empty() {
        return SignatureMatch::NeedMoreData;
    }
    if bytes.len() < b"HTTP/1.0 200 ".len() {
        if b"HTTP/1.".starts_with(bytes) || bytes.starts_with(b"HTTP/1.") {
            return SignatureMatch::NeedMoreData;
        }
        return SignatureMatch::NoMatch;
    }
    if !bytes.starts_with(b"HTTP/1.") {
        return SignatureMatch::NoMatch;
    }
    if bytes[8] != b' ' {
        return SignatureMatch::NoMatch;
    }
    if !bytes[9..12].iter().all(|c| c.is_ascii_digit()) {
        return SignatureMatch::NoMatch;
    }
    SignatureMatch::Match
}

/// TLS ClientHello: handshake record type 0x16 + valid record
/// version + ClientHello message type 0x01.
pub fn tls_client_hello(bytes: &[u8]) -> SignatureMatch {
    if bytes.is_empty() {
        return SignatureMatch::NeedMoreData;
    }
    if bytes[0] != 0x16 {
        return SignatureMatch::NoMatch;
    }
    if bytes.len() < 6 {
        return SignatureMatch::NeedMoreData;
    }
    let version = u16::from_be_bytes([bytes[1], bytes[2]]);
    if !(0x0301..=0x0303).contains(&version) {
        return SignatureMatch::NoMatch;
    }
    if bytes[5] != 0x01 {
        return SignatureMatch::NoMatch;
    }
    SignatureMatch::Match
}

/// TLS ServerHello: 0x16 handshake type + version + ServerHello
/// message type 0x02.
pub fn tls_server_hello(bytes: &[u8]) -> SignatureMatch {
    if bytes.is_empty() {
        return SignatureMatch::NeedMoreData;
    }
    if bytes[0] != 0x16 {
        return SignatureMatch::NoMatch;
    }
    if bytes.len() < 6 {
        return SignatureMatch::NeedMoreData;
    }
    let version = u16::from_be_bytes([bytes[1], bytes[2]]);
    if !(0x0301..=0x0303).contains(&version) {
        return SignatureMatch::NoMatch;
    }
    if bytes[5] != 0x02 {
        return SignatureMatch::NoMatch;
    }
    SignatureMatch::Match
}

/// SSH banner: `SSH-N.M-…`.
pub fn ssh_banner(bytes: &[u8]) -> SignatureMatch {
    if bytes.is_empty() {
        return SignatureMatch::NeedMoreData;
    }
    if bytes.len() < 4 {
        if !b"SSH-".starts_with(bytes) {
            return SignatureMatch::NoMatch;
        }
        return SignatureMatch::NeedMoreData;
    }
    if !bytes.starts_with(b"SSH-") {
        return SignatureMatch::NoMatch;
    }
    if bytes.len() < 8 {
        return SignatureMatch::NeedMoreData;
    }
    if !(bytes[4].is_ascii_digit() && bytes[5] == b'.') {
        return SignatureMatch::NoMatch;
    }
    SignatureMatch::Match
}

/// DNS message: 12-byte header with QDCOUNT > 0 and reasonable
/// flags.
pub fn dns_message(bytes: &[u8]) -> SignatureMatch {
    if bytes.len() < 12 {
        return SignatureMatch::NeedMoreData;
    }
    // Flags byte 2 has opcode in bits 3-6 (mask 0x78). Opcodes
    // 0 (QUERY), 1 (IQUERY), 2 (STATUS), 4 (NOTIFY), 5 (UPDATE) are
    // valid; everything else is invalid.
    let opcode = (bytes[2] >> 3) & 0x0f;
    if !matches!(opcode, 0 | 1 | 2 | 4 | 5) {
        return SignatureMatch::NoMatch;
    }
    let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]);
    if qdcount == 0 || qdcount > 16 {
        return SignatureMatch::NoMatch;
    }
    SignatureMatch::Match
}

/// SMTP banner: `220 ` (greeting) or `220-` (multi-line).
pub fn smtp_banner(bytes: &[u8]) -> SignatureMatch {
    if bytes.is_empty() {
        return SignatureMatch::NeedMoreData;
    }
    if bytes.len() < 4 {
        if b"220 ".starts_with(bytes) || b"220-".starts_with(bytes) {
            return SignatureMatch::NeedMoreData;
        }
        return SignatureMatch::NoMatch;
    }
    if bytes.starts_with(b"220 ") || bytes.starts_with(b"220-") {
        SignatureMatch::Match
    } else {
        SignatureMatch::NoMatch
    }
}

/// FTP banner: `220 ` / `220-` (control channel greeting).
pub fn ftp_banner(bytes: &[u8]) -> SignatureMatch {
    smtp_banner(bytes)
}

/// IRC message: starts with `NICK`, `USER`, `PASS`, or `:server`
/// prefix.
pub fn irc_message(bytes: &[u8]) -> SignatureMatch {
    if bytes.is_empty() {
        return SignatureMatch::NeedMoreData;
    }
    const STARTS: &[&[u8]] = &[b"NICK ", b"USER ", b"PASS ", b":"];
    let compatible = STARTS.iter().any(|s| {
        if bytes.len() >= s.len() {
            bytes.starts_with(s)
        } else {
            s.starts_with(bytes)
        }
    });
    if !compatible {
        return SignatureMatch::NoMatch;
    }
    if bytes.len() < 5 {
        return SignatureMatch::NeedMoreData;
    }
    if STARTS.iter().any(|s| bytes.starts_with(s)) {
        SignatureMatch::Match
    } else {
        SignatureMatch::NoMatch
    }
}

/// Redis RESP: starts with `+`, `-`, `:`, `$`, or `*`. Strict —
/// reject empty or non-RESP first byte.
pub fn redis_resp(bytes: &[u8]) -> SignatureMatch {
    if bytes.is_empty() {
        return SignatureMatch::NeedMoreData;
    }
    if matches!(bytes[0], b'+' | b'-' | b':' | b'$' | b'*') {
        if bytes.len() < 4 {
            // Need a CRLF or close to it to commit.
            return SignatureMatch::NeedMoreData;
        }
        // For the framing types ($ *), the next bytes should
        // describe a length: digits + optionally `-`.
        if matches!(bytes[0], b'$' | b'*') && !bytes[1].is_ascii_digit() && bytes[1] != b'-' {
            return SignatureMatch::NoMatch;
        }
        return SignatureMatch::Match;
    }
    SignatureMatch::NoMatch
}

/// MQTT CONNECT: first byte 0x10 (CONNECT control packet) and
/// protocol name `MQTT` or `MQIsdp` in the variable header.
pub fn mqtt_connect(bytes: &[u8]) -> SignatureMatch {
    if bytes.is_empty() {
        return SignatureMatch::NeedMoreData;
    }
    // First byte: 0x10 (CONNECT, flags zero).
    if bytes[0] != 0x10 {
        return SignatureMatch::NoMatch;
    }
    // Need: 1B type + 1-4B remaining length + 2B name len + 4-6B name.
    if bytes.len() < 12 {
        return SignatureMatch::NeedMoreData;
    }
    // Scan for "MQTT" or "MQIsdp" within first 20 bytes.
    let scan_limit = bytes.len().min(20);
    let has_mqtt = bytes[..scan_limit].windows(4).any(|w| w == b"MQTT");
    let has_legacy = bytes[..scan_limit].windows(6).any(|w| w == b"MQIsdp");
    if has_mqtt || has_legacy {
        SignatureMatch::Match
    } else {
        SignatureMatch::NoMatch
    }
}

/// Postgres startup message: first 4 bytes encode the message
/// length (≥ 8 ≤ 10_000), next 4 bytes encode protocol version
/// 3.0 = 0x00030000.
pub fn postgres_startup(bytes: &[u8]) -> SignatureMatch {
    if bytes.len() < 8 {
        return SignatureMatch::NeedMoreData;
    }
    let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if !(8..=10_000).contains(&len) {
        return SignatureMatch::NoMatch;
    }
    let version = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    // Protocol 3.0 (most common) or SSLRequest (80877103).
    if version == 0x0003_0000 || version == 80877103 {
        SignatureMatch::Match
    } else {
        SignatureMatch::NoMatch
    }
}

/// Curated `(parser_kind, signature)` table.
///
/// `parser_kind` strings align with the [`ParserKind`](crate::ParserKind)
/// slug vocabulary where applicable so signature matches dispatch
/// back to the existing parsers.
pub fn registry() -> impl Iterator<Item = (&'static str, SignatureFn)> {
    [
        ("http", http_request as SignatureFn),
        ("http2", http2_preface as SignatureFn),
        ("tls", tls_client_hello as SignatureFn),
        ("dns-udp", dns_message as SignatureFn),
        ("ssh", ssh_banner as SignatureFn),
        ("smtp", smtp_banner as SignatureFn),
        ("ftp", ftp_banner as SignatureFn),
        ("irc", irc_message as SignatureFn),
        ("redis-resp", redis_resp as SignatureFn),
        ("mqtt", mqtt_connect as SignatureFn),
        ("postgres", postgres_startup as SignatureFn),
    ]
    .into_iter()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_table(sig: SignatureFn, examples: &[(&[u8], SignatureMatch)]) {
        for (bytes, expected) in examples {
            assert_eq!(
                sig(bytes),
                *expected,
                "{} expected {:?}",
                String::from_utf8_lossy(bytes),
                expected,
            );
        }
    }

    #[test]
    fn http_request_signature() {
        assert_table(
            http_request,
            &[
                (b"GET / HTTP/1.1\r\n", SignatureMatch::Match),
                (b"POST /a HTTP/1.0\r\n", SignatureMatch::Match),
                (b"GET ", SignatureMatch::NeedMoreData),
                (b"GE", SignatureMatch::NeedMoreData),
                (b"XYZ", SignatureMatch::NoMatch),
                (&[0x16, 0x03, 0x01], SignatureMatch::NoMatch),
                (b"GET /index.html ", SignatureMatch::NeedMoreData),
            ],
        );
    }

    #[test]
    fn http_response_signature() {
        assert_table(
            http_response,
            &[
                (b"HTTP/1.1 200 OK\r\n", SignatureMatch::Match),
                (b"HTTP/1.0 404 Not Found\r\n", SignatureMatch::Match),
                (b"HTTP/1.", SignatureMatch::NeedMoreData),
                (b"GET / HTTP/1.1", SignatureMatch::NoMatch),
            ],
        );
    }

    #[test]
    fn tls_client_hello_signature() {
        assert_table(
            tls_client_hello,
            &[
                (&[0x16, 0x03, 0x01, 0x00, 0x42, 0x01], SignatureMatch::Match),
                (&[0x16, 0x03, 0x03, 0x00, 0x42, 0x01], SignatureMatch::Match),
                (
                    &[0x16, 0x03, 0x04, 0x00, 0x42, 0x01],
                    SignatureMatch::NoMatch,
                ),
                (
                    &[0x17, 0x03, 0x01, 0x00, 0x42, 0x01],
                    SignatureMatch::NoMatch,
                ),
                (&[0x16, 0x03], SignatureMatch::NeedMoreData),
                (b"GET / HTTP/1.1", SignatureMatch::NoMatch),
            ],
        );
    }

    #[test]
    fn tls_server_hello_signature() {
        assert_table(
            tls_server_hello,
            &[(&[0x16, 0x03, 0x03, 0x00, 0x42, 0x02], SignatureMatch::Match)],
        );
        // ClientHello bytes are rejected.
        assert_eq!(
            tls_server_hello(&[0x16, 0x03, 0x03, 0x00, 0x42, 0x01]),
            SignatureMatch::NoMatch
        );
    }

    #[test]
    fn ssh_banner_signature() {
        assert_table(
            ssh_banner,
            &[
                (b"SSH-2.0-OpenSSH_8.0\r\n", SignatureMatch::Match),
                (b"SSH-1.99-foo", SignatureMatch::Match),
                (b"SSH-", SignatureMatch::NeedMoreData),
                (b"SS", SignatureMatch::NeedMoreData),
                (b"FOO", SignatureMatch::NoMatch),
            ],
        );
    }

    #[test]
    fn dns_message_signature() {
        // Header: id=1234, flags=0x0100 (recursion desired), qdcount=1, ancount=0, nscount=0, arcount=0.
        let bytes = [
            0x04, 0xd2, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(dns_message(&bytes), SignatureMatch::Match);
        // Too short.
        assert_eq!(dns_message(&bytes[..8]), SignatureMatch::NeedMoreData);
        // Bad opcode (15 = invalid).
        let mut bad = bytes;
        bad[2] = 0x78; // opcode = 15
        assert_eq!(dns_message(&bad), SignatureMatch::NoMatch);
    }

    #[test]
    fn smtp_banner_signature() {
        assert_table(
            smtp_banner,
            &[
                (b"220 smtp.example.com ESMTP\r\n", SignatureMatch::Match),
                (b"220-multi\r\n", SignatureMatch::Match),
                (b"220", SignatureMatch::NeedMoreData),
                (b"HELO foo", SignatureMatch::NoMatch),
            ],
        );
    }

    #[test]
    fn irc_message_signature() {
        assert_table(
            irc_message,
            &[
                (b"NICK foo\r\n", SignatureMatch::Match),
                (b"USER me\r\n", SignatureMatch::Match),
                (b":server PING\r\n", SignatureMatch::Match),
                (b"NICK", SignatureMatch::NeedMoreData),
                (b"XXX", SignatureMatch::NoMatch),
            ],
        );
    }

    #[test]
    fn redis_resp_signature() {
        assert_table(
            redis_resp,
            &[
                (b"+OK\r\n", SignatureMatch::Match),
                (b"-ERR foo\r\n", SignatureMatch::Match),
                (b":1234\r\n", SignatureMatch::Match),
                (b"$5\r\nhello\r\n", SignatureMatch::Match),
                (b"*3\r\n", SignatureMatch::Match),
                (b"$X\r\n", SignatureMatch::NoMatch),
                (b"+", SignatureMatch::NeedMoreData),
                (b"X", SignatureMatch::NoMatch),
            ],
        );
    }

    #[test]
    fn mqtt_connect_signature() {
        // 0x10 + remaining length 14 + 4-byte name "MQTT".
        let bytes = [
            0x10, 0x0E, 0x00, 0x04, b'M', b'Q', b'T', b'T', 0x04, 0x02, 0x00, 0x3C, 0x00, 0x00,
        ];
        assert_eq!(mqtt_connect(&bytes), SignatureMatch::Match);
        // Non-CONNECT type byte.
        assert_eq!(mqtt_connect(&[0x20, 0x0E][..]), SignatureMatch::NoMatch);
        // Too short.
        assert_eq!(mqtt_connect(&[0x10][..]), SignatureMatch::NeedMoreData);
    }

    #[test]
    fn postgres_startup_signature() {
        // Length 16 + version 3.0 + dummy 8 bytes user.
        let mut bytes = vec![];
        bytes.extend_from_slice(&16u32.to_be_bytes());
        bytes.extend_from_slice(&0x0003_0000u32.to_be_bytes());
        bytes.extend_from_slice(b"user");
        assert_eq!(postgres_startup(&bytes), SignatureMatch::Match);
        // SSLRequest.
        let ssl = {
            let mut v = vec![];
            v.extend_from_slice(&8u32.to_be_bytes());
            v.extend_from_slice(&80877103u32.to_be_bytes());
            v
        };
        assert_eq!(postgres_startup(&ssl), SignatureMatch::Match);
        // Bad length.
        let bad = vec![0u8; 8];
        assert_eq!(postgres_startup(&bad), SignatureMatch::NoMatch);
    }

    #[test]
    fn registry_lists_eleven_signatures() {
        let count = registry().count();
        assert_eq!(count, 11);
    }

    #[test]
    fn http2_preface_table() {
        let preface = crate::classify::HTTP2_PREFACE;
        assert_table(
            http2_preface,
            &[
                (preface, SignatureMatch::Match),
                // Every proper prefix is undecided, never a match.
                (b"", SignatureMatch::NeedMoreData),
                (b"P", SignatureMatch::NeedMoreData),
                (b"PRI * HTTP/2.0\r\n\r\n", SignatureMatch::NeedMoreData),
                // One byte short.
                (&preface[..preface.len() - 1], SignatureMatch::NeedMoreData),
                // Definitively not h2.
                (b"GET / HTTP/1.1\r\n", SignatureMatch::NoMatch),
                (b"PRX * HTTP/2.0", SignatureMatch::NoMatch),
                // The right length, one wrong byte at the very end —
                // the case a length-only check would wave through.
                (
                    b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\x00",
                    SignatureMatch::NoMatch,
                ),
                (&[0u8; 24], SignatureMatch::NoMatch),
            ],
        );
        // Trailing bytes after a complete preface still match: a real
        // connection sends SETTINGS immediately after it.
        let mut with_tail = preface.to_vec();
        with_tail.extend_from_slice(&[0, 0, 0, 0x4, 0, 0, 0, 0, 0]);
        assert_eq!(http2_preface(&with_tail), SignatureMatch::Match);
    }

    /// A router tries signatures in order, so the preface must not be
    /// claimed by anything else — otherwise an h2 connection pins to
    /// the wrong parser and every byte after is misread.
    #[test]
    fn no_other_signature_claims_the_h2_preface() {
        let preface = crate::classify::HTTP2_PREFACE;
        for (name, sig) in registry() {
            if name == "http2" {
                continue;
            }
            assert_ne!(
                sig(preface),
                SignatureMatch::Match,
                "{name} claimed the HTTP/2 preface"
            );
        }
    }

    #[test]
    fn splitting_invariance_http2_preface() {
        // A prefix must never decide differently from the whole: the
        // property a heuristic slot depends on when the preface
        // arrives across segments.
        let preface = crate::classify::HTTP2_PREFACE;
        for end in 0..preface.len() {
            assert_eq!(
                http2_preface(&preface[..end]),
                SignatureMatch::NeedMoreData,
                "prefix of {end} bytes must stay undecided"
            );
        }
        assert_eq!(http2_preface(preface), SignatureMatch::Match);
    }

    #[test]
    fn splitting_invariance_http_request() {
        let bytes = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        for end in 1..=bytes.len() {
            let prefix = &bytes[..end];
            let result = http_request(prefix);
            assert_ne!(
                result,
                SignatureMatch::NoMatch,
                "prefix len {end} returned NoMatch unexpectedly: {prefix:?}",
            );
        }
    }

    #[test]
    fn splitting_invariance_tls_client_hello() {
        let bytes = [0x16, 0x03, 0x03, 0x00, 0x42, 0x01, 0x00, 0x00, 0x42];
        for end in 1..=bytes.len() {
            let prefix = &bytes[..end];
            let result = tls_client_hello(prefix);
            assert_ne!(
                result,
                SignatureMatch::NoMatch,
                "prefix len {end} returned NoMatch unexpectedly",
            );
        }
    }
}

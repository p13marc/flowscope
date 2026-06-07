use bytes::Bytes;

/// Parsed HTTP/1.x request — start line + headers + body.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub version: HttpVersion,
    /// Header (name, value) pairs in order. Names are ASCII;
    /// values are bytes (RFC 7230 §3.2.4 allows any byte).
    pub headers: Vec<(String, Vec<u8>)>,
    /// Body bytes. Empty if no body or transfer-encoding only signals
    /// EOF semantics with nothing transferred yet.
    pub body: Bytes,
}

/// Parsed HTTP/1.x response.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct HttpResponse {
    pub status: u16,
    pub reason: String,
    pub version: HttpVersion,
    pub headers: Vec<(String, Vec<u8>)>,
    pub body: Bytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum HttpVersion {
    Http1_0,
    Http1_1,
}

// ── Plan 78: convenience header accessors ─────────────────────────
//
// Every HTTP monitor against 0.6 ended up writing
//     find(|(k, _)| k.eq_ignore_ascii_case("host"))
//         .and_then(|(_, v)| std::str::from_utf8(v).ok())
// — repeated across `Host`, `User-Agent`, `Cookie`, `Content-Type`,
// `Content-Length`, `Set-Cookie`. The accessors below collapse the
// dance for the modal cases and ship a generic `header(name)` for
// everything else.

impl HttpRequest {
    /// `Host:` header value as UTF-8. `None` if absent or
    /// non-UTF-8.
    pub fn host(&self) -> Option<&str> {
        self.header_str("host")
    }

    /// `User-Agent:` header value as UTF-8.
    pub fn user_agent(&self) -> Option<&str> {
        self.header_str("user-agent")
    }

    /// `Cookie:` header value as UTF-8 (raw — no parsing into
    /// `name=value` pairs). Route through a downstream cookie
    /// crate for parsing.
    pub fn cookie(&self) -> Option<&str> {
        self.header_str("cookie")
    }

    /// First match (case-insensitive) for an arbitrary header.
    /// HTTP/1.x allows duplicates; this returns the first
    /// observed. For multi-valued headers use
    /// [`headers_all`](Self::headers_all).
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        header_lookup(&self.headers, name).next()
    }

    /// All matches (case-insensitive) for an arbitrary header
    /// in observation order.
    pub fn headers_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> + 'a {
        header_lookup(&self.headers, name)
    }

    fn header_str(&self, name: &str) -> Option<&str> {
        self.header(name).and_then(|v| std::str::from_utf8(v).ok())
    }
}

impl HttpResponse {
    /// `Content-Type:` header value as UTF-8.
    pub fn content_type(&self) -> Option<&str> {
        self.header_str("content-type")
    }

    /// `Content-Length:` header value parsed as `u64`. `None`
    /// if absent, non-UTF-8, or non-numeric.
    pub fn content_length(&self) -> Option<u64> {
        self.header_str("content-length")
            .and_then(|v| v.trim().parse().ok())
    }

    /// All `Set-Cookie:` header values as UTF-8, in observation
    /// order. HTTP/1.x servers can set multiple cookies via
    /// repeated headers.
    pub fn set_cookie(&self) -> impl Iterator<Item = &str> + '_ {
        self.headers_all("set-cookie")
            .filter_map(|v| std::str::from_utf8(v).ok())
    }

    /// First match (case-insensitive) for an arbitrary header.
    /// Mirror of [`HttpRequest::header`].
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        header_lookup(&self.headers, name).next()
    }

    /// All matches (case-insensitive) for an arbitrary header.
    /// Mirror of [`HttpRequest::headers_all`].
    pub fn headers_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> + 'a {
        header_lookup(&self.headers, name)
    }

    fn header_str(&self, name: &str) -> Option<&str> {
        self.header(name).and_then(|v| std::str::from_utf8(v).ok())
    }
}

/// Case-insensitive header iterator. Pulled out so request and
/// response share one implementation. RFC 7230 §3.2 mandates
/// case-insensitive matching on header names.
///
/// Two lifetimes because the yielded values borrow from
/// `headers` (`'h`) but the comparison key `name` (`'n`) is a
/// short-lived caller-supplied string slice — they're not
/// constrained to the same scope.
fn header_lookup<'h, 'n>(
    headers: &'h [(String, Vec<u8>)],
    name: &'n str,
) -> impl Iterator<Item = &'h [u8]> + use<'h, 'n> {
    headers
        .iter()
        .filter(move |(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_slice())
}

/// Configuration knobs for the HTTP parser.
#[derive(Debug, Clone)]
pub struct HttpConfig {
    /// Cap on the buffered bytes per direction. Once exceeded the
    /// reassembler drops the per-flow buffer to recover memory; the
    /// flow continues at TCP level but HTTP for that direction is
    /// considered desynced.
    pub max_buffer: usize,
    /// Cap on number of headers per message. Default: 64.
    pub max_headers: usize,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            max_buffer: 1024 * 1024, // 1 MiB
            max_headers: 64,
        }
    }
}

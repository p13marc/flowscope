use bytes::Bytes;

use super::poison::HttpPoison;

/// Parsed HTTP/1.x request — start line + headers + body.
///
/// All `Bytes` fields slice into one shared backing store per
/// parsed message — zero-copy after parsing. Plan 120: was
/// `String` / `Vec<u8>` in 0.10.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct HttpRequest {
    /// Method bytes (typically uppercase ASCII like `GET`, `POST`).
    pub method: Bytes,
    /// Request-target (path + query string).
    pub path: Bytes,
    pub version: HttpVersion,
    /// Header (name, value) pairs in order. Names are ASCII per
    /// RFC 7230 §3.2 (case-insensitive). Values are arbitrary
    /// bytes per §3.2.4.
    pub headers: Vec<(Bytes, Bytes)>,
    /// Body bytes. Empty if no body or transfer-encoding only signals
    /// EOF semantics with nothing transferred yet.
    pub body: Bytes,
}

/// Parsed HTTP/1.x response.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct HttpResponse {
    pub status: u16,
    /// Reason phrase from the status line.
    pub reason: Bytes,
    pub version: HttpVersion,
    pub headers: Vec<(Bytes, Bytes)>,
    pub body: Bytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum HttpVersion {
    Http1_0,
    Http1_1,
}

/// How a message body is delimited on the wire — decided from the
/// headers at header-completion time, before any body byte is read.
///
/// The parser needs this to know where a message ends and the next
/// one begins; an inline proxy needs it to stream the body itself.
/// For responses it is computed using the matching request's method,
/// per RFC 9112 §6.3 rules 1–2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum BodyFraming {
    /// No body: an explicit `Content-Length: 0`, a request with
    /// neither `Content-Length` nor `Transfer-Encoding` (§6.3 rule
    /// 6), or a response that cannot carry one (`HEAD`, `1xx`,
    /// `204`, `304` — §6.3 rules 1–2).
    None,
    /// `Content-Length: n` — exactly `n` body bytes follow.
    ContentLength(u64),
    /// `Transfer-Encoding: chunked` — chunk-framed body follows,
    /// terminated by a zero-size chunk and a trailer section.
    Chunked,
    /// Neither length nor chunked framing: the body extends to the
    /// connection close. Responses only — typical of HTTP/1.0.
    UntilClose,
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
    /// Construct an HTTP request.
    pub fn new(
        method: Bytes,
        path: Bytes,
        version: HttpVersion,
        headers: Vec<(Bytes, Bytes)>,
        body: Bytes,
    ) -> Self {
        Self {
            method,
            path,
            version,
            headers,
            body,
        }
    }

    /// Method as a UTF-8 `&str` (e.g. `"GET"`). `None` if the
    /// method bytes are not valid UTF-8 (extremely rare).
    pub fn method_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.method).ok()
    }

    /// Path as a UTF-8 `&str`.
    pub fn path_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.path).ok()
    }

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

    /// `Referer:` header value as UTF-8. New in 0.10.0.
    pub fn referer(&self) -> Option<&str> {
        self.header_str("referer")
    }

    /// `Accept:` header value as UTF-8 (raw, not parsed into
    /// media-range list). New in 0.10.0.
    pub fn accept(&self) -> Option<&str> {
        self.header_str("accept")
    }

    /// `Content-Type:` header value as UTF-8 (mirror of
    /// [`HttpResponse::content_type`]). New in 0.10.0.
    pub fn content_type(&self) -> Option<&str> {
        self.header_str("content-type")
    }

    /// `Content-Length:` header value parsed as `u64`. `None`
    /// if absent, non-UTF-8, or non-numeric. Mirror of
    /// [`HttpResponse::content_length`]. New in 0.10.0.
    pub fn content_length(&self) -> Option<u64> {
        self.header_str("content-length")
            .and_then(|v| v.trim().parse().ok())
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
    /// Construct an HTTP response.
    pub fn new(
        status: u16,
        reason: Bytes,
        version: HttpVersion,
        headers: Vec<(Bytes, Bytes)>,
        body: Bytes,
    ) -> Self {
        Self {
            status,
            reason,
            version,
            headers,
            body,
        }
    }

    /// Reason phrase as a UTF-8 `&str` (e.g. `"OK"`).
    pub fn reason_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.reason).ok()
    }

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

    /// Status class — `status / 100`. Returns `None` only if the
    /// status falls outside `[100, 599]`. New in 0.10.0.
    pub fn status_class(&self) -> Option<u8> {
        let cls = self.status / 100;
        if (1..=5).contains(&cls) {
            Some(cls as u8)
        } else {
            None
        }
    }

    /// `2xx` predicate. New in 0.10.0.
    pub fn is_success(&self) -> bool {
        self.status_class() == Some(2)
    }

    /// `3xx` predicate. New in 0.10.0.
    pub fn is_redirect(&self) -> bool {
        self.status_class() == Some(3)
    }

    /// `4xx` predicate. New in 0.10.0.
    pub fn is_client_error(&self) -> bool {
        self.status_class() == Some(4)
    }

    /// `5xx` predicate. New in 0.10.0.
    pub fn is_server_error(&self) -> bool {
        self.status_class() == Some(5)
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

/// How strictly the parser treats an ambiguously framed message.
///
/// RFC 9112 §6.3 leaves several situations where two recipients can
/// legitimately disagree about where a message ends — and a
/// disagreement between a proxy and its backend *is* request
/// smuggling. This selects what to do about them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum SmugglingPolicy {
    /// Any ambiguity poisons the connection. The default for an
    /// inline proxy: refusing to forward is the only response that
    /// cannot be exploited.
    Strict,
    /// Apply the normalizations RFC 9112 §6.3.3 mandates — dropping
    /// `Content-Length` when `Transfer-Encoding` is present,
    /// collapsing a repeated but identical length — and record them
    /// on the head. Anything that cannot be made unambiguous still
    /// poisons.
    ///
    /// A message with a recorded normalization **must not be
    /// forwarded from its `raw` bytes**: `raw` is what arrived, and
    /// forwarding it would hand the backend the same ambiguity.
    /// Re-serialize from the parsed headers instead.
    Normalize,
    /// Never poison: frame on a best-effort basis and keep observing.
    /// This is what passive telemetry uses — an observer that drops
    /// a flow because a client sent something odd is a worse
    /// observer, and it is not in a position to be exploited.
    Observe,
}

/// A change the parser made to an ambiguously framed message under
/// [`SmugglingPolicy::Normalize`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum Normalization {
    /// `Content-Length` was dropped because `Transfer-Encoding` was
    /// also present; the body is chunk-framed (RFC 9112 §6.3.3).
    StrippedContentLength,
    /// Several `Content-Length` values agreed and were collapsed to
    /// one.
    CollapsedContentLength,
}

/// The authority a request should be routed to.
///
/// [`host`](Self::host) is lowercased **with ASCII rules only**.
/// Unicode case folding is not safe here: U+212A KELVIN SIGN folds to
/// `k`, so `EXAMPLE.COM` spelled with a Kelvin sign would route as
/// `example.com` on one hop and not another.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Authority {
    /// Exactly as it appeared on the wire.
    pub raw: Bytes,
    /// ASCII-lowercased host, without the port.
    pub host: String,
    /// Explicit port, if the authority carried one.
    pub port: Option<u16>,
}

/// What a protocol switch handed the connection over to. After one of
/// these the parser stops: the caller splices the remaining bytes
/// through untouched.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SwitchKind {
    /// A `2xx` to `CONNECT` — the rest of the connection is a tunnel.
    ConnectTunnel,
    /// `101 Switching Protocols`; the token from the `Upgrade` header
    /// (for example `websocket`).
    Upgrade { protocol: Bytes },
    /// The HTTP/2 connection preface appeared where a request was
    /// expected — a prior-knowledge h2 client.
    Http2PriorKnowledge,
}

/// Request start line + headers, surfaced by the streaming parser at
/// header-completion time — *before* the body.
///
/// This is the routing-time view an inline proxy needs: everything
/// required to pick a backend (method, target, `Host`, all headers)
/// plus the [`framing`](Self::framing) describing how the body is
/// delimited, so the caller can stream the body itself and know where
/// the next message starts.
///
/// Headers keep their original case and their raw bytes: a proxy
/// forwards fields it does not itself read, so nothing is normalized
/// away. [`raw`](Self::raw) is the exact on-wire head, which is what
/// a verbatim-forwarding proxy relays.
///
/// Contrast [`HttpRequest`], emitted only once the whole body has
/// been buffered — the passive-telemetry shape.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct RequestHead {
    pub method: Bytes,
    /// Request-target exactly as it appeared: origin-form
    /// (`/path?q`), absolute-form (`http://host/path`), authority-form
    /// (`host:port`, for `CONNECT`), or `*`.
    pub path: Bytes,
    pub version: HttpVersion,
    /// Header fields in wire order, original case, raw values.
    pub headers: Vec<(Bytes, Bytes)>,
    pub framing: BodyFraming,
    /// Normalizations the parser applied to resolve a framing
    /// ambiguity. Empty unless the policy is
    /// [`SmugglingPolicy::Normalize`] and the message needed fixing —
    /// in which case `raw` must **not** be forwarded verbatim.
    pub applied: Vec<Normalization>,
    /// The exact on-wire head: start line through the blank line.
    pub raw: Bytes,
}

/// Response status line + headers, surfaced before the body.
///
/// Framing is computed using the matching request's method, per RFC
/// 9112 §6.3 rules 1–2 — a response to `HEAD` is bodyless whatever
/// its headers claim.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct ResponseHead {
    pub status: u16,
    pub reason: Bytes,
    pub version: HttpVersion,
    pub headers: Vec<(Bytes, Bytes)>,
    pub framing: BodyFraming,
    /// `true` for a `1xx` interim response. Interim responses precede
    /// the final one and never carry a body; a proxy forwards them
    /// and keeps waiting.
    pub interim: bool,
    /// Normalizations the parser applied; see
    /// [`RequestHead::applied`].
    pub applied: Vec<Normalization>,
    /// The exact on-wire head: status line through the blank line.
    pub raw: Bytes,
}

impl RequestHead {
    /// Method as a UTF-8 `&str` (e.g. `"GET"`). `None` if non-UTF-8.
    pub fn method_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.method).ok()
    }

    /// Request-target as a UTF-8 `&str`.
    pub fn path_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.path).ok()
    }

    /// `Host:` header value as UTF-8 — the modal routing key.
    ///
    /// This is the raw field. For a routing decision that also honours
    /// an absolute-form request-target, prefer the authority accessor
    /// added by issue #163.
    pub fn host(&self) -> Option<&str> {
        self.header_str("host")
    }

    /// `Content-Length:` header value parsed as `u64`.
    pub fn content_length(&self) -> Option<u64> {
        self.header_str("content-length")
            .and_then(|v| v.trim().parse().ok())
    }

    /// First match (case-insensitive) for an arbitrary header.
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        header_lookup(&self.headers, name).next()
    }

    /// All matches (case-insensitive) for an arbitrary header.
    pub fn headers_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> + 'a {
        header_lookup(&self.headers, name)
    }

    /// The authority this request should be routed to.
    ///
    /// RFC 9112 §3.2: a request-target in absolute form
    /// (`GET http://host/path`) carries its own authority, and that
    /// authority wins over the `Host` header — a proxy that routes on
    /// `Host` while its backend routes on the absolute form can be
    /// made to disagree.
    ///
    /// The host is lowercased with **ASCII rules only**, and a
    /// non-ASCII authority is refused rather than folded: U+212A
    /// KELVIN SIGN lowercases to `k` under Unicode rules, which turns
    /// case folding into a routing-desync primitive. A duplicated
    /// `Host` is refused for the same reason.
    ///
    /// Site policy (which authorities are acceptable at all) belongs
    /// to the caller — this returns the raw and the normalized form
    /// and imposes nothing else.
    ///
    /// ```
    /// # use bytes::Bytes;
    /// # use flowscope::FlowSide;
    /// # use flowscope::http::{HttpEvent, HttpProxyParser};
    /// let mut p = HttpProxyParser::new();
    /// let wire = Bytes::from_static(
    ///     b"GET http://Example.COM:8080/a HTTP/1.1\r\nHost: other.example\r\n\r\n",
    /// );
    /// p.push(FlowSide::Initiator, &wire);
    /// let Some(HttpEvent::RequestHead(head)) = p.next_event() else { panic!() };
    ///
    /// // The absolute-form target wins over the Host header.
    /// let authority = head.authority().unwrap();
    /// assert_eq!(authority.host, "example.com");
    /// assert_eq!(authority.port, Some(8080));
    /// ```
    pub fn authority(&self) -> Result<Authority, HttpPoison> {
        let mut hosts = header_lookup(&self.headers, "host");
        let host_header = hosts.next();
        if hosts.next().is_some() {
            return Err(HttpPoison::DuplicateHost);
        }
        // Absolute-form request-target: scheme "://" authority path.
        let raw: Bytes = match absolute_form_authority(&self.path) {
            Some(range) => self.path.slice(range),
            None => match host_header {
                Some(_) => {
                    let idx = self
                        .headers
                        .iter()
                        .position(|(k, _)| k.as_ref().eq_ignore_ascii_case(b"host"))
                        .expect("host header was just found");
                    self.headers[idx].1.clone()
                }
                None => Bytes::new(),
            },
        };
        parse_authority(raw)
    }

    fn header_str(&self, name: &str) -> Option<&str> {
        self.header(name).and_then(|v| std::str::from_utf8(v).ok())
    }
}

/// Byte range of the authority inside an absolute-form target, if the
/// target is in absolute form at all.
fn absolute_form_authority(target: &[u8]) -> Option<std::ops::Range<usize>> {
    let sep = target.windows(3).position(|w| w == b"://")?;
    // The scheme must be a token, not part of a path.
    if sep == 0 || target[..sep].iter().any(|b| !b.is_ascii_alphanumeric()) {
        return None;
    }
    let start = sep + 3;
    let end = target[start..]
        .iter()
        .position(|b| matches!(b, b'/' | b'?' | b'#'))
        .map_or(target.len(), |p| p + start);
    Some(start..end)
}

/// Split an authority into an ASCII-lowercased host and a port.
fn parse_authority(raw: Bytes) -> Result<Authority, HttpPoison> {
    if !raw.is_ascii() {
        return Err(HttpPoison::NonAsciiAuthority);
    }
    let s = std::str::from_utf8(&raw).map_err(|_| HttpPoison::NonAsciiAuthority)?;
    // Strip userinfo, which is not part of the routing key.
    let s = s.rsplit_once('@').map_or(s, |(_, after)| after);

    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        // IPv6 literal: [::1]:8080
        let (inside, after) = rest.split_once(']').ok_or(HttpPoison::NonAsciiAuthority)?;
        let port = match after.strip_prefix(':') {
            Some(p) if !p.is_empty() => Some(p.parse().map_err(|_| HttpPoison::NonAsciiAuthority)?),
            Some(_) => return Err(HttpPoison::NonAsciiAuthority),
            None => None,
        };
        (inside.to_ascii_lowercase(), port)
    } else {
        match s.rsplit_once(':') {
            Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => (
                h.to_ascii_lowercase(),
                Some(p.parse().map_err(|_| HttpPoison::NonAsciiAuthority)?),
            ),
            Some((_, p)) if !p.is_empty() => return Err(HttpPoison::NonAsciiAuthority),
            _ => (s.to_ascii_lowercase(), None),
        }
    };
    Ok(Authority { raw, host, port })
}

impl ResponseHead {
    /// Reason phrase as a UTF-8 `&str`.
    pub fn reason_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.reason).ok()
    }

    /// Status class — `status / 100`, or `None` outside `[100, 599]`.
    pub fn status_class(&self) -> Option<u8> {
        let cls = self.status / 100;
        if (1..=5).contains(&cls) {
            Some(cls as u8)
        } else {
            None
        }
    }

    /// `2xx` predicate.
    pub fn is_success(&self) -> bool {
        self.status_class() == Some(2)
    }

    /// `Content-Length:` header value parsed as `u64`.
    pub fn content_length(&self) -> Option<u64> {
        self.header_str("content-length")
            .and_then(|v| v.trim().parse().ok())
    }

    /// First match (case-insensitive) for an arbitrary header.
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        header_lookup(&self.headers, name).next()
    }

    /// All matches (case-insensitive) for an arbitrary header.
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
    headers: &'h [(Bytes, Bytes)],
    name: &'n str,
) -> impl Iterator<Item = &'h [u8]> + use<'h, 'n> {
    headers
        .iter()
        .filter(move |(k, _)| k.as_ref().eq_ignore_ascii_case(name.as_bytes()))
        .map(|(_, v)| v.as_ref())
}

/// Configuration knobs for the HTTP parser.
#[derive(Debug, Clone)]
#[non_exhaustive]
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

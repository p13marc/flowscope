//! [`HttpParser`] — `SessionParser` impl that produces
//! [`HttpRequest`] / [`HttpResponse`] events.
//!
//! Equivalent to [`crate::HttpFactory`] but in the typed-stream
//! shape: pair with `netring::FlowStream::session_stream(...)` to
//! get an async iterator of HTTP messages instead of a callback
//! handler.

use super::{
    parser::{self, DirState, ParseOutput},
    types::{HttpConfig, HttpRequest, HttpResponse, RequestHead},
};
use crate::{SessionParser, Timestamp};

/// Unified message type emitted by [`HttpParser`].
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "type", content = "data", rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum HttpMessage {
    Request(HttpRequest),
    Response(HttpResponse),
    /// Request headers emitted at header-completion time, *before*
    /// the body — only in inline-streaming mode
    /// ([`HttpConfig::inline_streaming`](super::HttpConfig::inline_streaming)).
    /// Carries the [`BodyFraming`](super::BodyFraming) so an inline
    /// proxy can route immediately and stream the body itself.
    RequestHead(RequestHead),
}

/// Per-flow HTTP/1.x parser. Holds independent state for the
/// initiator (request) and responder (response) directions.
///
/// Implements `Default + Clone`, so it can be passed directly as a
/// `SessionParserFactory` — every new flow gets a fresh clone.
#[derive(Debug, Clone)]
pub struct HttpParser {
    config: HttpConfig,
    init_buf: Vec<u8>,
    init_state: DirState,
    resp_buf: Vec<u8>,
    resp_state: DirState,
}

impl Default for HttpParser {
    fn default() -> Self {
        Self::with_config(HttpConfig::default())
    }
}

impl HttpParser {
    /// Construct with explicit config. Per-direction buffers are
    /// allocated lazily — a parser that only sees one direction
    /// (a half-open flow, or a request-only / response-only
    /// fixture) pays for only one 8 KiB Vec instead of two.
    pub fn with_config(config: HttpConfig) -> Self {
        Self {
            config,
            init_buf: Vec::new(),
            init_state: DirState::Headers,
            resp_buf: Vec::new(),
            resp_state: DirState::Headers,
        }
    }

    fn drain(
        state: &mut DirState,
        buf: &mut Vec<u8>,
        is_request: bool,
        cfg: &HttpConfig,
        out: &mut Vec<HttpMessage>,
    ) {
        loop {
            match parser::step(state, buf, is_request, cfg) {
                Ok(Some(ParseOutput::Request(r))) => out.push(HttpMessage::Request(r)),
                Ok(Some(ParseOutput::Response(r))) => out.push(HttpMessage::Response(r)),
                Ok(Some(ParseOutput::RequestHead(h))) => out.push(HttpMessage::RequestHead(h)),
                Ok(None) => break,
                Err(_) => {
                    buf.clear();
                    break;
                }
            }
        }
    }
}

impl SessionParser for HttpParser {
    type Message = HttpMessage;

    fn feed_initiator(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<HttpMessage>) {
        if bytes.is_empty() {
            return;
        }
        self.init_buf.extend_from_slice(bytes);
        Self::drain(
            &mut self.init_state,
            &mut self.init_buf,
            true,
            &self.config,
            out,
        );
    }

    fn feed_responder(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<HttpMessage>) {
        if bytes.is_empty() {
            return;
        }
        self.resp_buf.extend_from_slice(bytes);
        Self::drain(
            &mut self.resp_state,
            &mut self.resp_buf,
            false,
            &self.config,
            out,
        );
    }

    fn fin_initiator(&mut self, out: &mut Vec<HttpMessage>) {
        match parser::eof(&mut self.init_state, &mut self.init_buf) {
            Some(ParseOutput::Request(r)) => out.push(HttpMessage::Request(r)),
            Some(ParseOutput::Response(r)) => out.push(HttpMessage::Response(r)),
            Some(ParseOutput::RequestHead(h)) => out.push(HttpMessage::RequestHead(h)),
            None => {}
        }
    }

    fn fin_responder(&mut self, out: &mut Vec<HttpMessage>) {
        match parser::eof(&mut self.resp_state, &mut self.resp_buf) {
            Some(ParseOutput::Request(r)) => out.push(HttpMessage::Request(r)),
            Some(ParseOutput::Response(r)) => out.push(HttpMessage::Response(r)),
            Some(ParseOutput::RequestHead(h)) => out.push(HttpMessage::RequestHead(h)),
            None => {}
        }
    }

    fn rst_initiator(&mut self) {
        self.init_buf.clear();
        self.init_state = DirState::Headers;
    }

    fn rst_responder(&mut self) {
        self.resp_buf.clear();
        self.resp_state = DirState::Headers;
    }

    fn parser_kind(&self) -> crate::ParserKind {
        crate::ParserKind::Http1
    }

    /// In inline-streaming mode, report a poisoned direction so the
    /// driver tears the flow down — an inline proxy must not keep
    /// forwarding bytes past a framing desync (request smuggling).
    ///
    /// Gated on `inline_streaming` so passive-telemetry behaviour is
    /// unchanged: there, a desync silently drops the buffer and the
    /// flow stays up (a later valid message may still be observed on
    /// the other direction), matching the pre-spike default.
    fn is_poisoned(&self) -> bool {
        self.config.inline_streaming
            && (matches!(self.init_state, DirState::Desynced)
                || matches!(self.resp_state, DirState::Desynced))
    }

    fn poison_reason(&self) -> Option<&str> {
        if self.is_poisoned() {
            Some("http framing desync")
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed_init(p: &mut HttpParser, bytes: &[u8]) -> Vec<HttpMessage> {
        let mut out = Vec::new();
        p.feed_initiator(bytes, Timestamp::default(), &mut out);
        out
    }
    fn feed_resp(p: &mut HttpParser, bytes: &[u8]) -> Vec<HttpMessage> {
        let mut out = Vec::new();
        p.feed_responder(bytes, Timestamp::default(), &mut out);
        out
    }
    fn fin_resp(p: &mut HttpParser) -> Vec<HttpMessage> {
        let mut out = Vec::new();
        p.fin_responder(&mut out);
        out
    }

    #[test]
    fn parses_full_request_then_response() {
        let mut p = HttpParser::default();
        let req = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let m = feed_init(&mut p, req);
        assert_eq!(m.len(), 1);
        match &m[0] {
            HttpMessage::Request(r) => {
                assert_eq!(r.method, "GET");
                assert_eq!(r.path, "/index.html");
            }
            _ => panic!("expected Request"),
        }

        let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        let m = feed_resp(&mut p, resp);
        assert_eq!(m.len(), 1);
        match &m[0] {
            HttpMessage::Response(r) => {
                assert_eq!(r.status, 200);
                assert_eq!(r.body.as_ref(), b"hello");
            }
            _ => panic!("expected Response"),
        }
    }

    #[test]
    fn split_segments_concatenate() {
        let mut p = HttpParser::default();
        let m = feed_init(&mut p, b"GET /a HTTP/1.1\r\nHo");
        assert!(m.is_empty());
        let m = feed_init(&mut p, b"st: x\r\n\r\n");
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn pipelined_requests() {
        let mut p = HttpParser::default();
        let m = feed_init(&mut p, b"GET /a HTTP/1.1\r\n\r\nGET /b HTTP/1.1\r\n\r\n");
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn fin_flushes_until_eof_body() {
        let mut p = HttpParser::default();
        let m = feed_resp(&mut p, b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhel");
        assert!(m.is_empty());
        let m = feed_resp(&mut p, b"lo");
        assert!(m.is_empty());
        let m = fin_resp(&mut p);
        assert_eq!(m.len(), 1);
        match &m[0] {
            HttpMessage::Response(r) => assert_eq!(r.body.as_ref(), b"hello"),
            _ => panic!("expected Response"),
        }
    }

    // ── Inline-streaming mode ─────────────────────────────────────

    use super::super::types::BodyFraming;

    // Mirrors the construction path external crates must use:
    // `HttpConfig` is `#[non_exhaustive]`, so a struct literal is
    // unavailable to them — field reassignment is the real API.
    #[allow(clippy::field_reassign_with_default)]
    fn inline_parser() -> HttpParser {
        let mut cfg = HttpConfig::default();
        cfg.inline_streaming = true;
        HttpParser::with_config(cfg)
    }

    #[test]
    fn inline_post_emits_head_before_body_is_fed() {
        // The load-bearing property: a POST with Content-Length must
        // surface the routing head at header completion, BEFORE any
        // body bytes arrive.
        let mut p = inline_parser();
        let m = feed_init(
            &mut p,
            b"POST /submit HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 1000\r\n\r\n",
        );
        assert_eq!(m.len(), 1, "head must be emitted at header completion");
        match &m[0] {
            HttpMessage::RequestHead(h) => {
                assert_eq!(h.method.as_ref(), b"POST");
                assert_eq!(h.path.as_ref(), b"/submit");
                assert_eq!(h.host(), Some("api.example.com"));
                assert_eq!(h.framing, BodyFraming::ContentLength(1000));
            }
            other => panic!("expected RequestHead, got {other:?}"),
        }
        // The body is never emitted as a message and never buffered.
        let m = feed_init(&mut p, &vec![b'x'; 1000]);
        assert!(m.is_empty(), "body must not produce a message");
        assert!(!p.is_poisoned());
    }

    #[test]
    fn inline_get_head_has_no_body_framing() {
        let mut p = inline_parser();
        let m = feed_init(&mut p, b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n");
        assert_eq!(m.len(), 1);
        match &m[0] {
            HttpMessage::RequestHead(h) => {
                assert_eq!(h.method.as_ref(), b"GET");
                assert_eq!(h.framing, BodyFraming::None);
            }
            other => panic!("expected RequestHead, got {other:?}"),
        }
    }

    #[test]
    fn inline_chunked_head_then_boundary_found() {
        let mut p = inline_parser();
        // Head arrives with Chunked framing…
        let m = feed_init(
            &mut p,
            b"POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n",
        );
        assert_eq!(m.len(), 1);
        match &m[0] {
            HttpMessage::RequestHead(h) => assert_eq!(h.framing, BodyFraming::Chunked),
            other => panic!("expected RequestHead, got {other:?}"),
        }
        // …then the chunked body is skipped and the NEXT pipelined
        // request is located cleanly.
        let m = feed_init(
            &mut p,
            b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\nGET /next HTTP/1.1\r\nHost: h\r\n\r\n",
        );
        assert_eq!(m.len(), 1, "next request must be found after chunked body");
        match &m[0] {
            HttpMessage::RequestHead(h) => assert_eq!(h.path.as_ref(), b"/next"),
            other => panic!("expected RequestHead for /next, got {other:?}"),
        }
        assert!(!p.is_poisoned());
    }

    #[test]
    fn inline_pipelined_bodied_requests() {
        let mut p = inline_parser();
        // Two POSTs back-to-back in one feed; both heads surface,
        // bodies are skipped by Content-Length.
        let m = feed_init(
            &mut p,
            b"POST /a HTTP/1.1\r\nContent-Length: 3\r\n\r\nAAA\
              POST /b HTTP/1.1\r\nContent-Length: 2\r\n\r\nBB",
        );
        let heads: Vec<_> = m
            .iter()
            .filter_map(|msg| match msg {
                HttpMessage::RequestHead(h) => h.path_str(),
                _ => None,
            })
            .collect();
        assert_eq!(heads, vec!["/a", "/b"]);
    }

    #[test]
    fn inline_body_split_across_feeds_finds_next_request() {
        let mut p = inline_parser();
        let m = feed_init(&mut p, b"POST /a HTTP/1.1\r\nContent-Length: 5\r\n\r\nAB");
        assert_eq!(m.len(), 1); // head for /a
        let m = feed_init(&mut p, b"CDE"); // rest of body — no message
        assert!(m.is_empty());
        let m = feed_init(&mut p, b"GET /b HTTP/1.1\r\n\r\n");
        assert_eq!(m.len(), 1);
        match &m[0] {
            HttpMessage::RequestHead(h) => assert_eq!(h.path.as_ref(), b"/b"),
            other => panic!("expected RequestHead for /b, got {other:?}"),
        }
    }

    #[test]
    fn inline_malformed_request_poisons() {
        let mut p = inline_parser();
        let _ = feed_init(&mut p, b"NOT-HTTP \x00\x01\x02 garbage\r\n\r\n");
        assert!(p.is_poisoned(), "framing desync must poison in inline mode");
        assert_eq!(p.poison_reason(), Some("http framing desync"));
    }

    #[test]
    fn telemetry_mode_malformed_does_not_poison() {
        // Same malformed input, flag OFF: unchanged behaviour — the
        // buffer is dropped, no poison, flow stays up.
        let mut p = HttpParser::default();
        let _ = feed_init(&mut p, b"NOT-HTTP \x00\x01\x02 garbage\r\n\r\n");
        assert!(!p.is_poisoned());
    }
}

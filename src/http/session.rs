//! [`HttpParser`] — the passive-telemetry `SessionParser`, producing
//! one [`HttpRequest`] / [`HttpResponse`] per complete message.
//!
//! This is an *aggregating front-end* over the shared streaming
//! engine (`super::engine`): the engine frames the message and hands
//! back body spans it never retains, and this type accumulates those
//! spans into the single `body` field the telemetry shape exposes.
//! Inline proxies use the streaming front-end instead, which forwards
//! the same events without accumulating.

use bytes::{Bytes, BytesMut};

use super::{
    engine::{Dir, Engine, EngineEvent, EngineLimits, Head},
    types::{HttpConfig, HttpRequest, HttpResponse},
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
}

/// A message being accumulated on one direction.
#[derive(Debug, Clone)]
struct Partial {
    head: Head,
    body: BytesMut,
    /// Set once the accumulated body exceeds `max_buffer`; the
    /// message is still framed correctly, but its body is dropped
    /// rather than grown without bound.
    overflowed: bool,
}

/// Per-flow HTTP/1.x parser. Holds independent state for the
/// initiator (request) and responder (response) directions.
///
/// Implements `Default + Clone`, so it can be passed directly as a
/// `SessionParserFactory` — every new flow gets a fresh clone.
#[derive(Debug, Clone)]
pub struct HttpParser {
    engine: Engine,
    config: HttpConfig,
    request: Option<Partial>,
    response: Option<Partial>,
}

impl Default for HttpParser {
    fn default() -> Self {
        Self::with_config(HttpConfig::default())
    }
}

impl HttpParser {
    /// Construct with explicit config.
    pub fn with_config(config: HttpConfig) -> Self {
        let limits = EngineLimits {
            max_head_bytes: config.max_buffer,
            max_headers: config.max_headers,
            ..EngineLimits::default()
        };
        Self {
            engine: Engine::new(limits),
            config,
            request: None,
            response: None,
        }
    }

    fn partial_mut(&mut self, dir: Dir) -> &mut Option<Partial> {
        match dir {
            Dir::Request => &mut self.request,
            Dir::Response => &mut self.response,
        }
    }

    /// Pump the engine on one direction, aggregating spans into whole
    /// messages.
    fn drain(&mut self, dir: Dir, out: &mut Vec<HttpMessage>) {
        loop {
            match self.engine.poll(dir) {
                Ok(Some(ev)) => self.absorb(dir, ev, out),
                Ok(None) => break,
                // Telemetry is an observer: a framing failure drops
                // the direction's buffer and stays quiet. It never
                // poisons the flow — that is the inline proxy's
                // contract, not this one's.
                Err(_) => {
                    *self.partial_mut(dir) = None;
                    break;
                }
            }
        }
    }

    fn absorb(&mut self, dir: Dir, ev: EngineEvent, out: &mut Vec<HttpMessage>) {
        let max_buffer = self.config.max_buffer;
        match ev {
            EngineEvent::Head(head) => {
                *self.partial_mut(dir) = Some(Partial {
                    head,
                    body: BytesMut::new(),
                    overflowed: false,
                });
            }
            EngineEvent::Body { decoded, .. } => {
                if let Some(p) = self.partial_mut(dir).as_mut() {
                    if p.body.len() + decoded.len() > max_buffer {
                        p.overflowed = true;
                        p.body.clear();
                    } else if !p.overflowed {
                        p.body.extend_from_slice(&decoded);
                    }
                }
            }
            EngineEvent::Trailers { fields, .. } => {
                // Trailer fields join the header list, in wire order
                // after the head's own fields — the telemetry shape
                // has one header vec per message.
                if let Some(p) = self.partial_mut(dir).as_mut() {
                    p.head.headers.extend(fields);
                }
            }
            EngineEvent::End => {
                if let Some(p) = self.partial_mut(dir).take() {
                    out.push(finish(p));
                }
            }
            EngineEvent::Switch(_) => {
                // The connection left HTTP/1.x (CONNECT tunnel,
                // Upgrade, or a prior-knowledge h2 client). There is
                // no further HTTP to observe on it; whatever was
                // being accumulated is not a complete message.
                self.request = None;
                self.response = None;
            }
        }
    }

    /// Flush a close-delimited message at end of stream.
    fn finish_at_eof(&mut self, dir: Dir, out: &mut Vec<HttpMessage>) {
        if let Some(ev) = self.engine.fin(dir) {
            self.absorb(dir, ev, out);
        }
        // A body that was delimited by the close is complete now.
        if let Some(p) = self.partial_mut(dir).take() {
            out.push(finish(p));
        }
    }
}

fn finish(p: Partial) -> HttpMessage {
    let body: Bytes = p.body.freeze();
    let head = p.head;
    match head.dir {
        Dir::Request => HttpMessage::Request(HttpRequest {
            method: head.method,
            path: head.path,
            version: head.version,
            headers: head.headers,
            body,
        }),
        Dir::Response => HttpMessage::Response(HttpResponse {
            status: head.status,
            reason: head.reason,
            version: head.version,
            headers: head.headers,
            body,
        }),
    }
}

impl SessionParser for HttpParser {
    type Message = HttpMessage;

    fn feed_initiator(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<HttpMessage>) {
        if bytes.is_empty() {
            return;
        }
        self.engine.push(Dir::Request, bytes);
        self.drain(Dir::Request, out);
    }

    fn feed_responder(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<HttpMessage>) {
        if bytes.is_empty() {
            return;
        }
        self.engine.push(Dir::Response, bytes);
        self.drain(Dir::Response, out);
    }

    fn fin_initiator(&mut self, out: &mut Vec<HttpMessage>) {
        self.finish_at_eof(Dir::Request, out);
    }

    fn fin_responder(&mut self, out: &mut Vec<HttpMessage>) {
        self.finish_at_eof(Dir::Response, out);
    }

    fn rst_initiator(&mut self) {
        self.engine.reset(Dir::Request);
        self.request = None;
    }

    fn rst_responder(&mut self) {
        self.engine.reset(Dir::Response);
        self.response = None;
    }

    fn parser_kind(&self) -> crate::ParserKind {
        crate::ParserKind::Http1
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
    fn fin_init(p: &mut HttpParser) -> Vec<HttpMessage> {
        let mut out = Vec::new();
        p.fin_initiator(&mut out);
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

    // ── 0.23 fixes ────────────────────────────────────────────────

    #[test]
    fn chunked_request_body_is_decoded() {
        // Pre-0.23 the telemetry path never framed chunked at all:
        // the raw chunk framing ended up inside `body`, or the
        // direction desynced. The shared engine decodes it.
        let mut p = HttpParser::default();
        let m = feed_init(
            &mut p,
            b"POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n\
              5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n",
        );
        assert_eq!(m.len(), 1);
        match &m[0] {
            HttpMessage::Request(r) => assert_eq!(r.body.as_ref(), b"hello world"),
            other => panic!("expected Request, got {other:?}"),
        }
    }

    #[test]
    fn chunked_response_body_is_decoded_and_next_message_found() {
        let mut p = HttpParser::default();
        let _ = feed_init(&mut p, b"GET /a HTTP/1.1\r\n\r\nGET /b HTTP/1.1\r\n\r\n");
        let m = feed_resp(
            &mut p,
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n\r\n\
              HTTP/1.1 204 No Content\r\n\r\n",
        );
        assert_eq!(m.len(), 2, "chunked body must not swallow the next message");
        match &m[0] {
            HttpMessage::Response(r) => assert_eq!(r.body.as_ref(), b"abcd"),
            other => panic!("expected Response, got {other:?}"),
        }
    }

    #[test]
    fn chunked_trailers_join_the_header_list() {
        let mut p = HttpParser::default();
        let m = feed_init(
            &mut p,
            b"POST /u HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n\
              3\r\nabc\r\n0\r\nX-Checksum: deadbeef\r\n\r\n",
        );
        assert_eq!(m.len(), 1);
        match &m[0] {
            HttpMessage::Request(r) => {
                assert_eq!(r.body.as_ref(), b"abc");
                assert_eq!(r.header("x-checksum"), Some(&b"deadbeef"[..]));
            }
            other => panic!("expected Request, got {other:?}"),
        }
    }

    #[test]
    fn head_response_with_content_length_has_no_body() {
        // RFC 9112 §6.3 rule 1: a response to HEAD never has a body,
        // even with Content-Length. Pre-0.23 this mis-framed and ate
        // the following response.
        let mut p = HttpParser::default();
        let _ = feed_init(&mut p, b"HEAD /x HTTP/1.1\r\n\r\nGET /y HTTP/1.1\r\n\r\n");
        let m = feed_resp(
            &mut p,
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi",
        );
        assert_eq!(m.len(), 2, "HEAD response must not consume a body");
        match (&m[0], &m[1]) {
            (HttpMessage::Response(a), HttpMessage::Response(b)) => {
                assert!(a.body.is_empty());
                assert_eq!(b.body.as_ref(), b"hi");
            }
            other => panic!("expected two responses, got {other:?}"),
        }
    }

    #[test]
    fn status_204_and_304_have_no_body() {
        let mut p = HttpParser::default();
        let _ = feed_init(&mut p, b"GET /a HTTP/1.1\r\n\r\nGET /b HTTP/1.1\r\n\r\n");
        let m = feed_resp(
            &mut p,
            b"HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n\
              HTTP/1.1 304 Not Modified\r\nContent-Length: 7\r\n\r\n",
        );
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn clean_fin_on_idle_connection_is_not_a_parse_error() {
        // Pre-0.23 `eof()` unconditionally replaced the state with
        // Desynced, so a FIN on an idle keep-alive connection looked
        // like a framing failure.
        let mut p = HttpParser::default();
        let m = feed_init(&mut p, b"GET /a HTTP/1.1\r\n\r\n");
        assert_eq!(m.len(), 1);
        let m = fin_init(&mut p);
        assert!(m.is_empty());
        assert!(!p.is_poisoned(), "a clean FIN must not poison the parser");
    }

    #[test]
    fn request_without_length_has_no_body() {
        // RFC 9112 §6.3 rule 6: a request with neither TE nor CL has
        // no body — so a bodyless POST does not swallow what follows.
        let mut p = HttpParser::default();
        let m = feed_init(&mut p, b"POST /a HTTP/1.1\r\n\r\nGET /b HTTP/1.1\r\n\r\n");
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn interim_responses_are_not_reported_as_messages() {
        // A 1xx precedes the final response; telemetry reports the
        // final one, and the interim must not mis-frame it.
        let mut p = HttpParser::default();
        let _ = feed_init(&mut p, b"POST /u HTTP/1.1\r\nContent-Length: 0\r\n\r\n");
        let m = feed_resp(
            &mut p,
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        );
        assert_eq!(m.len(), 1);
        match &m[0] {
            HttpMessage::Response(r) => {
                assert_eq!(r.status, 200);
                assert_eq!(r.body.as_ref(), b"ok");
            }
            other => panic!("expected the final response, got {other:?}"),
        }
    }

    #[test]
    fn connect_tunnel_stops_http_observation() {
        let mut p = HttpParser::default();
        let _ = feed_init(&mut p, b"CONNECT example.com:443 HTTP/1.1\r\n\r\n");
        let m = feed_resp(&mut p, b"HTTP/1.1 200 Connection Established\r\n\r\n");
        // The tunnel's bytes are not HTTP, and are not reported as
        // malformed HTTP either.
        let m2 = feed_init(&mut p, b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc");
        assert!(m2.is_empty());
        assert!(!p.is_poisoned());
        let _ = m;
    }

    #[test]
    fn http2_preface_does_not_look_like_a_malformed_request() {
        let mut p = HttpParser::default();
        let m = feed_init(
            &mut p,
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00",
        );
        assert!(m.is_empty());
        assert!(!p.is_poisoned());
    }

    #[test]
    fn body_larger_than_max_buffer_does_not_grow_unbounded() {
        let cfg = HttpConfig {
            max_buffer: 1024,
            ..HttpConfig::default()
        };
        let mut p = HttpParser::with_config(cfg);
        let mut wire = b"POST /u HTTP/1.1\r\nContent-Length: 4096\r\n\r\n".to_vec();
        wire.extend(std::iter::repeat_n(b'x', 4096));
        let m = feed_init(&mut p, &wire);
        // Framing still completes; the oversized body is dropped.
        assert_eq!(m.len(), 1);
        match &m[0] {
            HttpMessage::Request(r) => assert!(r.body.is_empty()),
            other => panic!("expected Request, got {other:?}"),
        }
    }
}

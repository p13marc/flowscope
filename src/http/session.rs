//! [`HttpParser`] — `SessionParser` impl that produces
//! [`HttpRequest`] / [`HttpResponse`] events.
//!
//! Equivalent to [`crate::HttpFactory`] but in the typed-stream
//! shape: pair with `netring::FlowStream::session_stream(...)` to
//! get an async iterator of HTTP messages instead of a callback
//! handler.

use super::{
    parser::{self, DirState, ParseOutput},
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
pub enum HttpMessage {
    Request(HttpRequest),
    Response(HttpResponse),
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
            None => {}
        }
    }

    fn fin_responder(&mut self, out: &mut Vec<HttpMessage>) {
        match parser::eof(&mut self.resp_state, &mut self.resp_buf) {
            Some(ParseOutput::Request(r)) => out.push(HttpMessage::Request(r)),
            Some(ParseOutput::Response(r)) => out.push(HttpMessage::Response(r)),
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

    fn parser_kind(&self) -> &'static str {
        crate::http::PARSER_KIND
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
}

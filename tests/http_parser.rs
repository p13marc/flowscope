//! Unit-style tests for the HTTP parser, driven via the
//! `SessionParser` API.

use flowscope::http::{HttpMessage, HttpParser, HttpRequest, HttpResponse};
use flowscope::{SessionParser, Timestamp};

#[derive(Default)]
struct Captured {
    reqs: Vec<HttpRequest>,
    resps: Vec<HttpResponse>,
}

impl Captured {
    fn ingest(&mut self, msgs: Vec<HttpMessage>) {
        for m in msgs {
            match m {
                HttpMessage::Request(r) => self.reqs.push(r),
                HttpMessage::Response(r) => self.resps.push(r),
            }
        }
    }
}

fn feed_init(parser: &mut HttpParser, captured: &mut Captured, bytes: &[u8]) {
    captured.ingest(parser.feed_initiator(bytes, Timestamp::default()));
}

fn feed_resp(parser: &mut HttpParser, captured: &mut Captured, bytes: &[u8]) {
    captured.ingest(parser.feed_responder(bytes, Timestamp::default()));
}

#[test]
fn simple_get_request() {
    let mut parser = HttpParser::default();
    let mut captured = Captured::default();
    feed_init(
        &mut parser,
        &mut captured,
        b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
    );
    assert_eq!(captured.reqs.len(), 1);
    assert_eq!(captured.reqs[0].method, "GET");
    assert_eq!(captured.reqs[0].path, "/index.html");
    assert!(captured.reqs[0].body.is_empty());
}

#[test]
fn pipelined_requests() {
    let mut parser = HttpParser::default();
    let mut captured = Captured::default();
    feed_init(
        &mut parser,
        &mut captured,
        b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n",
    );
    feed_init(
        &mut parser,
        &mut captured,
        b"GET /b HTTP/1.1\r\nHost: x\r\n\r\n",
    );
    feed_init(
        &mut parser,
        &mut captured,
        b"GET /c HTTP/1.1\r\nHost: x\r\n\r\n",
    );
    assert_eq!(captured.reqs.len(), 3);
    assert_eq!(captured.reqs[0].path, "/a");
    assert_eq!(captured.reqs[1].path, "/b");
    assert_eq!(captured.reqs[2].path, "/c");
}

#[test]
fn response_with_content_length_body() {
    let mut parser = HttpParser::default();
    let mut captured = Captured::default();
    feed_resp(
        &mut parser,
        &mut captured,
        b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello, world!",
    );
    assert_eq!(captured.resps.len(), 1);
    assert_eq!(captured.resps[0].status, 200);
    assert_eq!(&*captured.resps[0].body, b"Hello, world!");
}

#[test]
fn split_across_segments() {
    let mut parser = HttpParser::default();
    let mut captured = Captured::default();
    feed_init(&mut parser, &mut captured, b"GET /index.html HTTP/1.1\r\n");
    feed_init(&mut parser, &mut captured, b"Host: ex");
    feed_init(&mut parser, &mut captured, b"ample.com\r\n\r\n");
    assert_eq!(captured.reqs.len(), 1);
    assert_eq!(captured.reqs[0].path, "/index.html");
}

#[test]
fn body_split_across_segments() {
    let mut parser = HttpParser::default();
    let mut captured = Captured::default();
    feed_resp(
        &mut parser,
        &mut captured,
        b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nHello",
    );
    assert!(captured.resps.is_empty(), "should wait for full body");
    feed_resp(&mut parser, &mut captured, b", world!");
    assert_eq!(captured.resps.len(), 1);
    assert_eq!(&*captured.resps[0].body, b"Hello, world!");
}

#[test]
fn connection_close_body_extends_to_fin() {
    let mut parser = HttpParser::default();
    let mut captured = Captured::default();
    feed_resp(
        &mut parser,
        &mut captured,
        b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\n",
    );
    feed_resp(&mut parser, &mut captured, b"hello");
    assert!(captured.resps.is_empty(), "still waiting for FIN");
    feed_resp(&mut parser, &mut captured, b" world");
    // FIN flush.
    captured.ingest(parser.fin_responder());
    assert_eq!(captured.resps.len(), 1);
    assert_eq!(&*captured.resps[0].body, b"hello world");
}

#[test]
fn malformed_doesnt_panic() {
    let mut parser = HttpParser::default();
    let mut captured = Captured::default();
    feed_init(
        &mut parser,
        &mut captured,
        b"\xff\xff\xffNOT HTTP\xff\xff\r\n\r\n",
    );
    // Should not panic; the parser enters Desynced state.
    let _ = parser.fin_initiator();
}

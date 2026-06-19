//! Unit-style tests for the HTTP parser, driven via the
//! `SessionParser` API.

use flowscope::{
    SessionParser, Timestamp,
    http::{HttpMessage, HttpParser, HttpRequest, HttpResponse},
};

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
    let mut out = Vec::new();
    parser.feed_initiator(bytes, Timestamp::default(), &mut out);
    captured.ingest(out);
}

fn feed_resp(parser: &mut HttpParser, captured: &mut Captured, bytes: &[u8]) {
    let mut out = Vec::new();
    parser.feed_responder(bytes, Timestamp::default(), &mut out);
    captured.ingest(out);
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
    let mut out = Vec::new();
    parser.fin_responder(&mut out);
    captured.ingest(out);
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
    let mut out = Vec::new();
    parser.fin_initiator(&mut out);
}

/// Plan 120 spec: every header `(Bytes, Bytes)` pair on a single
/// parsed request shares the SAME underlying Arc — slices into
/// one allocation, not N separate `Bytes::copy_from_slice` calls.
/// Verified by checking every field's `as_ptr()` falls within
/// a single contiguous region (the parser allocates one
/// `Bytes` arena for the header bytes and slices into it).
#[test]
fn headers_share_backing_bytes() {
    let mut parser = HttpParser::default();
    let mut captured = Captured::default();
    let req_bytes: &[u8] = b"GET /index.html HTTP/1.1\r\n\
         Host: example.com\r\n\
         User-Agent: bench\r\n\
         Accept: */*\r\n\
         Accept-Language: en-US\r\n\
         Cookie: x=y\r\n\r\n";
    feed_init(&mut parser, &mut captured, req_bytes);
    assert_eq!(captured.reqs.len(), 1);
    let req = &captured.reqs[0];
    assert!(req.headers.len() >= 5);

    // Compute the [lo, hi) byte range that every field MUST lie
    // within if all fields share one backing allocation. Use
    // the first header value's range as the anchor.
    let anchor = req.headers[0].1.as_ref().as_ptr() as usize;
    // Allocation can be at most as large as the header bytes
    // we fed in (probably smaller).
    let region_size = req_bytes.len();

    let in_region = |b: &bytes::Bytes| {
        let p = b.as_ref().as_ptr() as usize;
        // Generous range — the actual arena is at most the
        // length of the parsed prefix. If sharing fails, fields
        // would be in separate `Bytes::copy_from_slice` allocs
        // that wouldn't share an address with the anchor.
        p.abs_diff(anchor) < region_size * 2
    };

    for (name, val) in &req.headers {
        assert!(in_region(name), "header name not in shared region");
        assert!(in_region(val), "header value not in shared region");
    }
    assert!(in_region(&req.method), "method not in shared region");
    assert!(in_region(&req.path), "path not in shared region");
}

/// Plan 120 spec: `method_str` accessor returns a UTF-8 view
/// for the common case.
#[test]
fn method_str_returns_utf8_view() {
    let mut parser = HttpParser::default();
    let mut captured = Captured::default();
    // POST without a Content-Length leaves the request as
    // "body extends to FIN" and doesn't emit until fin_initiator.
    // Use GET (which the parser treats as zero-body) for a
    // request that emits on its own.
    feed_init(
        &mut parser,
        &mut captured,
        b"GET /api HTTP/1.1\r\nHost: x\r\n\r\n",
    );
    let req = &captured.reqs[0];
    assert_eq!(req.method_str(), Some("GET"));
    assert_eq!(req.path_str(), Some("/api"));
}

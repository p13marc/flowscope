//! Plan 107 — HttpExchangeParser coverage.

#![cfg(feature = "http")]

use flowscope::http::{HttpExchangeParser, HttpOutcome};
use flowscope::{SessionParser, Timestamp};

fn req(host: &str) -> Vec<u8> {
    format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n").into_bytes()
}

fn resp(status: u16) -> Vec<u8> {
    format!("HTTP/1.1 {status} OK\r\nContent-Length: 0\r\n\r\n").into_bytes()
}

#[test]
fn request_response_yields_one_completed_exchange() {
    let mut p = HttpExchangeParser::new();
    let req_out = p.feed_initiator(&req("a.example"), Timestamp::new(0, 0));
    assert!(req_out.is_empty(), "request alone shouldn't emit");
    let resp_out = p.feed_responder(&resp(200), Timestamp::new(1, 0));
    assert_eq!(resp_out.len(), 1);
    let ex = &resp_out[0];
    assert_eq!(ex.outcome, HttpOutcome::Completed);
    assert!(ex.is_success());
    assert!(!ex.is_error());
    assert_eq!(ex.status_class(), Some(2));
    assert_eq!(ex.request.method, "GET");
}

#[test]
fn pipelined_requests_match_in_order() {
    let mut p = HttpExchangeParser::new();
    let mut both = Vec::new();
    both.extend_from_slice(&req("a.example"));
    both.extend_from_slice(&req("b.example"));
    let _ = p.feed_initiator(&both, Timestamp::new(0, 0));
    let mut resps = Vec::new();
    resps.extend_from_slice(&resp(200));
    resps.extend_from_slice(&resp(404));
    let out = p.feed_responder(&resps, Timestamp::new(1, 0));
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].request.headers[0].1, b"a.example");
    assert_eq!(out[1].request.headers[0].1, b"b.example");
    assert!(out[0].is_success());
    assert!(out[1].is_client_error_outcome());
}

// Local helper — not on HttpExchange yet.
trait IsClientError {
    fn is_client_error_outcome(&self) -> bool;
}
impl IsClientError for flowscope::http::HttpExchange {
    fn is_client_error_outcome(&self) -> bool {
        self.status_class() == Some(4)
    }
}

#[test]
fn fin_drains_pending_requests_as_no_response() {
    let mut p = HttpExchangeParser::new();
    let _ = p.feed_initiator(&req("a.example"), Timestamp::new(0, 0));
    let out = p.fin_responder();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].outcome, HttpOutcome::NoResponse);
    assert!(out[0].response.is_none());
    assert!(out[0].elapsed.is_none());
}

#[test]
fn parser_kind_is_http_exchange() {
    let p = HttpExchangeParser::new();
    assert_eq!(p.parser_kind(), "http-exchange");
}

//! Request-side upgrade detection (#204): `RequestHead::upgrade_protocols`
//! and `RequestHead::is_websocket_upgrade`.
//!
//! RFC 9110 §7.8: an `Upgrade` header is only an upgrade offer when the
//! `Connection` header names the `upgrade` option. RFC 6455 §4.1 gives the
//! WebSocket opening-handshake shape.

#![cfg(feature = "http")]

use bytes::Bytes;
use flowscope::FlowSide;
use flowscope::http::{HttpEvent, HttpProxyParser, RequestHead};

/// Parse a single request head off the wire bytes.
fn head(wire: &'static [u8]) -> RequestHead {
    let mut p = HttpProxyParser::new();
    p.push(FlowSide::Initiator, &Bytes::from_static(wire));
    match p.next_event() {
        Some(HttpEvent::RequestHead(h)) => h,
        other => panic!("expected a request head, got {other:?}"),
    }
}

#[test]
fn websocket_upgrade_with_connection_comma_list_is_detected() {
    let h = head(
        b"GET /chat HTTP/1.1\r\n\
          Host: a.example\r\n\
          Connection: keep-alive, Upgrade\r\n\
          Upgrade: websocket\r\n\
          Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
          Sec-WebSocket-Version: 13\r\n\r\n",
    );
    assert_eq!(h.upgrade_protocols().collect::<Vec<_>>(), ["websocket"]);
    assert!(h.is_websocket_upgrade());
}

#[test]
fn upgrade_header_without_connection_token_is_not_an_offer() {
    let h = head(
        b"GET /chat HTTP/1.1\r\n\
          Host: a.example\r\n\
          Upgrade: websocket\r\n\
          Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
          Sec-WebSocket-Version: 13\r\n\r\n",
    );
    assert_eq!(h.upgrade_protocols().count(), 0);
    assert!(!h.is_websocket_upgrade());
}

#[test]
fn connection_keep_alive_alone_is_not_an_offer() {
    let h = head(
        b"GET / HTTP/1.1\r\n\
          Host: a.example\r\n\
          Connection: keep-alive\r\n\
          Upgrade: websocket\r\n\r\n",
    );
    assert_eq!(h.upgrade_protocols().count(), 0);
}

#[test]
fn upgrade_token_list_and_case_are_honoured() {
    let h = head(
        b"GET / HTTP/1.1\r\n\
          Host: a.example\r\n\
          Connection: UPGRADE\r\n\
          Upgrade: WebSocket ,  h2c\r\n\
          Sec-WebSocket-Key: k\r\n\
          Sec-WebSocket-Version: 13\r\n\r\n",
    );
    assert_eq!(
        h.upgrade_protocols().collect::<Vec<_>>(),
        ["WebSocket", "h2c"]
    );
    assert!(h.is_websocket_upgrade(), "token match is case-insensitive");
}

#[test]
fn post_with_full_websocket_headers_is_not_a_websocket_upgrade() {
    let h = head(
        b"POST /chat HTTP/1.1\r\n\
          Host: a.example\r\n\
          Connection: Upgrade\r\n\
          Upgrade: websocket\r\n\
          Sec-WebSocket-Key: k\r\n\
          Sec-WebSocket-Version: 13\r\n\
          Content-Length: 0\r\n\r\n",
    );
    // Still an upgrade *offer* — just not the RFC 6455 handshake shape.
    assert_eq!(h.upgrade_protocols().collect::<Vec<_>>(), ["websocket"]);
    assert!(!h.is_websocket_upgrade());
}

#[test]
fn missing_sec_websocket_key_is_not_a_websocket_upgrade() {
    let h = head(
        b"GET /chat HTTP/1.1\r\n\
          Host: a.example\r\n\
          Connection: Upgrade\r\n\
          Upgrade: websocket\r\n\
          Sec-WebSocket-Version: 13\r\n\r\n",
    );
    assert!(!h.is_websocket_upgrade());
}

#[test]
fn tokens_split_across_duplicate_header_instances_are_combined() {
    let h = head(
        b"GET /chat HTTP/1.1\r\n\
          Host: a.example\r\n\
          Connection: keep-alive\r\n\
          Connection: Upgrade\r\n\
          Upgrade: h2c\r\n\
          Upgrade: websocket\r\n\
          Sec-WebSocket-Key: k\r\n\
          Sec-WebSocket-Version: 13\r\n\r\n",
    );
    assert_eq!(
        h.upgrade_protocols().collect::<Vec<_>>(),
        ["h2c", "websocket"]
    );
    assert!(h.is_websocket_upgrade());
}

#[test]
fn a_future_websocket_version_still_detects() {
    // Deliberate: detection, not negotiation — version 14 must not be refused.
    let h = head(
        b"GET /chat HTTP/1.1\r\n\
          Host: a.example\r\n\
          Connection: Upgrade\r\n\
          Upgrade: websocket\r\n\
          Sec-WebSocket-Key: k\r\n\
          Sec-WebSocket-Version: 14\r\n\r\n",
    );
    assert!(h.is_websocket_upgrade());
}

//! Property-based tests for `SessionParser` / `DatagramParser`
//! splitting invariance and panic-freedom across HTTP, TLS, DNS-UDP,
//! and DNS-TCP.
//!
//! The headline property is **splitting invariance**: feeding a
//! valid byte sequence in one chunk should produce the same set of
//! messages as feeding it byte-by-byte (or via any other random
//! split). This catches buffer-management bugs in the per-direction
//! state machines.
//!
//! Secondary property: **no-panic on malformed input**. The parsers
//! must accept any random byte sequence without panicking.
//!
//! Run with:
//!     cargo test --features http,tls,dns --test parser_proptest
//!
//! Increase iterations via `PROPTEST_CASES=10000 cargo test ...`.

use proptest::prelude::*;

// ── HTTP ───────────────────────────────────────────────────────────

#[cfg(feature = "http")]
mod http_props {
    use flowscope::{
        SessionParser, Timestamp,
        http::{HttpConfig, HttpMessage, HttpParser},
    };

    use super::*;

    fn inline_parser() -> HttpParser {
        let mut cfg = HttpConfig::default();
        cfg.inline_streaming = true;
        HttpParser::with_config(cfg)
    }

    fn count_heads(msgs: &[HttpMessage]) -> usize {
        msgs.iter()
            .filter(|m| matches!(m, HttpMessage::RequestHead(_)))
            .count()
    }

    fn build_request(method: &str, path: &str, body: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(method.as_bytes());
        v.push(b' ');
        v.extend_from_slice(path.as_bytes());
        v.extend_from_slice(b" HTTP/1.1\r\nHost: example.com\r\nContent-Length: ");
        v.extend_from_slice(body.len().to_string().as_bytes());
        v.extend_from_slice(b"\r\n\r\n");
        v.extend_from_slice(body);
        v
    }

    fn count_requests(msgs: &[HttpMessage]) -> usize {
        msgs.iter()
            .filter(|m| matches!(m, HttpMessage::Request(_)))
            .count()
    }

    proptest! {
        #[test]
        fn split_invariance_request(
            body_len in 0usize..200,
            split_at in 1usize..200,
        ) {
            let body = vec![b'x'; body_len];
            let bytes = build_request("POST", "/test", &body);
            let split = split_at.min(bytes.len().saturating_sub(1)).max(1);

            // One-shot feed.
            let mut p1 = HttpParser::default();
            let mut m1 = Vec::new();
            p1.feed_initiator(&bytes, Timestamp::default(), &mut m1);

            // Two-chunk feed.
            let mut p2 = HttpParser::default();
            let mut m2 = Vec::new();
            p2.feed_initiator(&bytes[..split], Timestamp::default(), &mut m2);
            p2.feed_initiator(&bytes[split..], Timestamp::default(), &mut m2);

            prop_assert_eq!(count_requests(&m1), 1);
            prop_assert_eq!(count_requests(&m2), 1);
        }

        #[test]
        fn pipelined_request_count_matches(
            n in 1usize..6,
        ) {
            let mut bytes = Vec::new();
            for i in 0..n {
                bytes.extend_from_slice(&build_request("GET", &format!("/p{i}"), b""));
            }
            let mut p = HttpParser::default();
            let mut msgs = Vec::new();
            p.feed_initiator(&bytes, Timestamp::default(), &mut msgs);
            prop_assert_eq!(count_requests(&msgs), n);
        }

        #[test]
        fn no_panic_on_random_bytes(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
            let mut p = HttpParser::default();
            // The contract is "don't panic", not "parse anything".
            let mut sink = Vec::new();
            p.feed_initiator(&bytes, Timestamp::default(), &mut sink);
            sink.clear();
            p.feed_responder(&bytes, Timestamp::default(), &mut sink);
            p.rst_initiator();
            p.rst_responder();
        }

        /// Inline mode: whatever the split, exactly one RequestHead is
        /// emitted per bodied POST and the body is never surfaced —
        /// the head appears regardless of how the body is chunked
        /// across feeds.
        #[test]
        fn inline_split_invariance_head(
            body_len in 0usize..200,
            split_at in 1usize..300,
        ) {
            let body = vec![b'x'; body_len];
            let bytes = build_request("POST", "/test", &body);
            let split = split_at.min(bytes.len().saturating_sub(1)).max(1);

            let mut p1 = inline_parser();
            let mut m1 = Vec::new();
            p1.feed_initiator(&bytes, Timestamp::default(), &mut m1);

            let mut p2 = inline_parser();
            let mut m2 = Vec::new();
            p2.feed_initiator(&bytes[..split], Timestamp::default(), &mut m2);
            p2.feed_initiator(&bytes[split..], Timestamp::default(), &mut m2);

            prop_assert_eq!(count_heads(&m1), 1);
            prop_assert_eq!(count_heads(&m2), 1);
            // No full Request is ever emitted in inline mode.
            prop_assert_eq!(count_requests(&m1), 0);
            prop_assert_eq!(count_requests(&m2), 0);
        }

        /// Inline mode over pipelined bodied requests: one head per
        /// request, no matter the count — proves the body-skip finds
        /// every boundary.
        #[test]
        fn inline_pipelined_head_count(n in 1usize..6) {
            let mut bytes = Vec::new();
            for i in 0..n {
                bytes.extend_from_slice(&build_request("POST", &format!("/p{i}"), b"abc"));
            }
            let mut p = inline_parser();
            let mut msgs = Vec::new();
            p.feed_initiator(&bytes, Timestamp::default(), &mut msgs);
            prop_assert_eq!(count_heads(&msgs), n);
        }

        #[test]
        fn inline_no_panic_on_random_bytes(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
            let mut p = inline_parser();
            let mut sink = Vec::new();
            p.feed_initiator(&bytes, Timestamp::default(), &mut sink);
            sink.clear();
            p.feed_responder(&bytes, Timestamp::default(), &mut sink);
        }
    }
}

// ── TLS ────────────────────────────────────────────────────────────

#[cfg(feature = "tls")]
mod tls_props {
    use flowscope::{
        SessionParser, Timestamp,
        tls::{TlsMessage, TlsParser},
    };

    use super::*;

    fn build_client_hello() -> Vec<u8> {
        let mut ch_body = Vec::new();
        ch_body.extend_from_slice(&[0x03, 0x03]);
        ch_body.extend_from_slice(&[0u8; 32]);
        ch_body.push(0);
        ch_body.extend_from_slice(&[0, 2, 0x13, 0x01]);
        ch_body.extend_from_slice(&[1, 0]);
        ch_body.extend_from_slice(&[0, 0]);

        let mut handshake = Vec::new();
        handshake.push(0x01);
        let len = ch_body.len();
        handshake.push(((len >> 16) & 0xff) as u8);
        handshake.push(((len >> 8) & 0xff) as u8);
        handshake.push((len & 0xff) as u8);
        handshake.extend_from_slice(&ch_body);

        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    fn count_client_hello(msgs: &[TlsMessage]) -> usize {
        msgs.iter()
            .filter(|m| matches!(m, TlsMessage::ClientHello(_)))
            .count()
    }

    proptest! {
        #[test]
        fn split_invariance_client_hello(
            split_at in 1usize..200,
        ) {
            let bytes = build_client_hello();
            let split = split_at.min(bytes.len().saturating_sub(1)).max(1);

            let mut p1 = TlsParser::default();
            let mut m1 = Vec::new();
            p1.feed_initiator(&bytes, Timestamp::default(), &mut m1);

            let mut p2 = TlsParser::default();
            let mut m2 = Vec::new();
            p2.feed_initiator(&bytes[..split], Timestamp::default(), &mut m2);
            p2.feed_initiator(&bytes[split..], Timestamp::default(), &mut m2);

            prop_assert_eq!(count_client_hello(&m1), 1);
            prop_assert_eq!(count_client_hello(&m2), 1);
        }

        #[test]
        fn no_panic_on_random_bytes(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
            let mut p = TlsParser::default();
            let mut sink = Vec::new();
            p.feed_initiator(&bytes, Timestamp::default(), &mut sink);
            sink.clear();
            p.feed_responder(&bytes, Timestamp::default(), &mut sink);
            p.rst_initiator();
            p.rst_responder();
        }
    }
}

// ── DNS UDP (DatagramParser) ───────────────────────────────────────

#[cfg(feature = "dns")]
mod dns_udp_props {
    use flowscope::{
        DatagramParser, FlowSide, Timestamp,
        dns::{DnsMessage, DnsUdpParser},
    };

    use super::*;

    fn build_a_query(tx_id: u16, qname: &str) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&tx_id.to_be_bytes());
        v.extend_from_slice(&0x0100u16.to_be_bytes());
        v.extend_from_slice(&1u16.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        v.extend_from_slice(&0u16.to_be_bytes());
        for label in qname.split('.') {
            v.push(label.len() as u8);
            v.extend_from_slice(label.as_bytes());
        }
        v.push(0);
        v.extend_from_slice(&1u16.to_be_bytes());
        v.extend_from_slice(&1u16.to_be_bytes());
        v
    }

    proptest! {
        #[test]
        fn random_tx_id_round_trips(tx_id in any::<u16>()) {
            let bytes = build_a_query(tx_id, "example.com");
            let mut p = DnsUdpParser::new();
            let mut msgs = Vec::new();
            p.parse(&bytes, FlowSide::Initiator, Timestamp::default(), &mut msgs);
            prop_assert_eq!(msgs.len(), 1);
            match &msgs[0] {
                DnsMessage::Query(q) => prop_assert_eq!(q.transaction_id, tx_id),
                _ => prop_assert!(false, "expected Query"),
            }
        }

        #[test]
        fn no_panic_on_random_bytes(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
            let mut p = DnsUdpParser::new();
            let mut sink = Vec::new();
            p.parse(&bytes, FlowSide::Initiator, Timestamp::default(), &mut sink);
            sink.clear();
            p.parse(&bytes, FlowSide::Responder, Timestamp::default(), &mut sink);
        }
    }
}

// ── DNS TCP (SessionParser, length-framed) ─────────────────────────

#[cfg(feature = "dns")]
mod dns_tcp_props {
    use flowscope::{
        SessionParser, Timestamp,
        dns::{DnsMessage, DnsTcpParser},
    };

    use super::*;

    fn build_a_query_tcp(tx_id: u16, qname: &str) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&tx_id.to_be_bytes());
        body.extend_from_slice(&0x0100u16.to_be_bytes());
        body.extend_from_slice(&1u16.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        for label in qname.split('.') {
            body.push(label.len() as u8);
            body.extend_from_slice(label.as_bytes());
        }
        body.push(0);
        body.extend_from_slice(&1u16.to_be_bytes());
        body.extend_from_slice(&1u16.to_be_bytes());

        let mut frame = Vec::new();
        frame.extend_from_slice(&(body.len() as u16).to_be_bytes());
        frame.extend_from_slice(&body);
        frame
    }

    fn count_queries(msgs: &[DnsMessage]) -> usize {
        msgs.iter()
            .filter(|m| matches!(m, DnsMessage::Query(_)))
            .count()
    }

    proptest! {
        #[test]
        fn split_invariance_pipelined(
            n in 1usize..5,
            split_at in 1usize..400,
        ) {
            let mut bytes = Vec::new();
            for i in 0..n {
                bytes.extend_from_slice(&build_a_query_tcp(
                    i as u16,
                    &format!("p{i}.example"),
                ));
            }
            let split = split_at.min(bytes.len().saturating_sub(1)).max(1);

            let mut p1 = DnsTcpParser::default();
            let mut m1 = Vec::new();
            p1.feed_initiator(&bytes, Timestamp::default(), &mut m1);

            let mut p2 = DnsTcpParser::default();
            let mut m2 = Vec::new();
            p2.feed_initiator(&bytes[..split], Timestamp::default(), &mut m2);
            p2.feed_initiator(&bytes[split..], Timestamp::default(), &mut m2);

            prop_assert_eq!(count_queries(&m1), n);
            prop_assert_eq!(count_queries(&m2), n);
        }

        #[test]
        fn byte_at_a_time_invariance(n in 1usize..4) {
            let mut bytes = Vec::new();
            for i in 0..n {
                bytes.extend_from_slice(&build_a_query_tcp(
                    i as u16,
                    &format!("b{i}.example"),
                ));
            }
            let mut p = DnsTcpParser::default();
            let mut all = Vec::new();
            for chunk in bytes.chunks(1) {
                p.feed_initiator(chunk, Timestamp::default(), &mut all);
            }
            prop_assert_eq!(count_queries(&all), n);
        }

        #[test]
        fn no_panic_on_random_bytes(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
            let mut p = DnsTcpParser::default();
            let mut sink = Vec::new();
            p.feed_initiator(&bytes, Timestamp::default(), &mut sink);
            sink.clear();
            p.feed_responder(&bytes, Timestamp::default(), &mut sink);
            p.rst_initiator();
            p.rst_responder();
        }

        #[test]
        fn malformed_body_keeps_framing(
            garbage_len in 1u16..=200,
        ) {
            let mut bytes = Vec::new();
            // Length prefix says `garbage_len` bytes follow.
            bytes.extend_from_slice(&garbage_len.to_be_bytes());
            // Garbage body of that length.
            bytes.extend(std::iter::repeat_n(0xff_u8, garbage_len as usize));
            // Then a valid query the parser should still decode.
            bytes.extend_from_slice(&build_a_query_tcp(99, "valid.after"));

            let mut p = DnsTcpParser::default();
            let mut msgs = Vec::new();
            p.feed_initiator(&bytes, Timestamp::default(), &mut msgs);
            prop_assert_eq!(count_queries(&msgs), 1);
        }
    }
}

//! [`DnsTcpParser`] — `SessionParser` impl for DNS over TCP (RFC 1035
//! §4.2.2).
//!
//! TCP-encoded DNS messages are preceded by a 2-byte big-endian
//! length field. The parser reads `len`, then `len` bytes of message
//! body, parses it via [`crate::dns::parse_message`], emits the
//! message, then loops for the next length-prefixed frame.
//!
//! Pair with `netring::FlowStream::session_stream(...)` for an async
//! iterator API. Both directions are independent (queries on
//! initiator, responses on responder); each direction's bytes flow
//! through its own length-framed state machine.
//!
//! # Scope
//!
//! - DNS over **TCP/53** (and DoT after TLS termination, fed as
//!   plaintext bytes).
//! - All record types decoded by [`crate::dns::parse_message`]: A,
//!   AAAA, CNAME, NS, PTR, MX. Everything else surfaces as
//!   `DnsRdata::Other`.
//! - Out of scope: AXFR/IXFR multi-message zone-transfer correlation,
//!   EDNS(0) option decoding (the OPT pseudo-record falls into
//!   `Other`).

use crate::{SessionParser, Timestamp};

use super::datagram::DnsMessage;
use super::parser::{DnsParseResult, parse_message};

/// Per-flow DNS-over-TCP parser. Holds independent length-framed
/// buffers for the initiator (queries) and responder (responses).
///
/// Implements `Default + Clone` so it works as a `SessionParserFactory`
/// directly — every new flow gets a fresh clone.
#[derive(Debug, Default, Clone)]
pub struct DnsTcpParser {
    init_buf: Vec<u8>,
    resp_buf: Vec<u8>,
}

impl DnsTcpParser {
    /// Drain as many length-prefixed messages as possible from `buf`.
    /// `buf` is mutated in place: consumed bytes are drained from the
    /// front; partial messages stay buffered for the next call.
    fn drain(buf: &mut Vec<u8>) -> Vec<DnsMessage> {
        let mut out = Vec::new();
        loop {
            // Need at least 2 bytes for the length prefix.
            if buf.len() < 2 {
                return out;
            }
            let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
            // Need full message body.
            if buf.len() < 2 + len {
                return out;
            }
            // Peel off the length-prefixed frame.
            let frame_total = 2 + len;
            let body = &buf[2..frame_total];
            match parse_message(body) {
                Ok(DnsParseResult::Query(q)) => out.push(DnsMessage::Query(q)),
                Ok(DnsParseResult::Response(r)) => out.push(DnsMessage::Response(r)),
                Err(_) => {
                    // Malformed message — drop and continue. The
                    // length prefix still tells us how many bytes to
                    // skip, so we don't lose framing.
                }
            }
            // Drain consumed bytes; remaining (if any) becomes the
            // start of the next iteration.
            buf.drain(..frame_total);
        }
    }
}

impl SessionParser for DnsTcpParser {
    type Message = DnsMessage;

    fn feed_initiator(&mut self, bytes: &[u8], _ts: Timestamp) -> Vec<DnsMessage> {
        if bytes.is_empty() {
            return Vec::new();
        }
        self.init_buf.extend_from_slice(bytes);
        Self::drain(&mut self.init_buf)
    }

    fn feed_responder(&mut self, bytes: &[u8], _ts: Timestamp) -> Vec<DnsMessage> {
        if bytes.is_empty() {
            return Vec::new();
        }
        self.resp_buf.extend_from_slice(bytes);
        Self::drain(&mut self.resp_buf)
    }

    fn rst_initiator(&mut self) {
        self.init_buf.clear();
    }

    fn rst_responder(&mut self) {
        self.resp_buf.clear();
    }

    fn parser_kind(&self) -> &'static str {
        crate::dns::PARSER_KIND_TCP
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a length-prefixed wire-format DNS A query for `qname`.
    fn build_a_query_tcp(tx_id: u16, qname: &str) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&tx_id.to_be_bytes());
        body.extend_from_slice(&0x0100u16.to_be_bytes()); // flags
        body.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        body.extend_from_slice(&0u16.to_be_bytes()); // ancount
        body.extend_from_slice(&0u16.to_be_bytes()); // nscount
        body.extend_from_slice(&0u16.to_be_bytes()); // arcount
        for label in qname.split('.') {
            body.push(label.len() as u8);
            body.extend_from_slice(label.as_bytes());
        }
        body.push(0);
        body.extend_from_slice(&1u16.to_be_bytes()); // qtype A
        body.extend_from_slice(&1u16.to_be_bytes()); // qclass IN

        let mut frame = Vec::new();
        frame.extend_from_slice(&(body.len() as u16).to_be_bytes());
        frame.extend_from_slice(&body);
        frame
    }

    #[test]
    fn parses_one_query() {
        let mut p = DnsTcpParser::default();
        let bytes = build_a_query_tcp(0x1234, "example.com");
        let msgs = p.feed_initiator(&bytes, Timestamp::default());
        assert_eq!(msgs.len(), 1);
        match &msgs[0] {
            DnsMessage::Query(q) => assert_eq!(q.transaction_id, 0x1234),
            _ => panic!("expected Query"),
        }
    }

    #[test]
    fn parses_multiple_pipelined_queries() {
        let mut p = DnsTcpParser::default();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&build_a_query_tcp(1, "a.example"));
        bytes.extend_from_slice(&build_a_query_tcp(2, "b.example"));
        bytes.extend_from_slice(&build_a_query_tcp(3, "c.example"));
        let msgs = p.feed_initiator(&bytes, Timestamp::default());
        assert_eq!(msgs.len(), 3);
    }

    #[test]
    fn split_segments_concatenate() {
        let mut p = DnsTcpParser::default();
        let bytes = build_a_query_tcp(42, "split.example");
        // Feed one byte at a time.
        let mut all = Vec::new();
        for chunk in bytes.chunks(1) {
            all.extend(p.feed_initiator(chunk, Timestamp::default()));
        }
        assert_eq!(all.len(), 1);
        match &all[0] {
            DnsMessage::Query(q) => assert_eq!(q.transaction_id, 42),
            _ => panic!("expected Query"),
        }
    }

    #[test]
    fn split_at_length_prefix() {
        let mut p = DnsTcpParser::default();
        let bytes = build_a_query_tcp(7, "prefix.split");
        // Feed first byte alone (incomplete length prefix).
        assert!(
            p.feed_initiator(&bytes[..1], Timestamp::default())
                .is_empty()
        );
        // Feed everything else — should emit one Query.
        let msgs = p.feed_initiator(&bytes[1..], Timestamp::default());
        assert_eq!(msgs.len(), 1);
    }

    #[test]
    fn malformed_body_consumes_frame_and_keeps_framing() {
        let mut p = DnsTcpParser::default();
        // Length prefix says 12 bytes (the minimum DNS header), but
        // body is malformed garbage.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&12u16.to_be_bytes());
        bytes.extend_from_slice(&[0xff; 12]);
        // Then a valid query.
        bytes.extend_from_slice(&build_a_query_tcp(99, "valid.after"));
        let msgs = p.feed_initiator(&bytes, Timestamp::default());
        // Malformed first frame is dropped; valid second emits.
        assert_eq!(msgs.len(), 1);
        match &msgs[0] {
            DnsMessage::Query(q) => assert_eq!(q.transaction_id, 99),
            _ => panic!("expected Query"),
        }
    }

    #[test]
    fn rst_clears_buffer() {
        let mut p = DnsTcpParser::default();
        let bytes = build_a_query_tcp(1, "partial.example");
        // Feed half — nothing emits.
        assert!(
            p.feed_initiator(&bytes[..bytes.len() / 2], Timestamp::default())
                .is_empty()
        );
        p.rst_initiator();
        assert!(p.init_buf.is_empty());
    }

    #[test]
    fn empty_feed_returns_empty() {
        let mut p = DnsTcpParser::default();
        assert!(p.feed_initiator(&[], Timestamp::default()).is_empty());
        assert!(p.feed_responder(&[], Timestamp::default()).is_empty());
    }

    #[test]
    fn auto_factory_via_default_clone() {
        // DnsTcpParser is Default + Clone + SessionParser, so the
        // blanket impl makes it its own factory.
        use crate::SessionParserFactory;
        let mut f = DnsTcpParser::default();
        let mut p: DnsTcpParser = SessionParserFactory::<()>::new_parser(&mut f, &());
        let bytes = build_a_query_tcp(7, "auto.factory");
        let msgs = p.feed_initiator(&bytes, Timestamp::default());
        assert_eq!(msgs.len(), 1);
    }
}

//! [`DnsUdpParser`] — `DatagramParser` impl that surfaces DNS
//! query/response messages, with optional query/response
//! correlation.
//!
//! Pair with `netring::FlowStream::datagram_stream(...)` for an
//! async iterator API, or [`crate::FlowDatagramDriver`] /
//! [`crate::pcap::PcapFlowSource::datagrams`] for the sync path.

use crate::{DatagramParser, FlowSide, Timestamp};

use super::correlator::Correlator;
use super::parser::{DnsParseResult, parse_message_at};
use super::types::{DnsConfig, DnsQuery, DnsResponse};

/// Unified message type emitted by [`DnsUdpParser`].
///
/// `#[non_exhaustive]` — match with a trailing `_ => {}` arm.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "type", content = "data", rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum DnsMessage {
    /// A query observed on the wire.
    Query(DnsQuery),
    /// A response. With correlation enabled, `elapsed` carries the
    /// round-trip time since the matching query.
    Response(DnsResponse),
    /// A query that received no response within `query_timeout`.
    /// Emitted by [`DatagramParser::on_tick`] when correlation is
    /// enabled (see [`DnsUdpParser::with_correlation`]).
    Unanswered(DnsQuery),
}

/// Per-flow DNS-over-UDP parser.
///
/// Without correlation (the default), each datagram is parsed
/// independently. With correlation enabled — [`Self::with_correlation`]
/// or [`Self::with_config`] — `Response` messages carry RTT in their
/// `elapsed` field, and [`DatagramParser::on_tick`] emits
/// [`DnsMessage::Unanswered`] for queries left unanswered past
/// `query_timeout`.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct DnsUdpParser {
    /// `Some` when correlation is enabled. The parser is per-flow,
    /// so transaction IDs never collide across flows — a scope-free
    /// `Correlator<()>` is sufficient.
    correlator: Option<Correlator<()>>,
}

impl DnsUdpParser {
    /// No correlation — each datagram parsed independently. Same as
    /// [`Default`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable query/response correlation with the default
    /// [`DnsConfig`].
    pub fn with_correlation() -> Self {
        Self {
            correlator: Some(Correlator::new()),
        }
    }

    /// Enable correlation with an explicit [`DnsConfig`]
    /// (`query_timeout`, `max_pending`).
    pub fn with_config(config: DnsConfig) -> Self {
        Self {
            correlator: Some(Correlator::with_config(config)),
        }
    }
}

impl DatagramParser for DnsUdpParser {
    type Message = DnsMessage;

    fn parse(&mut self, payload: &[u8], _side: FlowSide, ts: Timestamp) -> Vec<DnsMessage> {
        match parse_message_at(payload, ts) {
            Ok(DnsParseResult::Query(q)) => {
                if let Some(c) = &mut self.correlator {
                    c.record_query((), q.clone());
                }
                vec![DnsMessage::Query(q)]
            }
            Ok(DnsParseResult::Response(mut r)) => {
                if let Some(c) = &mut self.correlator
                    && let Some((_, elapsed)) = c.match_response(&(), r.transaction_id, ts)
                {
                    r.elapsed = Some(elapsed);
                }
                vec![DnsMessage::Response(r)]
            }
            Err(_) => Vec::new(),
        }
    }

    fn on_tick(&mut self, now: Timestamp) -> Vec<DnsMessage> {
        match &mut self.correlator {
            Some(c) => c
                .sweep(now)
                .into_iter()
                .map(DnsMessage::Unanswered)
                .collect(),
            None => Vec::new(),
        }
    }

    fn parser_kind(&self) -> &'static str {
        crate::dns::PARSER_KIND_UDP
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Build a wire-format DNS message for `qname` with the given
    /// header `flags` (`0x0100` for a query, `0x8100` for a
    /// response).
    fn build_msg(tx_id: u16, qname: &str, flags: u16) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&tx_id.to_be_bytes());
        v.extend_from_slice(&flags.to_be_bytes());
        v.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        v.extend_from_slice(&0u16.to_be_bytes()); // ancount
        v.extend_from_slice(&0u16.to_be_bytes()); // nscount
        v.extend_from_slice(&0u16.to_be_bytes()); // arcount
        for label in qname.split('.') {
            v.push(label.len() as u8);
            v.extend_from_slice(label.as_bytes());
        }
        v.push(0);
        v.extend_from_slice(&1u16.to_be_bytes()); // qtype A
        v.extend_from_slice(&1u16.to_be_bytes()); // qclass IN
        v
    }

    #[test]
    fn parses_query() {
        let mut p = DnsUdpParser::new();
        let bytes = build_msg(0xabcd, "example.com", 0x0100);
        let msgs = p.parse(&bytes, FlowSide::Initiator, Timestamp::default());
        assert_eq!(msgs.len(), 1);
        match &msgs[0] {
            DnsMessage::Query(q) => assert_eq!(q.transaction_id, 0xabcd),
            _ => panic!("expected Query"),
        }
    }

    #[test]
    fn malformed_returns_empty() {
        let mut p = DnsUdpParser::new();
        let msgs = p.parse(b"\x00", FlowSide::Initiator, Timestamp::default());
        assert!(msgs.is_empty());
    }

    #[test]
    fn correlation_sets_elapsed_on_response() {
        let mut p = DnsUdpParser::with_correlation();
        let q = build_msg(0x1234, "example.com", 0x0100);
        p.parse(&q, FlowSide::Initiator, Timestamp::new(10, 0));
        let r = build_msg(0x1234, "example.com", 0x8100);
        let msgs = p.parse(&r, FlowSide::Responder, Timestamp::new(10, 500_000_000));
        assert_eq!(msgs.len(), 1);
        match &msgs[0] {
            DnsMessage::Response(resp) => {
                assert_eq!(resp.elapsed, Some(Duration::from_millis(500)));
            }
            _ => panic!("expected Response"),
        }
    }

    #[test]
    fn on_tick_emits_unanswered_after_timeout() {
        let mut p = DnsUdpParser::with_correlation();
        let q = build_msg(0x9, "slow.example", 0x0100);
        p.parse(&q, FlowSide::Initiator, Timestamp::new(0, 0));
        // Before query_timeout (default 30 s) — nothing.
        assert!(p.on_tick(Timestamp::new(5, 0)).is_empty());
        // Past the timeout — the unanswered query surfaces.
        let ticked = p.on_tick(Timestamp::new(60, 0));
        assert_eq!(ticked.len(), 1);
        assert!(matches!(&ticked[0], DnsMessage::Unanswered(uq) if uq.transaction_id == 9));
    }

    #[test]
    fn matched_query_not_reported_unanswered() {
        let mut p = DnsUdpParser::with_correlation();
        let q = build_msg(0x9, "x.example", 0x0100);
        p.parse(&q, FlowSide::Initiator, Timestamp::new(0, 0));
        let r = build_msg(0x9, "x.example", 0x8100);
        p.parse(&r, FlowSide::Responder, Timestamp::new(1, 0));
        // The query was answered → never reported unanswered.
        assert!(p.on_tick(Timestamp::new(60, 0)).is_empty());
    }

    #[test]
    fn without_correlation_no_rtt_no_unanswered() {
        let mut p = DnsUdpParser::new();
        let q = build_msg(0x1, "x.example", 0x0100);
        p.parse(&q, FlowSide::Initiator, Timestamp::new(0, 0));
        let r = build_msg(0x1, "x.example", 0x8100);
        let msgs = p.parse(&r, FlowSide::Responder, Timestamp::new(1, 0));
        match &msgs[0] {
            DnsMessage::Response(resp) => assert!(resp.elapsed.is_none()),
            _ => panic!("expected Response"),
        }
        assert!(p.on_tick(Timestamp::new(99, 0)).is_empty());
    }
}

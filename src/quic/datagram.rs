//! [`QuicUdpParser`] — `DatagramParser` over UDP/443.

use super::parser::{PARSER_KIND_STR, parse};
use super::types::QuicInitial;
use crate::Timestamp;
use crate::event::FlowSide;
use crate::session::DatagramParser;

/// The IANA-assigned QUIC port. Real-world deployments may
/// also use 80 (h3 over alternate-svc) and arbitrary ports;
/// route additional ports yourself via the typed driver.
pub const QUIC_PORT: u16 = 443;

#[derive(Debug, Clone, Copy, Default)]
pub struct QuicUdpParser;

impl QuicUdpParser {
    pub fn new() -> Self {
        Self
    }
}

impl DatagramParser for QuicUdpParser {
    type Message = QuicInitial;

    fn parser_kind(&self) -> &'static str {
        PARSER_KIND_STR
    }

    fn parse(
        &mut self,
        payload: &[u8],
        _side: FlowSide,
        _ts: Timestamp,
        out: &mut Vec<Self::Message>,
    ) {
        if let Some(msg) = parse(payload) {
            out.push(msg);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_kind_and_port() {
        let p = QuicUdpParser::new();
        assert_eq!(p.parser_kind(), "quic");
        assert_eq!(QUIC_PORT, 443);
    }

    #[test]
    fn empty_payload_yields_no_message() {
        let mut p = QuicUdpParser::new();
        let mut out = Vec::new();
        p.parse(&[], FlowSide::Initiator, Timestamp::default(), &mut out);
        assert!(out.is_empty());
    }
}

//! [`NbnsParser`] — `DatagramParser` impl over UDP/137.

use super::parser::parse;
use super::types::NbnsMessage;
use crate::Timestamp;
use crate::event::FlowSide;
use crate::session::DatagramParser;

/// Stable identifier returned by `NbnsParser::parser_kind()`.
pub const PARSER_KIND: &str = "netbios-ns";

/// IANA-assigned NetBIOS Name Service UDP port.
pub const NBNS_PORT: u16 = 137;

/// `DatagramParser` that emits one [`NbnsMessage`] per
/// well-formed NBNS datagram. No per-connection state — NBNS
/// is purely request/response over UDP.
#[derive(Debug, Clone, Copy, Default)]
pub struct NbnsParser;

impl NbnsParser {
    pub fn new() -> Self {
        Self
    }
}

impl DatagramParser for NbnsParser {
    type Message = NbnsMessage;

    fn parser_kind(&self) -> &'static str {
        PARSER_KIND
    }

    fn parse(
        &mut self,
        payload: &[u8],
        _side: FlowSide,
        _ts: Timestamp,
        out: &mut Vec<Self::Message>,
    ) {
        if let Ok(msg) = parse(payload) {
            out.push(msg);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_kind_label() {
        let p = NbnsParser;
        assert_eq!(p.parser_kind(), "netbios-ns");
    }

    #[test]
    fn nbns_port_constant_matches_iana() {
        assert_eq!(NBNS_PORT, 137);
    }

    #[test]
    fn malformed_payload_emits_nothing() {
        let mut parser = NbnsParser;
        let mut out = Vec::new();
        parser.parse(
            b"too short",
            FlowSide::Initiator,
            Timestamp::default(),
            &mut out,
        );
        assert!(out.is_empty());
    }
}

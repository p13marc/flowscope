//! [`SsdpParser`] — `DatagramParser` impl over UDP/1900.

use super::parser::parse;
use super::types::SsdpMessage;
use crate::Timestamp;
use crate::event::FlowSide;
use crate::session::DatagramParser;

/// Stable identifier returned by `SsdpParser::parser_kind()`.
pub const PARSER_KIND: &str = "ssdp";

/// The well-known SSDP UDP port.
pub const SSDP_MULTICAST_PORT: u16 = 1900;

/// `DatagramParser` that emits one [`SsdpMessage`] per
/// well-formed SSDP datagram.
#[derive(Debug, Clone, Copy, Default)]
pub struct SsdpParser;

impl SsdpParser {
    /// Construct a fresh parser. No tunables today.
    pub fn new() -> Self {
        Self
    }
}

impl DatagramParser for SsdpParser {
    type Message = SsdpMessage;

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
        if let Some(msg) = parse(payload) {
            out.push(msg);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssdp::SsdpKind;

    #[test]
    fn parser_kind_label() {
        let p = SsdpParser;
        assert_eq!(p.parser_kind(), "ssdp");
    }

    #[test]
    fn ssdp_port_constant_matches_iana() {
        assert_eq!(SSDP_MULTICAST_PORT, 1900);
    }

    #[test]
    fn end_to_end_msearch() {
        let payload = concat!(
            "M-SEARCH * HTTP/1.1\r\n",
            "HOST: 239.255.255.250:1900\r\n",
            "MAN: \"ssdp:discover\"\r\n",
            "MX: 3\r\n",
            "ST: ssdp:all\r\n",
            "\r\n",
        );
        let mut parser = SsdpParser::new();
        let mut out = Vec::new();
        parser.parse(
            payload.as_bytes(),
            FlowSide::Initiator,
            Timestamp::default(),
            &mut out,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, SsdpKind::MSearch);
    }

    #[test]
    fn malformed_payload_emits_nothing() {
        let mut parser = SsdpParser::new();
        let mut out = Vec::new();
        parser.parse(
            b"garbage",
            FlowSide::Initiator,
            Timestamp::default(),
            &mut out,
        );
        assert!(out.is_empty());
    }
}

//! [`DhcpParser`] — `DatagramParser` impl over UDP/67-68.
//!
//! Issue #11 (0.18).

use super::parser::parse;
use super::types::DhcpMessage;
use crate::Timestamp;
use crate::event::FlowSide;
use crate::session::DatagramParser;

/// `DatagramParser` that emits one [`DhcpMessage`] per
/// well-formed DHCP datagram.
///
/// Register on UDP ports 67 (BOOTP server) and 68 (BOOTP
/// client) — most DHCP traffic is captured on these.
#[derive(Debug, Clone, Copy, Default)]
pub struct DhcpParser;

impl DhcpParser {
    /// Construct a default parser. No tunables today.
    pub fn new() -> Self {
        Self
    }
}

/// Stable identifier for the parser. Mirrors the
/// [`crate::parser_kinds`] convention.
pub const PARSER_KIND: &str = "dhcp";

impl DatagramParser for DhcpParser {
    type Message = DhcpMessage;

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
    use crate::dhcp::types::DhcpMessageType;

    #[test]
    fn parser_kind_label() {
        let p = DhcpParser;
        assert_eq!(p.parser_kind(), "dhcp");
    }

    #[test]
    fn end_to_end_discover() {
        // Hand-rolled minimal DHCPDISCOVER datagram.
        let mut p = vec![0u8; 236];
        p[0] = 1; // BootRequest
        p[1] = 1; // htype Ethernet
        p[2] = 6; // hlen
        p[4..8].copy_from_slice(&0x12345678u32.to_be_bytes());
        p[28..34].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
        // Magic cookie + opt 53 DISCOVER + opt 55 PRL + opt 60 + END.
        p.extend_from_slice(&[99, 130, 83, 99]);
        p.extend_from_slice(&[53, 1, 1]);
        p.extend_from_slice(&[55, 4, 1, 3, 6, 15]);
        p.extend_from_slice(&[60, 8, b'M', b'S', b'F', b'T', b' ', b'5', b'.', b'0']);
        p.push(255);

        let mut parser = DhcpParser::new();
        let mut out = Vec::new();
        parser.parse(&p, FlowSide::Initiator, Timestamp::default(), &mut out);
        assert_eq!(out.len(), 1);
        let msg = &out[0];
        assert_eq!(msg.msg_type, Some(DhcpMessageType::Discover));
        assert_eq!(msg.fingerprint().as_deref(), Some("1,3,6,15|MSFT 5.0"));
    }

    #[test]
    fn malformed_payload_emits_nothing() {
        let mut parser = DhcpParser::new();
        let mut out = Vec::new();
        parser.parse(
            b"garbage",
            FlowSide::Initiator,
            Timestamp::default(),
            &mut out,
        );
        assert_eq!(out.len(), 0);
    }
}

//! [`TftpParser`] — `DatagramParser` impl over UDP/69.

use super::parser::parse;
use super::types::TftpMessage;
use crate::Timestamp;
use crate::event::FlowSide;
use crate::session::DatagramParser;

/// Stable identifier returned by `TftpParser::parser_kind()`.
pub const PARSER_KIND: &str = "tftp";

/// The well-known TFTP server port.
///
/// Note: only the initial RRQ / WRQ goes to port 69 — the
/// rest of the transfer happens on an ephemeral port the
/// server allocates per RFC 1350 §4. Consumers wiring up
/// dispatch should register the parser on both 69 and the
/// flow's responder ephemeral.
pub const TFTP_SERVER_PORT: u16 = 69;

/// `DatagramParser` that emits one [`TftpMessage`] per
/// well-formed TFTP packet.
#[derive(Debug, Clone, Copy, Default)]
pub struct TftpParser;

impl TftpParser {
    /// Construct a fresh parser. No tunables today.
    pub fn new() -> Self {
        Self
    }
}

impl DatagramParser for TftpParser {
    type Message = TftpMessage;

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
    use crate::tftp::{TftpMode, TftpOpcode};

    #[test]
    fn parser_kind_label() {
        let p = TftpParser;
        assert_eq!(p.parser_kind(), "tftp");
    }

    #[test]
    fn server_port_constant_matches_iana() {
        assert_eq!(TFTP_SERVER_PORT, 69);
    }

    #[test]
    fn end_to_end_rrq() {
        let mut payload = vec![0x00, 0x01];
        payload.extend_from_slice(b"firmware.bin\0octet\0");
        let mut parser = TftpParser::new();
        let mut out = Vec::new();
        parser.parse(
            &payload,
            FlowSide::Initiator,
            Timestamp::default(),
            &mut out,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].opcode, TftpOpcode::ReadRequest);
        assert_eq!(out[0].mode, Some(TftpMode::Octet));
    }

    #[test]
    fn malformed_payload_emits_nothing() {
        let mut parser = TftpParser::new();
        let mut out = Vec::new();
        parser.parse(&[], FlowSide::Initiator, Timestamp::default(), &mut out);
        assert!(out.is_empty());
    }
}

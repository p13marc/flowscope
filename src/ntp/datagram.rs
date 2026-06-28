//! [`NtpParser`] — `DatagramParser` impl over UDP/123.

use super::parser::parse;
use super::types::NtpMessage;
use crate::Timestamp;
use crate::event::FlowSide;
use crate::session::DatagramParser;

/// Stable identifier returned by `NtpParser::parser_kind()`.
pub const PARSER_KIND: &str = "ntp";

/// `DatagramParser` that emits one [`NtpMessage`] per
/// well-formed NTP / SNTP datagram.
#[derive(Debug, Clone, Copy, Default)]
pub struct NtpParser;

impl NtpParser {
    /// Construct a fresh parser. No tunables today.
    pub fn new() -> Self {
        Self
    }
}

impl DatagramParser for NtpParser {
    type Message = NtpMessage;

    fn parser_kind(&self) -> crate::ParserKind {
        crate::ParserKind::Ntp
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
    use crate::ntp::NtpMode;

    #[test]
    fn parser_kind_label() {
        let p = NtpParser;
        assert_eq!(p.parser_kind().as_str(), "ntp");
    }

    #[test]
    fn end_to_end_client_request() {
        // VN=4, mode=3 (client), 48 bytes.
        let mut payload = vec![0u8; 48];
        payload[0] = (4 << 3) | 3;
        let mut parser = NtpParser::new();
        let mut out = Vec::new();
        parser.parse(
            &payload,
            FlowSide::Initiator,
            Timestamp::default(),
            &mut out,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].mode, NtpMode::Client);
    }

    #[test]
    fn malformed_payload_emits_nothing() {
        let mut parser = NtpParser::new();
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

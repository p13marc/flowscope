//! [`StunParser`] — `DatagramParser` impl.

use super::parser::parse;
use super::types::StunMessage;
use crate::Timestamp;
use crate::event::FlowSide;
use crate::session::DatagramParser;

pub const PARSER_KIND: &str = "stun";

/// Convention port for STUN over UDP (IANA-assigned).
pub const STUN_PORT: u16 = 3478;

/// `DatagramParser` that emits one [`StunMessage`] per
/// well-formed STUN datagram. Aggressive about rejection
/// (top-two-bits-zero + magic cookie + length consistency
/// all required) so it's safe to attempt on any UDP flow.
#[derive(Debug, Clone, Copy, Default)]
pub struct StunParser;

impl StunParser {
    pub fn new() -> Self {
        Self
    }
}

impl DatagramParser for StunParser {
    type Message = StunMessage;

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
    fn parser_kind_and_port() {
        assert_eq!(StunParser.parser_kind(), "stun");
        assert_eq!(STUN_PORT, 3478);
    }

    #[test]
    fn malformed_payload_emits_nothing() {
        let mut p = StunParser;
        let mut out = Vec::new();
        p.parse(
            b"not stun",
            FlowSide::Initiator,
            Timestamp::default(),
            &mut out,
        );
        assert!(out.is_empty());
    }
}

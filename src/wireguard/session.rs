//! [`WireGuardParser`] — `DatagramParser` impl.

use super::parser::parse;
use super::types::WireGuardMessage;
use crate::Timestamp;
use crate::event::FlowSide;
use crate::session::DatagramParser;

pub const PARSER_KIND: &str = "wireguard";

/// Convention port for WireGuard (no IANA assignment). Most
/// public configs use 51820; corporate / personal setups
/// frequently vary it for obscurity.
pub const WIREGUARD_PORT: u16 = 51820;

/// `DatagramParser` that emits one [`WireGuardMessage`] per
/// well-formed WG datagram. Unknown payloads produce no
/// events — the parser is intentionally aggressive about
/// rejection (length + reserved-zero + type byte all must
/// match exactly) so it's safe to attempt on any UDP flow
/// for opportunistic detection.
#[derive(Debug, Clone, Copy, Default)]
pub struct WireGuardParser;

impl WireGuardParser {
    pub fn new() -> Self {
        Self
    }
}

impl DatagramParser for WireGuardParser {
    type Message = WireGuardMessage;

    fn parser_kind(&self) -> crate::ParserKind {
        crate::ParserKind::WireGuard
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
    fn parser_kind_and_port_constants() {
        assert_eq!(WireGuardParser.parser_kind().as_str(), "wireguard");
        assert_eq!(WIREGUARD_PORT, 51820);
    }

    #[test]
    fn unknown_payload_no_event() {
        let mut p = WireGuardParser;
        let mut out = Vec::new();
        p.parse(
            b"not a wireguard packet",
            FlowSide::Initiator,
            Timestamp::default(),
            &mut out,
        );
        assert!(out.is_empty());
    }
}

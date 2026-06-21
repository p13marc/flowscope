//! [`RadiusParser`] — `DatagramParser` impl over UDP/1812+1813.

use super::parser::parse;
use super::types::RadiusMessage;
use crate::Timestamp;
use crate::event::FlowSide;
use crate::session::DatagramParser;

pub const PARSER_KIND: &str = "radius";

/// IANA-assigned RADIUS authentication port (RFC 2865).
pub const RADIUS_AUTH_PORT: u16 = 1812;
/// IANA-assigned RADIUS accounting port (RFC 2866).
pub const RADIUS_ACCT_PORT: u16 = 1813;

/// `DatagramParser` that emits one [`RadiusMessage`] per
/// well-formed RADIUS datagram.
#[derive(Debug, Clone, Copy, Default)]
pub struct RadiusParser;

impl RadiusParser {
    pub fn new() -> Self {
        Self
    }
}

impl DatagramParser for RadiusParser {
    type Message = RadiusMessage;

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

    #[test]
    fn parser_kind_label_and_ports() {
        assert_eq!(RadiusParser.parser_kind(), "radius");
        assert_eq!(RADIUS_AUTH_PORT, 1812);
        assert_eq!(RADIUS_ACCT_PORT, 1813);
    }

    #[test]
    fn malformed_emits_nothing() {
        let mut p = RadiusParser;
        let mut out = Vec::new();
        p.parse(
            b"garbage",
            FlowSide::Initiator,
            Timestamp::default(),
            &mut out,
        );
        assert!(out.is_empty());
    }
}

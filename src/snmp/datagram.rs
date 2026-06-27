//! [`SnmpParser`] — `DatagramParser` impl over UDP/161+162.

use super::parser::parse;
use super::types::SnmpMessage;
use crate::Timestamp;
use crate::event::FlowSide;
use crate::session::DatagramParser;

pub const PARSER_KIND: &str = "snmp";

/// IANA-assigned SNMP request port.
pub const SNMP_PORT: u16 = 161;
/// IANA-assigned SNMP trap port.
pub const SNMP_TRAP_PORT: u16 = 162;

/// `DatagramParser` that emits one [`SnmpMessage`] per
/// well-formed SNMPv1/v2c datagram. Aggressive about
/// rejection — ASN.1 BER decode failures simply produce no
/// event.
#[derive(Debug, Clone, Copy, Default)]
pub struct SnmpParser;

impl SnmpParser {
    pub fn new() -> Self {
        Self
    }
}

impl DatagramParser for SnmpParser {
    type Message = SnmpMessage;

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
        assert_eq!(SnmpParser.parser_kind(), "snmp");
        assert_eq!(SNMP_PORT, 161);
        assert_eq!(SNMP_TRAP_PORT, 162);
    }

    #[test]
    fn malformed_emits_nothing() {
        let mut p = SnmpParser;
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

//! [`KerberosUdpParser`] — `DatagramParser` over UDP/88
//! Kerberos.

use super::parser::parse;
use super::types::KerberosMessage;
use crate::Timestamp;
use crate::event::FlowSide;
use crate::session::DatagramParser;

/// IANA-assigned Kerberos KDC port.
pub const KERBEROS_PORT: u16 = 88;

#[derive(Debug, Clone, Copy, Default)]
pub struct KerberosUdpParser;

impl KerberosUdpParser {
    pub fn new() -> Self {
        Self
    }
}

impl DatagramParser for KerberosUdpParser {
    type Message = KerberosMessage;

    fn parser_kind(&self) -> crate::ParserKind {
        crate::ParserKind::Kerberos
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
        let p = KerberosUdpParser::new();
        assert_eq!(p.parser_kind().as_str(), "kerberos");
        assert_eq!(KERBEROS_PORT, 88);
    }

    #[test]
    fn empty_payload_yields_no_message() {
        let mut p = KerberosUdpParser::new();
        let mut out = Vec::new();
        p.parse(&[], FlowSide::Initiator, Timestamp::default(), &mut out);
        assert!(out.is_empty());
    }
}

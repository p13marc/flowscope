//! [`LdapParser`] — `SessionParser` over TCP/389. LDAP
//! messages aren't framed by a length prefix; each is a
//! self-describing ASN.1 SEQUENCE. We drain back-to-back
//! messages until the buffer can't yield more.

use bytes::BytesMut;

use super::parser::{PARSER_KIND_STR, parse_with_len};
use super::types::LdapMessage;
use crate::Timestamp;
use crate::session::SessionParser;

/// IANA-assigned LDAP port.
pub const LDAP_PORT: u16 = 389;

const MAX_BUFFER: usize = 256 * 1024;
const MIN_PARSE_BYTES: usize = 2;

#[derive(Debug, Clone, Default)]
pub struct LdapParser {
    init: BytesMut,
    resp: BytesMut,
    poisoned: bool,
}

impl LdapParser {
    pub fn new() -> Self {
        Self::default()
    }

    fn drain(&mut self, side_init: bool, out: &mut Vec<LdapMessage>) {
        let buf = if side_init {
            &mut self.init
        } else {
            &mut self.resp
        };
        loop {
            if buf.len() < MIN_PARSE_BYTES {
                return;
            }
            match parse_with_len(buf) {
                Some((msg, consumed)) if consumed > 0 => {
                    out.push(msg);
                    bytes::Buf::advance(buf, consumed);
                }
                _ => return,
            }
        }
    }
}

impl SessionParser for LdapParser {
    type Message = LdapMessage;

    fn parser_kind(&self) -> &'static str {
        PARSER_KIND_STR
    }

    fn feed_initiator(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<Self::Message>) {
        if self.init.len() + bytes.len() > MAX_BUFFER {
            self.poisoned = true;
            return;
        }
        self.init.extend_from_slice(bytes);
        self.drain(true, out);
    }

    fn feed_responder(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<Self::Message>) {
        if self.resp.len() + bytes.len() > MAX_BUFFER {
            self.poisoned = true;
            return;
        }
        self.resp.extend_from_slice(bytes);
        self.drain(false, out);
    }

    fn is_poisoned(&self) -> bool {
        self.poisoned
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_kind_and_port() {
        let p = LdapParser::new();
        assert_eq!(p.parser_kind(), "ldap");
        assert_eq!(LDAP_PORT, 389);
    }

    #[test]
    fn drains_one_simple_bind() {
        let buf = [
            0x30, 0x0C, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00,
        ];
        let mut p = LdapParser::new();
        let mut out = Vec::new();
        p.feed_initiator(&buf, Timestamp::default(), &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].message_id, 1);
    }

    #[test]
    fn drains_two_back_to_back() {
        let one = [
            0x30, 0x0C, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00,
        ];
        let mut buf = Vec::new();
        buf.extend_from_slice(&one);
        buf.extend_from_slice(&one);
        let mut p = LdapParser::new();
        let mut out = Vec::new();
        p.feed_initiator(&buf, Timestamp::default(), &mut out);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn split_feed_reassembles() {
        let one = [
            0x30, 0x0C, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00,
        ];
        let mut p = LdapParser::new();
        let mut out = Vec::new();
        p.feed_initiator(&one[..5], Timestamp::default(), &mut out);
        assert!(out.is_empty());
        p.feed_initiator(&one[5..], Timestamp::default(), &mut out);
        assert_eq!(out.len(), 1);
    }
}

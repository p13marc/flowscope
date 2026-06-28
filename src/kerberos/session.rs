//! [`KerberosTcpParser`] — `SessionParser` over TCP/88
//! Kerberos. Handles the RFC 4120 §7.2.2 4-byte length-
//! prefix framing.

use bytes::BytesMut;

use super::parser::parse;
use super::types::KerberosMessage;
use crate::Timestamp;
use crate::session::SessionParser;

const MAX_BUFFER: usize = 256 * 1024;
const MAX_MESSAGE: usize = 64 * 1024;

#[derive(Debug, Clone, Default)]
pub struct KerberosTcpParser {
    init: BytesMut,
    resp: BytesMut,
}

impl KerberosTcpParser {
    pub fn new() -> Self {
        Self::default()
    }

    fn drain(buf: &mut BytesMut, out: &mut Vec<KerberosMessage>) {
        loop {
            if buf.len() < 4 {
                return;
            }
            let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
            if len == 0 || len > MAX_MESSAGE {
                // Pathological length; flush and resync.
                buf.clear();
                return;
            }
            if buf.len() < 4 + len {
                return;
            }
            let frame = &buf[4..4 + len];
            if let Ok(msg) = parse(frame) {
                out.push(msg);
            }
            bytes::Buf::advance(buf, 4 + len);
        }
    }
}

impl SessionParser for KerberosTcpParser {
    type Message = KerberosMessage;

    fn parser_kind(&self) -> crate::ParserKind {
        crate::ParserKind::Kerberos
    }

    fn feed_initiator(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<Self::Message>) {
        if self.init.len() + bytes.len() > MAX_BUFFER {
            self.init.clear();
        }
        self.init.extend_from_slice(bytes);
        Self::drain(&mut self.init, out);
    }

    fn feed_responder(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<Self::Message>) {
        if self.resp.len() + bytes.len() > MAX_BUFFER {
            self.resp.clear();
        }
        self.resp.extend_from_slice(bytes);
        Self::drain(&mut self.resp, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_kind() {
        let p = KerberosTcpParser::new();
        assert_eq!(p.parser_kind().as_str(), "kerberos");
    }

    #[test]
    fn zero_length_clears_buffer() {
        let mut p = KerberosTcpParser::new();
        let mut out = Vec::new();
        p.feed_initiator(&[0, 0, 0, 0, 0x6A], Timestamp::default(), &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn split_length_prefix_resumes() {
        let mut p = KerberosTcpParser::new();
        let mut out = Vec::new();
        p.feed_initiator(&[0, 0], Timestamp::default(), &mut out);
        assert!(out.is_empty());
        p.feed_initiator(&[0, 0], Timestamp::default(), &mut out);
        assert!(out.is_empty());
    }
}

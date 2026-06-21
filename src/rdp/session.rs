//! [`RdpParser`] — `SessionParser` over the cleartext RDP
//! X.224 negotiation. Emits at most one event per direction.

use bytes::BytesMut;

use super::parser::parse_frame;
use super::types::RdpMessage;
use crate::Timestamp;
use crate::session::SessionParser;

pub const PARSER_KIND: &str = "rdp";

/// IANA-assigned port for RDP.
pub const RDP_PORT: u16 = 3389;

/// `SessionParser` that emits one [`RdpMessage`] per side
/// (Connection Request from the initiator, Connection
/// Confirm from the responder). After that we stop draining;
/// subsequent bytes are TLS-wrapped (or legacy MCS) and out
/// of scope.
#[derive(Debug, Clone, Default)]
pub struct RdpParser {
    init: SideBuf,
    resp: SideBuf,
}

#[derive(Debug, Clone, Default)]
struct SideBuf {
    buf: BytesMut,
    /// `true` after we've emitted the one event from this
    /// side; future bytes are TLS or MCS and ignored.
    done: bool,
}

const MAX_FRAME: usize = 4096; // RDP CR is typically < 100 bytes

impl RdpParser {
    pub fn new() -> Self {
        Self::default()
    }

    fn try_drain(buf: &mut SideBuf) -> Option<RdpMessage> {
        if buf.done {
            return None;
        }
        if buf.buf.len() < 4 {
            return None;
        }
        // TPKT length is bytes 2..4 (big-endian).
        let total = u16::from_be_bytes([buf.buf[2], buf.buf[3]]) as usize;
        if total > MAX_FRAME {
            // Pathological — drop everything and disable
            // the side. (RDP CR is small; > 4 KiB is not
            // legitimate.)
            buf.buf.clear();
            buf.done = true;
            return None;
        }
        if buf.buf.len() < total {
            return None;
        }
        let frame = &buf.buf[..total];
        let msg = parse_frame(frame);
        // Whether we parsed it or not, we're done with this
        // side (anything else is TLS).
        buf.done = true;
        msg
    }
}

impl SessionParser for RdpParser {
    type Message = RdpMessage;

    fn parser_kind(&self) -> &'static str {
        PARSER_KIND
    }

    fn feed_initiator(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<Self::Message>) {
        if self.init.done {
            return;
        }
        self.init.buf.extend_from_slice(bytes);
        if let Some(msg) = Self::try_drain(&mut self.init) {
            out.push(msg);
        }
    }

    fn feed_responder(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<Self::Message>) {
        if self.resp.done {
            return;
        }
        self.resp.buf.extend_from_slice(bytes);
        if let Some(msg) = Self::try_drain(&mut self.resp) {
            out.push(msg);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rdp::{RdpMessage, RdpProtocols};

    fn ts() -> Timestamp {
        Timestamp::default()
    }

    #[test]
    fn parser_kind_label() {
        assert_eq!(RdpParser::new().parser_kind(), "rdp");
        assert_eq!(RDP_PORT, 3389);
    }

    #[test]
    fn end_to_end_cr_only() {
        // Build a CR with a cookie + TLS+HYBRID flags.
        let cookie = b"Cookie: mstshash=alice\r\n";
        let mut x224 = Vec::new();
        x224.push(0u8);
        x224.push(0xE0);
        x224.extend_from_slice(&[0, 0, 0, 0, 0]);
        x224.extend_from_slice(cookie);
        x224.push(0x01);
        x224.push(0);
        x224.extend_from_slice(&8u16.to_le_bytes());
        x224.extend_from_slice(&0x03u32.to_le_bytes());
        x224[0] = (6 + cookie.len()) as u8;
        let total = (4 + x224.len()) as u16;
        let mut payload = vec![0x03, 0x00];
        payload.extend_from_slice(&total.to_be_bytes());
        payload.extend_from_slice(&x224);

        let mut p = RdpParser::new();
        let mut out = Vec::new();
        p.feed_initiator(&payload, ts(), &mut out);
        assert_eq!(out.len(), 1);
        match &out[0] {
            RdpMessage::ConnectionRequest {
                cookie_username,
                requested_protocols,
                ..
            } => {
                assert_eq!(cookie_username.as_deref(), Some("alice"));
                let req = requested_protocols.expect("flags");
                assert!(req.contains(RdpProtocols::SSL));
            }
            _ => panic!("expected CR"),
        }
        // Subsequent bytes (TLS handshake) are ignored.
        let before = out.len();
        p.feed_initiator(b"\x16\x03\x01\x00\x00", ts(), &mut out);
        assert_eq!(out.len(), before);
    }

    #[test]
    fn split_feed_assembled_correctly() {
        let cookie = b"";
        let mut x224 = Vec::new();
        x224.push(6u8); // LI
        x224.push(0xE0);
        x224.extend_from_slice(&[0, 0, 0, 0, 0]);
        x224.extend_from_slice(cookie);
        x224.push(0x01);
        x224.push(0);
        x224.extend_from_slice(&8u16.to_le_bytes());
        x224.extend_from_slice(&0x00u32.to_le_bytes());
        let total = (4 + x224.len()) as u16;
        let mut payload = vec![0x03, 0x00];
        payload.extend_from_slice(&total.to_be_bytes());
        payload.extend_from_slice(&x224);

        let mut p = RdpParser::new();
        let mut out = Vec::new();
        p.feed_initiator(&payload[..6], ts(), &mut out);
        assert!(out.is_empty(), "incomplete → no event yet");
        p.feed_initiator(&payload[6..], ts(), &mut out);
        assert_eq!(out.len(), 1);
    }
}

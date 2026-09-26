//! [`SmbParser`] — `SessionParser` over TCP/445. Drains
//! one [`SmbMessage`] per NetBIOS Session Service PDU.
//!
//! Framing: NetBIOS Session Service header is 4 bytes —
//! type(1) + length(3 bytes big-endian). For SMB the type
//! is `0x00` (SESSION_MESSAGE); other types
//! (REQUEST/ACK/RETARGET/NEGATIVE/KEEPALIVE) are skipped
//! without yielding an SmbMessage.

use bytes::BytesMut;

use super::parser::parse;
use super::types::SmbMessage;
use crate::Timestamp;
use crate::session::SessionParser;

/// IANA-assigned SMB Direct port.
pub const SMB_PORT: u16 = 445;

const MAX_BUFFER: usize = 1024 * 1024;
const NBSS_HEADER_LEN: usize = 4;
const NBSS_TYPE_SESSION_MESSAGE: u8 = 0x00;
/// NetBIOS Session Service caps message length at 17 bits
/// (per RFC 1002 §4.3.1).
const MAX_NBSS_LEN: usize = 0x1FFFF;

#[derive(Debug, Clone, Default)]
pub struct SmbParser {
    init: BytesMut,
    resp: BytesMut,
    /// Bytes went missing on (initiator, responder): resync on the
    /// next NBSS + SMB header.
    resync: [bool; 2],
}

/// Offset of the next plausible NBSS session message carrying SMB:
/// a `0x00` type byte, then a 3-byte length, then `\xFESMB` (SMB2),
/// `\xFFSMB` (SMB1) or `\xFDSMB` (SMB3 transform).
fn find_nbss_smb(buf: &[u8]) -> Option<usize> {
    buf.windows(8).position(|w| {
        w[0] == NBSS_TYPE_SESSION_MESSAGE && matches!(w[4], 0xFD..=0xFF) && &w[5..8] == b"SMB"
    })
}

impl SmbParser {
    pub fn new() -> Self {
        Self::default()
    }

    fn drain(buf: &mut BytesMut, out: &mut Vec<SmbMessage>) {
        loop {
            if buf.len() < NBSS_HEADER_LEN {
                return;
            }
            let nbss_type = buf[0];
            let len =
                (((buf[1] & 0x01) as usize) << 16) | ((buf[2] as usize) << 8) | (buf[3] as usize);
            if len > MAX_NBSS_LEN {
                buf.clear();
                return;
            }
            if buf.len() < NBSS_HEADER_LEN + len {
                return;
            }
            let pdu = &buf[NBSS_HEADER_LEN..NBSS_HEADER_LEN + len];
            if nbss_type == NBSS_TYPE_SESSION_MESSAGE
                && let Ok(msg) = parse(pdu)
            {
                out.push(msg);
            }
            bytes::Buf::advance(buf, NBSS_HEADER_LEN + len);
        }
    }
}

impl SessionParser for SmbParser {
    type Message = SmbMessage;

    fn parser_kind(&self) -> crate::ParserKind {
        crate::ParserKind::Smb
    }

    fn feed_initiator(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<Self::Message>) {
        if self.init.len() + bytes.len() > MAX_BUFFER {
            self.init.clear();
        }
        self.init.extend_from_slice(bytes);
        crate::session::resync_frames(&mut self.resync[0], &mut self.init, 7, find_nbss_smb);
        if !self.resync[0] {
            Self::drain(&mut self.init, out);
        }
    }

    fn feed_responder(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<Self::Message>) {
        if self.resp.len() + bytes.len() > MAX_BUFFER {
            self.resp.clear();
        }
        self.resp.extend_from_slice(bytes);
        crate::session::resync_frames(&mut self.resync[1], &mut self.resp, 7, find_nbss_smb);
        if !self.resync[1] {
            Self::drain(&mut self.resp, out);
        }
    }

    /// Drop the partial PDU and resume at the next NBSS + SMB header.
    fn on_gap(
        &mut self,
        side: crate::FlowSide,
        _missing: u64,
        _ts: Timestamp,
        _out: &mut Vec<SmbMessage>,
    ) -> crate::GapResponse {
        let i = usize::from(side == crate::FlowSide::Responder);
        match side {
            crate::FlowSide::Initiator => self.init.clear(),
            crate::FlowSide::Responder => self.resp.clear(),
        }
        self.resync[i] = true;
        crate::GapResponse::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_nbss(payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + payload.len());
        let len = payload.len() as u32;
        out.push(0x00); // SESSION_MESSAGE
        out.push(((len >> 16) & 0x01) as u8);
        out.push(((len >> 8) & 0xFF) as u8);
        out.push((len & 0xFF) as u8);
        out.extend_from_slice(payload);
        out
    }

    fn build_smb2_negotiate() -> Vec<u8> {
        let mut frame = vec![0u8; 64];
        frame[0..4].copy_from_slice(&[0xFE, b'S', b'M', b'B']);
        frame
    }

    #[test]
    fn parser_kind_and_port() {
        let p = SmbParser::new();
        assert_eq!(p.parser_kind().as_str(), "smb");
        assert_eq!(SMB_PORT, 445);
    }

    #[test]
    fn drains_one_negotiate() {
        let nbss = build_nbss(&build_smb2_negotiate());
        let mut p = SmbParser::new();
        let mut out = Vec::new();
        p.feed_initiator(&nbss, Timestamp::default(), &mut out);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn drains_two_back_to_back() {
        let mut buf = Vec::new();
        let nbss = build_nbss(&build_smb2_negotiate());
        buf.extend_from_slice(&nbss);
        buf.extend_from_slice(&nbss);
        let mut p = SmbParser::new();
        let mut out = Vec::new();
        p.feed_initiator(&buf, Timestamp::default(), &mut out);
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn split_feed_reassembles() {
        let nbss = build_nbss(&build_smb2_negotiate());
        let mut p = SmbParser::new();
        let mut out = Vec::new();
        p.feed_initiator(&nbss[..10], Timestamp::default(), &mut out);
        assert!(out.is_empty());
        p.feed_initiator(&nbss[10..], Timestamp::default(), &mut out);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn ignores_non_session_message_nbss() {
        // Type 0x85 = KEEPALIVE, length 0.
        let nbss = [0x85, 0x00, 0x00, 0x00];
        let mut p = SmbParser::new();
        let mut out = Vec::new();
        p.feed_initiator(&nbss, Timestamp::default(), &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn a_gap_resyncs_on_the_next_nbss_smb_header() {
        let mut p = SmbParser::new();
        let mut out = Vec::new();
        let pdu = build_nbss(&build_smb2_negotiate());
        p.feed_initiator(&pdu[..20], Timestamp::default(), &mut out);
        let r = p.on_gap(
            crate::FlowSide::Initiator,
            10,
            Timestamp::default(),
            &mut out,
        );
        assert_eq!(r, crate::GapResponse::Continue);
        let mut tail = pdu[30..].to_vec();
        tail.extend_from_slice(&pdu);
        p.feed_initiator(&tail, Timestamp::default(), &mut out);
        assert_eq!(out.len(), 1);
    }
}

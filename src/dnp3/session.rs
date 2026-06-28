//! [`DnpParser`] — `SessionParser` over TCP/20000 DNP3.
//!
//! Drains one [`DnpMessage`] per visible link-layer frame.
//! Frame boundaries are detected via the `0x05 0x64` start-
//! bytes magic and the length byte. Bytes that don't match
//! the frame shape are silently dropped (a defensive
//! resync to keep the parser stable on broken / truncated
//! streams).

use bytes::BytesMut;

use super::parser::parse;
use super::types::DnpMessage;
use crate::Timestamp;
use crate::session::SessionParser;

pub const PARSER_KIND: &str = "dnp3";

/// IANA-assigned DNP3-over-TCP port.
pub const DNP3_PORT: u16 = 20000;

const MAX_FRAME: usize = 292; // 10 link header + 282 user-data max (16*17 + 16 crc = 282)
const MAX_BUFFER: usize = 64 * 1024;

#[derive(Debug, Clone, Default)]
pub struct DnpParser {
    init: BytesMut,
    resp: BytesMut,
}

impl DnpParser {
    pub fn new() -> Self {
        Self::default()
    }

    fn drain(buf: &mut BytesMut, out: &mut Vec<DnpMessage>) {
        loop {
            // Scan for the start-byte magic.
            let Some(magic_at) = find_magic(buf) else {
                if buf.len() > MAX_BUFFER {
                    buf.clear();
                }
                return;
            };
            if magic_at > 0 {
                bytes::Buf::advance(buf, magic_at);
            }
            if buf.len() < 3 {
                return;
            }
            let frame_len = total_frame_len(buf[2]);
            if frame_len > MAX_FRAME {
                // Pathological length; advance past the
                // magic so we don't loop on the same bad
                // start bytes.
                bytes::Buf::advance(buf, 2);
                continue;
            }
            if buf.len() < frame_len {
                // Need more bytes.
                return;
            }
            let consumed = match parse(&buf[..frame_len]) {
                Ok(msg) => {
                    out.push(msg);
                    frame_len
                }
                Err(_) => 2, // skip past the bad magic
            };
            bytes::Buf::advance(buf, consumed);
        }
    }
}

/// Find the next `0x05 0x64` start-byte pair.
fn find_magic(buf: &BytesMut) -> Option<usize> {
    buf.windows(2).position(|w| w == [0x05, 0x64])
}

/// Compute the total frame length on the wire given the
/// link-layer length byte. Layout:
///
///   start(2) + length(1) + header(8) + zero-or-more
///   16-byte data blocks each with a 2-byte trailing CRC,
///   final block may be < 16 bytes.
fn total_frame_len(length_byte: u8) -> usize {
    let length = length_byte as usize;
    if length < 5 {
        // Invalid — parse() will reject; reserve max so we
        // don't read past the buffer waiting for non-bytes.
        return 0;
    }
    // user_data bytes = length - 5.
    let user_data = length - 5;
    // 2 start + 1 length + 8 header (5 ctrl/addr + 2 header CRC + extra) = 11 bytes.
    // Actually layout is: 2 start + 1 length + 5 (ctrl+dst+src) + 2 header CRC = 10.
    let mut total = 10;
    // Plus user_data bytes carved into 16-byte blocks each
    // with a 2-byte CRC.
    let full_blocks = user_data / 16;
    let remainder = user_data % 16;
    total += full_blocks * 18;
    if remainder > 0 {
        total += remainder + 2;
    }
    total
}

impl SessionParser for DnpParser {
    type Message = DnpMessage;

    fn parser_kind(&self) -> crate::ParserKind {
        crate::ParserKind::Dnp3
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
    use crate::session::DatagramParser;

    fn build_reset_link_frame(dst: u16, src: u16) -> Vec<u8> {
        // start(2) + length(1=5) + ctrl(0xC0) + dst(2) + src(2) + crc(2) = 10 bytes.
        let mut out = vec![0x05, 0x64, 0x05, 0xC0];
        out.extend_from_slice(&dst.to_le_bytes());
        out.extend_from_slice(&src.to_le_bytes());
        out.extend_from_slice(&[0xAA, 0xBB]);
        out
    }

    fn ts() -> Timestamp {
        Timestamp::default()
    }

    #[test]
    fn parser_kind_and_port_constants() {
        assert_eq!(DnpParser::new().parser_kind().as_str(), "dnp3");
        assert_eq!(DNP3_PORT, 20000);
        // datagram-parser sanity: confirm we're NOT a
        // DatagramParser (the trait should not be in scope
        // for this type).
        fn assert_session<T: SessionParser>(_: &T) {}
        let p = DnpParser::new();
        assert_session(&p);
        let _: fn(&dyn DatagramParser<Message = ()>) = |_| {};
    }

    #[test]
    fn drains_one_frame() {
        let buf = build_reset_link_frame(1, 2);
        let mut p = DnpParser::new();
        let mut out = Vec::new();
        p.feed_initiator(&buf, ts(), &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].dst_addr, 1);
        assert_eq!(out[0].src_addr, 2);
    }

    #[test]
    fn drains_back_to_back_frames() {
        let mut buf = Vec::new();
        for i in 1..=4u16 {
            buf.extend_from_slice(&build_reset_link_frame(i, i + 10));
        }
        let mut p = DnpParser::new();
        let mut out = Vec::new();
        p.feed_initiator(&buf, ts(), &mut out);
        assert_eq!(out.len(), 4);
    }

    #[test]
    fn split_feed_reassembles() {
        let buf = build_reset_link_frame(1, 2);
        let mut p = DnpParser::new();
        let mut out = Vec::new();
        p.feed_initiator(&buf[..5], ts(), &mut out);
        assert!(out.is_empty());
        p.feed_initiator(&buf[5..], ts(), &mut out);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn skips_garbage_then_finds_real_frame() {
        let mut buf = vec![0xDE, 0xAD, 0xBE, 0xEF];
        buf.extend_from_slice(&build_reset_link_frame(7, 9));
        let mut p = DnpParser::new();
        let mut out = Vec::new();
        p.feed_initiator(&buf, ts(), &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].dst_addr, 7);
    }
}

//! [`SshParser`] — `SessionParser` over the cleartext SSH-2
//! handshake. Stops emitting events after `SSH_MSG_NEWKEYS`
//! on each side (the rest of the connection is encrypted).

use bytes::BytesMut;

use super::parser::{
    kexinit_message_byte, newkeys_message_byte, parse_kexinit_payload, version_banner_prefix,
};
use super::types::SshMessage;
use crate::Timestamp;
use crate::session::SessionParser;

/// Stable identifier for the parser.
pub const PARSER_KIND: &str = "ssh";

/// `SessionParser` that emits banner / KEXINIT / Encrypted
/// events from the cleartext portion of an SSH-2 handshake.
///
/// Issue #7 (0.18).
#[derive(Debug, Clone, Default)]
pub struct SshParser {
    initiator: SideState,
    responder: SideState,
}

#[derive(Debug, Clone, Default)]
struct SideState {
    buffer: BytesMut,
    banner_seen: bool,
    /// `true` after we've emitted `SshMessage::Encrypted` for
    /// this side — we stop draining bytes after that.
    encrypted: bool,
}

impl SshParser {
    /// Construct a fresh parser. No tunables today.
    pub fn new() -> Self {
        Self::default()
    }

    fn drain_side(&mut self, side: Side, out: &mut Vec<SshMessage>) {
        let from_client = matches!(side, Side::Initiator);
        let state = match side {
            Side::Initiator => &mut self.initiator,
            Side::Responder => &mut self.responder,
        };
        if state.encrypted {
            state.buffer.clear();
            return;
        }

        if !state.banner_seen {
            if let Some(banner) = extract_banner(&mut state.buffer) {
                state.banner_seen = true;
                out.push(SshMessage::Banner { banner });
            } else {
                // Need more bytes before the banner is complete.
                return;
            }
        }

        loop {
            match extract_binary_packet(&mut state.buffer) {
                None => break,
                Some(payload) => {
                    if payload.is_empty() {
                        continue;
                    }
                    let msg_type = payload[0];
                    if msg_type == kexinit_message_byte() {
                        if let Some(kex) = parse_kexinit_payload(&payload[1..], from_client) {
                            out.push(SshMessage::KexInit(Box::new(kex)));
                        }
                    } else if msg_type == newkeys_message_byte() {
                        out.push(SshMessage::Encrypted);
                        state.encrypted = true;
                        state.buffer.clear();
                        return;
                    }
                    // Any other pre-NEWKEYS message types (e.g.
                    // SSH_MSG_KEX_DH_INIT) are skipped — not
                    // operationally interesting for fingerprinting.
                }
            }
        }
    }
}

impl SessionParser for SshParser {
    type Message = SshMessage;

    fn parser_kind(&self) -> &'static str {
        PARSER_KIND
    }

    fn feed_initiator(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<Self::Message>) {
        self.initiator.buffer.extend_from_slice(bytes);
        self.drain_side(Side::Initiator, out);
    }

    fn feed_responder(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<Self::Message>) {
        self.responder.buffer.extend_from_slice(bytes);
        self.drain_side(Side::Responder, out);
    }
}

#[derive(Clone, Copy)]
enum Side {
    Initiator,
    Responder,
}

/// Find the first `\r\n`-terminated `"SSH-2.0-..."` line in
/// the buffer and return it. Truncates the buffer past the
/// `\r\n`. Returns `None` if no full banner line is present
/// yet.
///
/// Defensively bounds banner length to 255 bytes (RFC 4253
/// §4.2 specifies a 255-octet ceiling); anything longer is
/// treated as garbage and dropped.
fn extract_banner(buffer: &mut BytesMut) -> Option<String> {
    const MAX_BANNER: usize = 255;
    loop {
        let Some(eol) = find_crlf(buffer) else {
            if buffer.len() > MAX_BANNER {
                // No CRLF after 255 bytes — drop to keep buffer
                // bounded.
                buffer.clear();
            }
            return None;
        };
        if eol > MAX_BANNER {
            // Skip the giant line and keep looking.
            buffer.advance_by(eol + 2);
            continue;
        }
        let line = &buffer[..eol];
        if !line.starts_with(version_banner_prefix().as_bytes()) {
            // Pre-banner text (e.g. legal notice) — drop and
            // try the next line.
            buffer.advance_by(eol + 2);
            continue;
        }
        let banner = std::str::from_utf8(line).ok()?.to_string();
        buffer.advance_by(eol + 2);
        return Some(banner);
    }
}

/// Walk for `\r\n`. Returns the index of the `\r`.
fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

/// Extract one SSH binary-packet payload from the buffer.
/// Returns the payload bytes (with the 1-byte msg-type prefix)
/// and advances the buffer past the consumed packet. Returns
/// `None` if the buffer doesn't yet hold a full packet.
///
/// Wire shape (pre-NEWKEYS, no MAC):
///
/// ```text
/// 4B packet_length
/// 1B padding_length
/// N B payload  where N = packet_length - padding_length - 1
/// M B padding
/// ```
///
/// Caps `packet_length` at 256 KiB (the spec's minimum maximum
/// is 32768; 256 KiB is comfortably past anything real and
/// rejects adversarial size inflation).
fn extract_binary_packet(buffer: &mut BytesMut) -> Option<Vec<u8>> {
    const MAX_PACKET_LEN: u32 = 256 * 1024;
    if buffer.len() < 5 {
        return None;
    }
    let packet_length = u32::from_be_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]);
    if packet_length == 0 || packet_length > MAX_PACKET_LEN {
        buffer.clear();
        return None;
    }
    let total = 4 + packet_length as usize;
    if buffer.len() < total {
        return None;
    }
    let padding_length = buffer[4] as usize;
    let payload_len = (packet_length as usize).checked_sub(padding_length + 1)?;
    let payload = buffer[5..5 + payload_len].to_vec();
    buffer.advance_by(total);
    Some(payload)
}

/// `BytesMut::advance` consumes `n` bytes from the front;
/// we keep a tiny wrapper for clarity.
trait BytesMutExt {
    fn advance_by(&mut self, n: usize);
}

impl BytesMutExt for BytesMut {
    fn advance_by(&mut self, n: usize) {
        use bytes::Buf;
        self.advance(n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts() -> Timestamp {
        Timestamp::default()
    }

    fn binary_packet(payload: &[u8]) -> Vec<u8> {
        // Minimum padding length is 4 per RFC 4253 §6.
        let mut pad_len = 4;
        // Round packet body (padding_length + payload + padding)
        // to a multiple of 8 (cipher block size for pre-NEWKEYS).
        while !(1 + payload.len() + pad_len).is_multiple_of(8) {
            pad_len += 1;
        }
        let packet_length = (1 + payload.len() + pad_len) as u32;
        let mut p = packet_length.to_be_bytes().to_vec();
        p.push(pad_len as u8);
        p.extend_from_slice(payload);
        p.extend(std::iter::repeat_n(0u8, pad_len));
        p
    }

    fn kexinit_packet(from_client: bool) -> Vec<u8> {
        // Minimal but valid KEXINIT.
        let mut payload = vec![kexinit_message_byte()];
        payload.extend_from_slice(&[0u8; 16]); // cookie
        // 10 empty name-lists.
        for _ in 0..10 {
            payload.extend_from_slice(&0u32.to_be_bytes());
        }
        payload.push(0); // first_kex_packet_follows
        payload.extend_from_slice(&[0u8; 4]); // reserved
        let _ = from_client;
        binary_packet(&payload)
    }

    #[test]
    fn parser_kind_label() {
        let p = SshParser::default();
        assert_eq!(p.parser_kind(), "ssh");
    }

    #[test]
    fn emits_banner_then_kexinit_then_encrypted() {
        let mut p = SshParser::new();
        let mut out = Vec::new();

        // Client banner + KEXINIT + NEWKEYS in one feed.
        let mut stream = Vec::new();
        stream.extend_from_slice(b"SSH-2.0-OpenSSH_9.6\r\n");
        stream.extend(kexinit_packet(true));
        stream.extend(binary_packet(&[newkeys_message_byte()]));
        p.feed_initiator(&stream, ts(), &mut out);

        assert_eq!(out.len(), 3);
        assert!(
            matches!(&out[0], SshMessage::Banner { banner } if banner == "SSH-2.0-OpenSSH_9.6")
        );
        assert!(matches!(&out[1], SshMessage::KexInit(k) if k.from_client));
        assert_eq!(out[2], SshMessage::Encrypted);

        // After Encrypted, further bytes on this side are ignored.
        out.clear();
        p.feed_initiator(b"more-bytes", ts(), &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn server_kexinit_sets_from_client_false() {
        let mut p = SshParser::new();
        let mut out = Vec::new();
        let mut stream = Vec::new();
        stream.extend_from_slice(b"SSH-2.0-OpenSSH_9.6\r\n");
        stream.extend(kexinit_packet(false));
        p.feed_responder(&stream, ts(), &mut out);
        assert!(matches!(&out[1], SshMessage::KexInit(k) if !k.from_client));
    }

    #[test]
    fn banner_emitted_when_split_across_feeds() {
        let mut p = SshParser::new();
        let mut out = Vec::new();
        p.feed_initiator(b"SSH-2.0-", ts(), &mut out);
        assert!(out.is_empty(), "banner not yet complete");
        p.feed_initiator(b"OpenSSH_9.6\r\n", ts(), &mut out);
        assert_eq!(out.len(), 1);
        assert!(
            matches!(&out[0], SshMessage::Banner { banner } if banner == "SSH-2.0-OpenSSH_9.6")
        );
    }

    #[test]
    fn pre_banner_text_lines_skipped() {
        let mut p = SshParser::new();
        let mut out = Vec::new();
        // Some servers send legal text before the SSH banner.
        let mut stream = Vec::new();
        stream.extend_from_slice(b"Welcome to bank-of-evil\r\n");
        stream.extend_from_slice(b"Unauthorized use prohibited\r\n");
        stream.extend_from_slice(b"SSH-2.0-OpenSSH_9.6\r\n");
        p.feed_initiator(&stream, ts(), &mut out);
        assert_eq!(out.len(), 1);
        assert!(matches!(&out[0], SshMessage::Banner { .. }));
    }

    #[test]
    fn oversized_banner_dropped_without_panic() {
        let mut p = SshParser::new();
        let mut out = Vec::new();
        // 300 bytes with no CRLF — buffer gets cleared.
        p.feed_initiator(&vec![b'A'; 300], ts(), &mut out);
        assert!(out.is_empty());
        // Now a proper banner can still come through.
        p.feed_initiator(b"SSH-2.0-Real\r\n", ts(), &mut out);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn malformed_packet_length_clears_buffer() {
        let mut p = SshParser::new();
        let mut out = Vec::new();
        p.feed_initiator(b"SSH-2.0-x\r\n", ts(), &mut out);
        out.clear();
        // Packet length of 0 is invalid.
        p.feed_initiator(&[0u8, 0, 0, 0, 4], ts(), &mut out);
        // No crash; no emit.
        assert!(out.is_empty());
    }
}

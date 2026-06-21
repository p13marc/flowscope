//! WireGuard datagram detection.
//!
//! We never try to decrypt; the goal is fingerprinting.
//! Returns `None` on any input that doesn't match a
//! WireGuard message-shape exactly.

use super::types::{WireGuardKind, WireGuardMessage};

/// Parse a single UDP datagram as a WireGuard message.
/// Returns `None` when the payload doesn't fit any of the
/// four defined shapes (length + type-byte + reserved-zero
/// match required).
pub fn parse(payload: &[u8]) -> Option<WireGuardMessage> {
    if payload.len() < 4 {
        return None;
    }
    // Reserved bytes must be zero per the whitepaper.
    if payload[1] != 0 || payload[2] != 0 || payload[3] != 0 {
        return None;
    }
    match (payload[0], payload.len()) {
        (1, 148) => Some(WireGuardMessage {
            kind: WireGuardKind::HandshakeInitiation,
            sender_index: Some(le_u32(&payload[4..8])),
            receiver_index: None,
            payload_length: None,
        }),
        (2, 92) => Some(WireGuardMessage {
            kind: WireGuardKind::HandshakeResponse,
            sender_index: Some(le_u32(&payload[4..8])),
            receiver_index: Some(le_u32(&payload[8..12])),
            payload_length: None,
        }),
        (3, 64) => Some(WireGuardMessage {
            kind: WireGuardKind::CookieReply,
            sender_index: None,
            receiver_index: Some(le_u32(&payload[4..8])),
            payload_length: None,
        }),
        // Transport data: variable length, minimum 32 bytes
        // (4 header + 4 receiver + 8 counter + 16 AEAD tag).
        (4, n) if n >= 32 => {
            let receiver = le_u32(&payload[4..8]);
            // Bytes 8..16 are the counter (LE u64); skip.
            let body = (n - 16) as u32;
            Some(WireGuardMessage {
                kind: WireGuardKind::TransportData,
                sender_index: None,
                receiver_index: Some(receiver),
                payload_length: Some(body),
            })
        }
        _ => None,
    }
}

fn le_u32(buf: &[u8]) -> u32 {
    u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build(kind: u8, len: usize, sender: u32, receiver: u32) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        buf[0] = kind;
        // Layout differs per type:
        // - Type 1 (initiation): bytes 4..8 = sender_index.
        // - Type 2 (response): bytes 4..8 = sender, 8..12 = receiver.
        // - Type 3 (cookie reply): bytes 4..8 = receiver_index.
        // - Type 4 (transport data): bytes 4..8 = receiver_index.
        match kind {
            1 => {
                buf[4..8].copy_from_slice(&sender.to_le_bytes());
            }
            2 => {
                buf[4..8].copy_from_slice(&sender.to_le_bytes());
                buf[8..12].copy_from_slice(&receiver.to_le_bytes());
            }
            3 | 4 => {
                buf[4..8].copy_from_slice(&receiver.to_le_bytes());
            }
            _ => {}
        }
        buf
    }

    #[test]
    fn handshake_initiation_148_bytes() {
        let buf = build(1, 148, 0xdeadbeef, 0);
        let msg = parse(&buf).expect("parse");
        assert_eq!(msg.kind, WireGuardKind::HandshakeInitiation);
        assert_eq!(msg.sender_index, Some(0xdeadbeef));
        assert_eq!(msg.receiver_index, None);
    }

    #[test]
    fn handshake_response_92_bytes() {
        let buf = build(2, 92, 0xcafebabe, 0xdeadbeef);
        let msg = parse(&buf).expect("parse");
        assert_eq!(msg.kind, WireGuardKind::HandshakeResponse);
        assert_eq!(msg.sender_index, Some(0xcafebabe));
        assert_eq!(msg.receiver_index, Some(0xdeadbeef));
    }

    #[test]
    fn cookie_reply_64_bytes() {
        let buf = build(3, 64, 0, 0x12345678);
        let msg = parse(&buf).expect("parse");
        assert_eq!(msg.kind, WireGuardKind::CookieReply);
        assert_eq!(msg.receiver_index, Some(0x12345678));
    }

    #[test]
    fn transport_data_min_length_32() {
        let buf = build(4, 32, 0, 0x99);
        let msg = parse(&buf).expect("parse");
        assert_eq!(msg.kind, WireGuardKind::TransportData);
        assert_eq!(msg.receiver_index, Some(0x99));
        assert_eq!(msg.payload_length, Some(16)); // 32 - 16 tag
    }

    #[test]
    fn transport_data_larger() {
        let buf = build(4, 1500, 0, 0x99);
        let msg = parse(&buf).expect("parse");
        assert_eq!(msg.payload_length, Some(1484));
    }

    #[test]
    fn wrong_length_handshake_rejected() {
        // Initiation should be exactly 148 bytes.
        let buf = build(1, 100, 0, 0);
        assert!(parse(&buf).is_none());
    }

    #[test]
    fn non_zero_reserved_rejected() {
        let mut buf = build(1, 148, 0, 0);
        buf[2] = 0xff;
        assert!(parse(&buf).is_none());
    }

    #[test]
    fn unknown_type_rejected() {
        let buf = build(99, 32, 0, 0);
        assert!(parse(&buf).is_none());
    }

    #[test]
    fn too_short_rejected() {
        assert!(parse(&[0u8; 3]).is_none());
    }

    #[test]
    fn transport_data_below_min_rejected() {
        let buf = build(4, 20, 0, 0);
        assert!(parse(&buf).is_none());
    }

    #[test]
    fn kind_is_handshake_predicate() {
        assert!(WireGuardKind::HandshakeInitiation.is_handshake());
        assert!(WireGuardKind::HandshakeResponse.is_handshake());
        assert!(!WireGuardKind::CookieReply.is_handshake());
        assert!(!WireGuardKind::TransportData.is_handshake());
    }

    #[test]
    fn kind_as_str_slugs_match() {
        assert_eq!(
            WireGuardKind::HandshakeInitiation.as_str(),
            "handshake_initiation"
        );
        assert_eq!(
            WireGuardKind::HandshakeResponse.as_str(),
            "handshake_response"
        );
        assert_eq!(WireGuardKind::CookieReply.as_str(), "cookie_reply");
        assert_eq!(WireGuardKind::TransportData.as_str(), "transport_data");
    }
}

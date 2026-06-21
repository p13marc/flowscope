//! DNP3 wire-format parser.
//!
//! Strict: returns `None` on any wire shape that doesn't
//! match IEEE 1815-2012 §8 (data link layer) + §10
//! (application layer). Does NOT verify the per-block CRCs;
//! the Suricata CVE history teaches us that fancy CRC
//! handling in passive parsers is a CVE magnet. The
//! 16-byte CRC-protected user-data blocks are walked
//! structurally (length + CRC layout) so we recognise the
//! end of the first block, but we don't verify the CRC.

use super::types::{
    DnpAppFunctionKind, DnpApplication, DnpInternalIndications, DnpLinkFunctionKind, DnpMessage,
};

const START_BYTES: [u8; 2] = [0x05, 0x64];
const LINK_HEADER_LEN: usize = 10;
/// First user-data block max payload (16 bytes + 2 CRC).
const FIRST_BLOCK_DATA: usize = 16;

/// Parse a single DNP3 frame from the front of `payload`.
/// Returns the parsed message on success.
pub fn parse(payload: &[u8]) -> Option<DnpMessage> {
    if payload.len() < LINK_HEADER_LEN {
        return None;
    }
    if payload[0..2] != START_BYTES {
        return None;
    }
    let length = payload[2] as usize;
    // RFC: length covers ctrl + dst + src + payload, NOT the
    // length byte itself, the start bytes, or the CRCs.
    // Minimum valid value is 5 (just the link header).
    if length < 5 {
        return None;
    }
    let control = payload[3];
    let dst_addr = u16::from_le_bytes([payload[4], payload[5]]);
    let src_addr = u16::from_le_bytes([payload[6], payload[7]]);
    // Bytes 8..10 are the header CRC — skipped here per the
    // module doc.

    let link_function = DnpLinkFunctionKind::from_raw(control);
    let link_dir = (control & 0x80) != 0;
    let link_prm = (control & 0x40) != 0;

    // User-data bytes count = length - 5 (subtract the
    // ctrl + dst(2) + src(2)).
    let user_data_len = length - 5;
    let mut application = None;
    if user_data_len > 0 {
        // First block starts at offset 10; carries up to
        // 16 data bytes then a 2-byte CRC.
        let first_block_data = user_data_len.min(FIRST_BLOCK_DATA);
        let data_end = LINK_HEADER_LEN + first_block_data;
        if payload.len() >= data_end {
            application = decode_application(&payload[LINK_HEADER_LEN..data_end]);
        }
    }

    Some(DnpMessage {
        src_addr,
        dst_addr,
        link_function,
        link_dir,
        link_prm,
        application,
    })
}

/// Decode the per-block transport-layer header (1 byte) +
/// application-layer header (2 bytes minimum).
fn decode_application(buf: &[u8]) -> Option<DnpApplication> {
    if buf.len() < 3 {
        return None;
    }
    // Byte 0: transport-layer header (FIN/FIR/SEQ). We
    // surface it via the application FIR/FIN duplicate so
    // consumers don't need to peek separately.
    let _transport = buf[0];
    let ac = buf[1]; // application control
    let raw_function_code = buf[2];

    let fir = (ac & 0x80) != 0;
    let fin = (ac & 0x40) != 0;
    let con = (ac & 0x20) != 0;
    let uns = (ac & 0x10) != 0;
    let sequence = ac & 0x0F;

    let function = DnpAppFunctionKind::from_raw(raw_function_code);
    let iin = if function.is_response() && buf.len() >= 5 {
        let bits = u16::from_le_bytes([buf[3], buf[4]]);
        Some(DnpInternalIndications::from_bits_truncate(bits))
    } else {
        None
    };

    Some(DnpApplication {
        sequence,
        fir,
        fin,
        con,
        uns,
        function,
        raw_function_code,
        iin,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid DNP3 frame with the given
    /// link-layer fields and (optionally) an application
    /// payload (transport byte + AC + function + optional IIN).
    fn build_frame(control: u8, dst: u16, src: u16, user_data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&START_BYTES);
        // length covers ctrl + dst + src + user_data.
        out.push((5 + user_data.len()) as u8);
        out.push(control);
        out.extend_from_slice(&dst.to_le_bytes());
        out.extend_from_slice(&src.to_le_bytes());
        // header CRC placeholder (we don't verify).
        out.extend_from_slice(&[0xAA, 0xBB]);
        out.extend_from_slice(user_data);
        out
    }

    #[test]
    fn parses_minimum_link_only_frame() {
        // Reset Link States: control = primary (0x40) + DIR
        // (0x80) + function 0 → 0xC0. No user data.
        let buf = build_frame(0xC0, 1, 2, &[]);
        let msg = parse(&buf).expect("parse");
        assert_eq!(msg.src_addr, 2);
        assert_eq!(msg.dst_addr, 1);
        assert_eq!(msg.link_function, DnpLinkFunctionKind::ResetLinkStates);
        assert!(msg.link_dir);
        assert!(msg.link_prm);
        assert!(msg.application.is_none());
    }

    #[test]
    fn parses_user_data_with_app_header() {
        // User data: transport(0xC1 = FIN+FIR+seq1) + AC(0xC1 = FIR+FIN+seq1) + function 1 (Read).
        let user_data = &[0xC1, 0xC1, 0x01];
        let buf = build_frame(0xC3, 0x000A, 0x0001, user_data); // UserData primary (func 3)
        let msg = parse(&buf).expect("parse");
        assert_eq!(msg.link_function, DnpLinkFunctionKind::UserData);
        let app = msg.application.expect("app");
        assert!(app.fir);
        assert!(app.fin);
        assert!(!app.uns);
        assert_eq!(app.sequence, 1);
        assert_eq!(app.function, DnpAppFunctionKind::Read);
        assert_eq!(app.raw_function_code, 1);
        assert!(app.iin.is_none());
    }

    #[test]
    fn response_carries_iin_bits() {
        // Response (function 129) + IIN with DEVICE_RESTART (bit 7) + CLASS_1_EVENTS (bit 1).
        let user_data = &[0xC0, 0xC0, 0x81, 0x82, 0x00];
        let buf = build_frame(0xC3, 1, 2, user_data);
        let msg = parse(&buf).expect("parse");
        let app = msg.application.expect("app");
        assert_eq!(app.function, DnpAppFunctionKind::Response);
        let iin = app.iin.expect("iin");
        assert!(iin.contains(DnpInternalIndications::DEVICE_RESTART));
        assert!(iin.contains(DnpInternalIndications::CLASS_1_EVENTS));
    }

    #[test]
    fn rejects_wrong_start_bytes() {
        let mut buf = build_frame(0xC0, 1, 2, &[]);
        buf[0] = 0x99;
        assert!(parse(&buf).is_none());
    }

    #[test]
    fn rejects_too_short() {
        assert!(parse(&[0u8; 9]).is_none());
    }

    #[test]
    fn rejects_invalid_length() {
        let mut buf = build_frame(0xC0, 1, 2, &[]);
        buf[2] = 0x02; // length < 5 is invalid
        assert!(parse(&buf).is_none());
    }

    #[test]
    fn unknown_function_code_preserved_as_other() {
        let user_data = &[0xC0, 0xC0, 0x99];
        let buf = build_frame(0xC3, 1, 2, user_data);
        let msg = parse(&buf).expect("parse");
        let app = msg.application.expect("app");
        assert_eq!(app.function, DnpAppFunctionKind::Other(0x99));
        assert_eq!(app.raw_function_code, 0x99);
    }

    #[test]
    fn link_function_secondary_decodes_to_ack() {
        // control: secondary (PRM=0), function 0 (Ack).
        let buf = build_frame(0x00, 1, 2, &[]);
        let msg = parse(&buf).expect("parse");
        assert_eq!(msg.link_function, DnpLinkFunctionKind::Ack);
        assert!(!msg.link_prm);
    }

    #[test]
    fn link_function_slugs() {
        assert_eq!(DnpLinkFunctionKind::UserData.as_str(), "user_data");
        assert_eq!(DnpLinkFunctionKind::Ack.as_str(), "ack");
        assert_eq!(DnpLinkFunctionKind::NotSupported.as_str(), "not_supported");
    }

    #[test]
    fn app_function_response_predicate() {
        assert!(DnpAppFunctionKind::Response.is_response());
        assert!(DnpAppFunctionKind::UnsolicitedResponse.is_response());
        assert!(DnpAppFunctionKind::AuthenticateResponse.is_response());
        assert!(!DnpAppFunctionKind::Read.is_response());
    }
}

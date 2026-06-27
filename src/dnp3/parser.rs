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
    DnpAppFunctionKind, DnpApplication, DnpInternalIndications, DnpLinkDirection,
    DnpLinkFunctionKind, DnpLinkRole, DnpMessage,
};

const START_BYTES: [u8; 2] = [0x05, 0x64];
const LINK_HEADER_LEN: usize = 10;
/// First user-data block max payload (16 bytes + 2 CRC).
const FIRST_BLOCK_DATA: usize = 16;

/// DNP3 CRC-16 over `data` (IEEE 1815-2012 §9.2.4.5).
///
/// Polynomial 0x3D65, reflected (0xA6BC), result one's-complemented
/// — the standard DNP3 framing CRC. The on-wire CRC bytes follow
/// `data` little-endian (low byte first).
///
/// Pure, bounded, no length-driven loop over attacker-controlled
/// sizes — `data` here is always the fixed 8-byte link header, so
/// this is not the reassembly-style code path the Suricata DNP3 CVE
/// lived in.
fn dnp3_crc(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xA6BC;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Failure mode for [`parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// Payload shorter than the 10-byte link header.
    Truncated { need: usize, have: usize },
    /// Bytes 0..2 weren't the `0x05 0x64` start-bytes magic.
    BadStartBytes,
    /// Link-layer length byte was < 5 (the minimum valid).
    InvalidLength(u8),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated { need, have } => {
                write!(f, "truncated DNP3 link header: need {need}, have {have}")
            }
            Self::BadStartBytes => f.write_str("bad start bytes (expected 0x0564)"),
            Self::InvalidLength(n) => write!(f, "invalid link-layer length: {n} (min 5)"),
        }
    }
}

impl std::error::Error for ParseError {}

impl From<ParseError> for crate::Error {
    fn from(e: ParseError) -> Self {
        use crate::error::{ErrorCode, Module};
        let code = match &e {
            ParseError::Truncated { .. } => ErrorCode::Truncated,
            ParseError::BadStartBytes | ParseError::InvalidLength(_) => ErrorCode::Parse,
        };
        crate::Error::with_code(Module::Dnp3, code, e.to_string())
    }
}

/// Parse a single DNP3 frame from the front of `payload`.
pub fn parse(payload: &[u8]) -> Result<DnpMessage, ParseError> {
    if payload.len() < LINK_HEADER_LEN {
        return Err(ParseError::Truncated {
            need: LINK_HEADER_LEN,
            have: payload.len(),
        });
    }
    if payload[0..2] != START_BYTES {
        return Err(ParseError::BadStartBytes);
    }
    let length = payload[2] as usize;
    // RFC: length covers ctrl + dst + src + payload, NOT the
    // length byte itself, the start bytes, or the CRCs.
    // Minimum valid value is 5 (just the link header).
    if length < 5 {
        return Err(ParseError::InvalidLength(payload[2]));
    }
    let control = payload[3];
    let dst_addr = u16::from_le_bytes([payload[4], payload[5]]);
    let src_addr = u16::from_le_bytes([payload[6], payload[7]]);
    // Bytes 8..10 are the header CRC (little-endian) covering the
    // 8-byte link header. Validate it (issue #80) so consumers can
    // tell a corrupt/non-DNP3 frame from a clean one.
    let on_wire_crc = u16::from_le_bytes([payload[8], payload[9]]);
    let header_crc_valid = dnp3_crc(&payload[0..8]) == on_wire_crc;

    let link_function = DnpLinkFunctionKind::from_raw(control);
    let link_dir = DnpLinkDirection::from_bit((control & 0x80) != 0);
    let link_prm = DnpLinkRole::from_bit((control & 0x40) != 0);

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

    Ok(DnpMessage {
        src_addr,
        dst_addr,
        link_function,
        link_dir,
        link_prm,
        application,
        header_crc_valid,
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
        // Real header CRC over the 8-byte link header (issue #80).
        out.extend_from_slice(&dnp3_crc(&out[0..8]).to_le_bytes());
        out.extend_from_slice(user_data);
        out
    }

    #[test]
    fn crc_matches_dnp3_spec_vector() {
        // IEEE 1815 §9.2.4.5 worked example: CRC of the 8-byte
        // link header `05 64 05 C0 01 00 00 04` is 0x21E9, stored
        // little-endian on the wire as E9 21.
        let header = [0x05u8, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x00, 0x04];
        assert_eq!(dnp3_crc(&header), 0x21E9);
    }

    #[test]
    fn header_crc_validates_and_detects_tampering() {
        let mut buf = build_frame(0xC0, 1, 2, &[]);
        assert!(parse(&buf).unwrap().header_crc_valid);
        // Flip a CRC byte → invalid, but the frame still parses
        // (metadata is surfaced with header_crc_valid = false).
        buf[8] ^= 0xFF;
        let msg = parse(&buf).unwrap();
        assert!(!msg.header_crc_valid);
        assert_eq!(msg.src_addr, 2); // metadata still extracted
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
        assert_eq!(msg.link_dir, DnpLinkDirection::ToOutstation);
        assert_eq!(msg.link_prm, DnpLinkRole::Primary);
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
        assert_eq!(parse(&buf).unwrap_err(), ParseError::BadStartBytes);
    }

    #[test]
    fn rejects_too_short() {
        assert_eq!(
            parse(&[0u8; 9]).unwrap_err(),
            ParseError::Truncated { need: 10, have: 9 }
        );
    }

    #[test]
    fn rejects_invalid_length() {
        let mut buf = build_frame(0xC0, 1, 2, &[]);
        buf[2] = 0x02; // length < 5 is invalid
        assert_eq!(parse(&buf).unwrap_err(), ParseError::InvalidLength(0x02));
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
        assert_eq!(msg.link_prm, DnpLinkRole::Secondary);
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

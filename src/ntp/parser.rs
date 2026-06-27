//! NTP wire decoder. RFC 5905 §7.3.

use super::types::{NtpLeapIndicator, NtpMessage, NtpMode, NtpTimestamp};

/// NTP fixed-header size — every conformant NTP / SNTP datagram
/// is at least this. Extension fields, KOD, and MAC append to
/// it but aren't surfaced.
pub const NTP_HEADER_LEN: usize = 48;

/// Failure mode for [`parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// Payload shorter than the 48-byte NTP fixed header.
    Truncated { need: usize, have: usize },
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated { need, have } => {
                write!(f, "truncated NTP header: need {need}, have {have}")
            }
        }
    }
}

impl std::error::Error for ParseError {}

impl From<ParseError> for crate::Error {
    fn from(e: ParseError) -> Self {
        use crate::error::{ErrorCode, Module};
        let code = match &e {
            ParseError::Truncated { .. } => ErrorCode::Truncated,
        };
        crate::Error::with_code(Module::Ntp, code, e.to_string())
    }
}

/// Parse a UDP/123 payload as an NTP message.
///
/// Returns `Err` when the payload is shorter than 48 bytes.
/// Larger payloads parse cleanly — the trailing bytes are
/// extension fields / authentication, which we don't surface.
pub fn parse(payload: &[u8]) -> Result<NtpMessage, ParseError> {
    if payload.len() < NTP_HEADER_LEN {
        return Err(ParseError::Truncated {
            need: NTP_HEADER_LEN,
            have: payload.len(),
        });
    }
    let b0 = payload[0];
    let leap = NtpLeapIndicator::from_raw((b0 >> 6) & 0x03);
    let version = (b0 >> 3) & 0x07;
    let mode = NtpMode::from_raw(b0 & 0x07);
    let stratum = payload[1];
    let poll = payload[2] as i8;
    let precision = payload[3] as i8;
    let root_delay_raw = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let root_dispersion_raw =
        u32::from_be_bytes([payload[8], payload[9], payload[10], payload[11]]);
    let mut ref_id = [0u8; 4];
    ref_id.copy_from_slice(&payload[12..16]);
    let ref_timestamp = decode_timestamp(&payload[16..24]);
    let origin_timestamp = decode_timestamp(&payload[24..32]);
    let recv_timestamp = decode_timestamp(&payload[32..40]);
    let transmit_timestamp = decode_timestamp(&payload[40..48]);

    Ok(NtpMessage {
        leap,
        version,
        mode,
        stratum,
        poll,
        precision,
        root_delay_raw,
        root_dispersion_raw,
        ref_id,
        ref_timestamp,
        origin_timestamp,
        recv_timestamp,
        transmit_timestamp,
    })
}

fn decode_timestamp(bytes: &[u8]) -> NtpTimestamp {
    NtpTimestamp {
        seconds: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        fraction: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn build_msg(b0: u8, stratum: u8, ref_id: [u8; 4]) -> Vec<u8> {
        let mut p = vec![0u8; NTP_HEADER_LEN];
        p[0] = b0;
        p[1] = stratum;
        p[12..16].copy_from_slice(&ref_id);
        p
    }

    #[test]
    fn parses_minimal_client_request() {
        // VN=4, mode=3 (client), LI=0.
        let p = build_msg((4 << 3) | 3, 0, [0; 4]);
        let m = parse(&p).unwrap();
        assert_eq!(m.version, 4);
        assert_eq!(m.mode, NtpMode::Client);
        assert_eq!(m.leap, NtpLeapIndicator::NoWarning);
        assert_eq!(m.stratum, 0);
    }

    #[test]
    fn parses_server_reply_with_ipv4_ref_id() {
        // VN=4, mode=4 (server), stratum=2, ref_id = upstream IP.
        let p = build_msg((4 << 3) | 4, 2, [192, 0, 2, 1]);
        let m = parse(&p).unwrap();
        assert_eq!(m.mode, NtpMode::Server);
        assert_eq!(m.ref_id_as_ipv4(), Some(Ipv4Addr::new(192, 0, 2, 1)));
    }

    #[test]
    fn parses_stratum1_with_ascii_ref_id() {
        let p = build_msg((4 << 3) | 4, 1, *b"GPS\0");
        let m = parse(&p).unwrap();
        assert_eq!(m.stratum, 1);
        assert_eq!(m.ref_id_as_str(), Some("GPS"));
    }

    #[test]
    fn parses_mode7_monlist_amplification() {
        // Real monlist requests carry mode=7 (private),
        // version=2 (legacy). Both flagged.
        let p = build_msg((2 << 3) | 7, 0, [0; 4]);
        let m = parse(&p).unwrap();
        assert_eq!(m.mode, NtpMode::Private);
        assert_eq!(m.version, 2);
        assert!(m.is_amplification_risk());
    }

    #[test]
    fn rejects_truncated_payload() {
        assert!(parse(&[]).is_err());
        assert!(parse(&[0; 47]).is_err());
    }

    #[test]
    fn extension_field_bytes_after_48b_are_ignored() {
        let mut p = build_msg((4 << 3) | 4, 1, *b"PPS\0");
        // Add 8 bytes of "MAC" past the header. Parser must not
        // care about anything past the fixed 48 bytes.
        p.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0x00, 0x01, 0x02, 0x03]);
        let m = parse(&p).unwrap();
        assert_eq!(m.ref_id_as_str(), Some("PPS"));
    }

    #[test]
    fn timestamps_decode_round_trip() {
        let mut p = vec![0u8; NTP_HEADER_LEN];
        p[0] = (4 << 3) | 4;
        p[1] = 2;
        // Reference timestamp = NTP epoch + 1234, frac = 0x80000000 (=0.5 sec).
        p[16..20].copy_from_slice(&1234u32.to_be_bytes());
        p[20..24].copy_from_slice(&0x80000000u32.to_be_bytes());
        let m = parse(&p).unwrap();
        assert_eq!(m.ref_timestamp.seconds, 1234);
        assert_eq!(m.ref_timestamp.fraction, 0x80000000);
    }

    #[test]
    fn poll_and_precision_decode_as_signed() {
        let mut p = build_msg((4 << 3) | 4, 1, [0; 4]);
        p[2] = 0xfc; // -4 as i8
        p[3] = 0xe0; // -32 as i8
        let m = parse(&p).unwrap();
        assert_eq!(m.poll, -4);
        assert_eq!(m.precision, -32);
    }
}

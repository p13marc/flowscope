//! STUN wire-format parser.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::types::{StunClass, StunMessage, extract_method};

/// RFC 5389 §6 magic cookie. Every modern STUN message
/// includes this 4-byte value immediately after the
/// length field.
pub const MAGIC_COOKIE: u32 = 0x2112_A442;

const HEADER_LEN: usize = 20;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_USERNAME: u16 = 0x0006;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_SOFTWARE: u16 = 0x8022;

/// Failure mode for [`parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// Payload shorter than the 20-byte STUN header, or the
    /// length field claims more attribute bytes than present.
    Truncated { need: usize, have: usize },
    /// Top two type bits were set, or the RFC 5389 magic
    /// cookie was absent — not a STUN message.
    NotStun,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated { need, have } => {
                write!(f, "truncated STUN message: need {need}, have {have}")
            }
            Self::NotStun => f.write_str("not a STUN message (bad type bits or magic cookie)"),
        }
    }
}

impl std::error::Error for ParseError {}

impl From<ParseError> for crate::Error {
    fn from(e: ParseError) -> Self {
        use crate::error::{ErrorCode, Module};
        let code = match &e {
            ParseError::Truncated { .. } => ErrorCode::Truncated,
            ParseError::NotStun => ErrorCode::Parse,
        };
        crate::Error::with_code(Module::Stun, code, e.to_string())
    }
}

/// Parse a single UDP datagram as a STUN message. Returns
/// `Err` for any payload that doesn't match the STUN wire
/// shape exactly (header length, magic cookie, length field
/// internal consistency).
pub fn parse(payload: &[u8]) -> Result<StunMessage, ParseError> {
    if payload.len() < HEADER_LEN {
        return Err(ParseError::Truncated {
            need: HEADER_LEN,
            have: payload.len(),
        });
    }
    let type_word = u16::from_be_bytes([payload[0], payload[1]]);
    // The top 2 bits MUST be zero per RFC 5389 §6.
    if (type_word & 0xc000) != 0 {
        return Err(ParseError::NotStun);
    }
    let msg_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    let cookie = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(ParseError::NotStun);
    }
    if payload.len() < HEADER_LEN + msg_len {
        return Err(ParseError::Truncated {
            need: HEADER_LEN + msg_len,
            have: payload.len(),
        });
    }
    let class = StunClass::from_type_bits(type_word);
    let method = extract_method(type_word);
    let mut transaction_id = [0u8; 12];
    transaction_id.copy_from_slice(&payload[8..20]);

    let mut mapped_address = None;
    let mut username = None;
    let mut software = None;

    let attrs = &payload[HEADER_LEN..HEADER_LEN + msg_len];
    let mut cursor = 0;
    while cursor + 4 <= attrs.len() {
        let attr_type = u16::from_be_bytes([attrs[cursor], attrs[cursor + 1]]);
        let attr_len = u16::from_be_bytes([attrs[cursor + 2], attrs[cursor + 3]]) as usize;
        cursor += 4;
        if cursor + attr_len > attrs.len() {
            // Truncated attribute — bail.
            break;
        }
        let value = &attrs[cursor..cursor + attr_len];
        match attr_type {
            ATTR_MAPPED_ADDRESS => {
                if let Some(addr) = decode_mapped_address(value, false, &transaction_id) {
                    mapped_address = Some(addr);
                }
            }
            ATTR_XOR_MAPPED_ADDRESS => {
                if let Some(addr) = decode_mapped_address(value, true, &transaction_id) {
                    mapped_address = Some(addr);
                }
            }
            ATTR_USERNAME => {
                username = Some(String::from_utf8_lossy(value).to_string());
            }
            ATTR_SOFTWARE => {
                software = Some(String::from_utf8_lossy(value).to_string());
            }
            _ => {}
        }
        // Attributes are padded to a 4-byte boundary.
        let padded = (attr_len + 3) & !3;
        cursor += padded;
    }

    Ok(StunMessage {
        class,
        method,
        transaction_id,
        mapped_address,
        username,
        software,
    })
}

/// Decode MAPPED-ADDRESS (RFC 5389 §15.1) or
/// XOR-MAPPED-ADDRESS (§15.2). Layout:
/// `reserved(1)|family(1)|port(2)|address(4 or 16)`.
fn decode_mapped_address(value: &[u8], xor: bool, txn: &[u8; 12]) -> Option<SocketAddr> {
    if value.len() < 4 {
        return None;
    }
    let family = value[1];
    let port_raw = u16::from_be_bytes([value[2], value[3]]);
    let port = if xor {
        port_raw ^ ((MAGIC_COOKIE >> 16) as u16)
    } else {
        port_raw
    };
    match family {
        0x01 => {
            // IPv4
            if value.len() < 8 {
                return None;
            }
            let raw = u32::from_be_bytes([value[4], value[5], value[6], value[7]]);
            let ip_u32 = if xor { raw ^ MAGIC_COOKIE } else { raw };
            Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip_u32)), port))
        }
        0x02 => {
            // IPv6 — XOR uses the magic cookie + transaction ID.
            if value.len() < 20 {
                return None;
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&value[4..20]);
            if xor {
                let cookie_be = MAGIC_COOKIE.to_be_bytes();
                ip[0] ^= cookie_be[0];
                ip[1] ^= cookie_be[1];
                ip[2] ^= cookie_be[2];
                ip[3] ^= cookie_be[3];
                for i in 0..12 {
                    ip[4 + i] ^= txn[i];
                }
            }
            Some(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), port))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_binding_request(txn: [u8; 12], attrs: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0x0001u16.to_be_bytes()); // Binding Request
        buf.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
        buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        buf.extend_from_slice(&txn);
        buf.extend_from_slice(attrs);
        buf
    }

    fn pad_to_4(value: &[u8]) -> Vec<u8> {
        let padded = (value.len() + 3) & !3;
        let mut v = value.to_vec();
        v.resize(padded, 0);
        v
    }

    #[test]
    fn parses_minimal_binding_request() {
        let txn = [1u8; 12];
        let buf = build_binding_request(txn, &[]);
        let msg = parse(&buf).expect("parse");
        assert_eq!(msg.class, StunClass::Request);
        assert_eq!(msg.method, 0x001); // Binding
        assert_eq!(msg.transaction_id, txn);
    }

    #[test]
    fn rejects_wrong_magic_cookie() {
        let mut buf = build_binding_request([0u8; 12], &[]);
        buf[4..8].copy_from_slice(&0xdeadbeefu32.to_be_bytes());
        assert!(parse(&buf).is_err());
    }

    #[test]
    fn rejects_top_two_bits_set() {
        let mut buf = build_binding_request([0u8; 12], &[]);
        buf[0] |= 0xc0;
        assert!(parse(&buf).is_err());
    }

    #[test]
    fn rejects_too_short() {
        assert!(parse(&[0u8; 19]).is_err());
    }

    #[test]
    fn decodes_xor_mapped_address_ipv4() {
        // XOR-encoded `192.168.1.42:5000`.
        let txn = [0u8; 12];
        let port: u16 = 5000 ^ ((MAGIC_COOKIE >> 16) as u16);
        let ip_raw: u32 = u32::from(Ipv4Addr::new(192, 168, 1, 42)) ^ MAGIC_COOKIE;
        let mut attr_value = Vec::new();
        attr_value.push(0); // reserved
        attr_value.push(0x01); // IPv4 family
        attr_value.extend_from_slice(&port.to_be_bytes());
        attr_value.extend_from_slice(&ip_raw.to_be_bytes());
        let mut attrs = Vec::new();
        attrs.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        attrs.extend_from_slice(&(attr_value.len() as u16).to_be_bytes());
        attrs.extend_from_slice(&pad_to_4(&attr_value));
        let buf = build_binding_request(txn, &attrs);
        let msg = parse(&buf).expect("parse");
        let addr = msg.mapped_address.expect("xor-mapped");
        assert_eq!(
            addr,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42)), 5000)
        );
    }

    #[test]
    fn decodes_software_attribute() {
        let txn = [0u8; 12];
        let value = b"Coturn-4.5.2";
        let mut attrs = Vec::new();
        attrs.extend_from_slice(&ATTR_SOFTWARE.to_be_bytes());
        attrs.extend_from_slice(&(value.len() as u16).to_be_bytes());
        attrs.extend_from_slice(&pad_to_4(value));
        let buf = build_binding_request(txn, &attrs);
        let msg = parse(&buf).expect("parse");
        assert_eq!(msg.software.as_deref(), Some("Coturn-4.5.2"));
    }

    #[test]
    fn decodes_username_attribute() {
        let txn = [0u8; 12];
        let value = b"realm:alice";
        let mut attrs = Vec::new();
        attrs.extend_from_slice(&ATTR_USERNAME.to_be_bytes());
        attrs.extend_from_slice(&(value.len() as u16).to_be_bytes());
        attrs.extend_from_slice(&pad_to_4(value));
        let buf = build_binding_request(txn, &attrs);
        let msg = parse(&buf).expect("parse");
        assert_eq!(msg.username.as_deref(), Some("realm:alice"));
    }

    #[test]
    fn success_response_class_decoded() {
        let mut buf = build_binding_request([0u8; 12], &[]);
        // Set class bits to (1, 0) → SuccessResponse: type = 0x0101.
        buf[0..2].copy_from_slice(&0x0101u16.to_be_bytes());
        let msg = parse(&buf).expect("parse");
        assert_eq!(msg.class, StunClass::SuccessResponse);
        assert_eq!(msg.method, 0x001);
    }

    #[test]
    fn error_response_class_decoded() {
        let mut buf = build_binding_request([0u8; 12], &[]);
        buf[0..2].copy_from_slice(&0x0111u16.to_be_bytes()); // (1, 1) error
        let msg = parse(&buf).expect("parse");
        assert_eq!(msg.class, StunClass::ErrorResponse);
    }

    #[test]
    fn class_as_str_slugs() {
        assert_eq!(StunClass::Request.as_str(), "request");
        assert_eq!(StunClass::Indication.as_str(), "indication");
        assert_eq!(StunClass::SuccessResponse.as_str(), "success_response");
        assert_eq!(StunClass::ErrorResponse.as_str(), "error_response");
    }
}

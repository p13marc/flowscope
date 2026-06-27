//! RADIUS wire-format parsing via rusticata radius-parser.

use super::types::{RadiusCodeKind, RadiusMessage};

/// Failure mode for [`parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// RADIUS wire decode failure (malformed / truncated /
    /// non-RADIUS payload).
    Decode,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decode => f.write_str("RADIUS decode failed"),
        }
    }
}

impl std::error::Error for ParseError {}

impl From<ParseError> for crate::Error {
    fn from(e: ParseError) -> Self {
        use crate::error::{ErrorCode, Module};
        let code = match &e {
            ParseError::Decode => ErrorCode::Parse,
        };
        crate::Error::with_code(Module::Radius, code, e.to_string())
    }
}

/// Parse one RADIUS UDP datagram. Returns a [`ParseError`] on
/// malformed input.
pub fn parse(payload: &[u8]) -> Result<RadiusMessage, ParseError> {
    let (_rem, data) = radius_parser::parse_radius_data(payload).map_err(|_| ParseError::Decode)?;
    let code = RadiusCodeKind::from_raw(data.code.0);
    let mut msg = RadiusMessage {
        code,
        identifier: data.identifier,
        authenticator_len: data.authenticator.len(),
        username: None,
        calling_station_id: None,
        called_station_id: None,
        nas_ip_address: None,
        framed_ip_address: None,
        has_user_password: false,
    };
    if let Some(attrs) = data.attributes {
        for attr in attrs {
            use radius_parser::RadiusAttribute as A;
            match attr {
                A::UserName(b) => {
                    msg.username = Some(String::from_utf8_lossy(b).into_owned());
                }
                A::UserPassword(_) => {
                    msg.has_user_password = true;
                }
                A::CallingStationId(b) => {
                    msg.calling_station_id = Some(String::from_utf8_lossy(b).into_owned());
                }
                A::CalledStationId(b) => {
                    msg.called_station_id = Some(String::from_utf8_lossy(b).into_owned());
                }
                A::NasIPAddress(ip) => {
                    msg.nas_ip_address = Some(ip);
                }
                A::FramedIPAddress(ip) => {
                    msg.framed_ip_address = Some(ip);
                }
                _ => {}
            }
        }
    }
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-built Access-Request with UserName="alice",
    /// User-Password (4 bytes, will be hashed but we just
    /// detect presence), NAS-IP-Address=10.0.0.5,
    /// Calling-Station-Id="00:11:22:33:44:55".
    fn sample_access_request() -> Vec<u8> {
        let mut buf = Vec::new();
        // RADIUS header: code(1) | identifier(1) | length(2) |
        // authenticator(16).
        buf.push(1); // Access-Request
        buf.push(0x42); // identifier
        // length placeholder (filled below).
        buf.extend_from_slice(&[0, 0]);
        buf.extend_from_slice(&[0u8; 16]); // authenticator (zeros)
        // Attributes: User-Name "alice" (type 1, len 7, value "alice").
        buf.extend_from_slice(&[1, 7, b'a', b'l', b'i', b'c', b'e']);
        // User-Password (type 2, len 18, 16 bytes hash payload).
        buf.push(2);
        buf.push(18);
        buf.extend_from_slice(&[0xab; 16]);
        // NAS-IP-Address (type 4, len 6, 10.0.0.5).
        buf.extend_from_slice(&[4, 6, 10, 0, 0, 5]);
        // Calling-Station-Id (type 31, len 19, "00:11:22:33:44:55").
        buf.push(31);
        let csi = b"00:11:22:33:44:55";
        buf.push((csi.len() + 2) as u8);
        buf.extend_from_slice(csi);
        // Fill the length field.
        let total = buf.len() as u16;
        buf[2..4].copy_from_slice(&total.to_be_bytes());
        buf
    }

    #[test]
    fn parses_access_request() {
        let payload = sample_access_request();
        let msg = parse(&payload).expect("parse");
        assert_eq!(msg.code, RadiusCodeKind::AccessRequest);
        assert_eq!(msg.identifier, 0x42);
        assert_eq!(msg.username.as_deref(), Some("alice"));
        assert!(msg.has_user_password);
        assert_eq!(
            msg.nas_ip_address,
            Some(std::net::Ipv4Addr::new(10, 0, 0, 5))
        );
        assert_eq!(msg.calling_station_id.as_deref(), Some("00:11:22:33:44:55"));
        assert_eq!(msg.authenticator_len, 16);
    }

    #[test]
    fn rejects_truncated() {
        assert!(parse(&[0u8; 5]).is_err());
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse(b"not radius").is_err());
    }

    #[test]
    fn code_slugs_match() {
        assert_eq!(RadiusCodeKind::AccessRequest.as_str(), "access_request");
        assert_eq!(RadiusCodeKind::AccessAccept.as_str(), "access_accept");
        assert_eq!(RadiusCodeKind::AccessReject.as_str(), "access_reject");
        assert_eq!(
            RadiusCodeKind::AccountingRequest.as_str(),
            "accounting_request"
        );
        assert_eq!(RadiusCodeKind::Other(99).as_str(), "other");
    }

    #[test]
    fn message_with_no_attrs_still_parses() {
        // Header only.
        let mut buf = vec![1u8, 0x00];
        buf.extend_from_slice(&20u16.to_be_bytes());
        buf.extend_from_slice(&[0u8; 16]);
        let msg = parse(&buf).expect("header-only parses");
        assert_eq!(msg.code, RadiusCodeKind::AccessRequest);
        assert!(msg.username.is_none());
        assert!(!msg.has_user_password);
    }
}

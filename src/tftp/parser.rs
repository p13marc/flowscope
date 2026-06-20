//! TFTP wire parser — RFC 1350 §5.

use super::types::{TftpErrorCode, TftpMessage, TftpMode, TftpOpcode};

/// Parse a UDP/69 payload as a TFTP packet.
///
/// Returns `None` when:
/// - The payload is shorter than 2 bytes (no opcode field).
/// - The opcode is one of the request shapes (1/2) but the
///   payload lacks two NUL-terminated strings (filename + mode).
/// - The opcode is DATA (3) or ACK (4) but the payload is
///   shorter than the 4-byte fixed header.
/// - The opcode is ERROR (5) but the payload lacks a 2-byte
///   errcode + NUL-terminated message.
pub fn parse(payload: &[u8]) -> Option<TftpMessage> {
    if payload.len() < 2 {
        return None;
    }
    let opcode = TftpOpcode::from_raw(u16::from_be_bytes([payload[0], payload[1]]));
    let rest = &payload[2..];

    let mut msg = TftpMessage {
        opcode,
        filename: None,
        mode: None,
        block: None,
        data_len: None,
        error_code: None,
        error_message: None,
    };

    match opcode {
        TftpOpcode::ReadRequest | TftpOpcode::WriteRequest => {
            let (filename, after) = take_nul_string(rest)?;
            let (mode, _after2) = take_nul_string(after)?;
            msg.filename = Some(filename);
            msg.mode = Some(TftpMode::parse_str(&mode));
        }
        TftpOpcode::Data => {
            if rest.len() < 2 {
                return None;
            }
            msg.block = Some(u16::from_be_bytes([rest[0], rest[1]]));
            msg.data_len = Some(rest.len() - 2);
        }
        TftpOpcode::Ack => {
            if rest.len() < 2 {
                return None;
            }
            msg.block = Some(u16::from_be_bytes([rest[0], rest[1]]));
        }
        TftpOpcode::Error => {
            if rest.len() < 2 {
                return None;
            }
            msg.error_code = Some(TftpErrorCode::from_raw(u16::from_be_bytes([
                rest[0], rest[1],
            ])));
            // RFC 1350 §5 specifies a NUL-terminated message;
            // tolerate either form (with or without).
            let tail = &rest[2..];
            let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
            if let Ok(s) = std::str::from_utf8(&tail[..end]) {
                msg.error_message = Some(s.to_string());
            }
        }
        TftpOpcode::Other(_) => {
            // Surface the opcode but nothing past it — we don't
            // know the shape.
        }
    }

    Some(msg)
}

/// Read a NUL-terminated US-ASCII string from `buf`. Returns
/// `(string, remainder_after_NUL)`. Rejects non-UTF-8 bytes,
/// missing NUL, and zero-length strings (RFC 1350 implies
/// filename + mode are both non-empty).
fn take_nul_string(buf: &[u8]) -> Option<(String, &[u8])> {
    let nul = buf.iter().position(|&b| b == 0)?;
    if nul == 0 {
        return None;
    }
    let s = std::str::from_utf8(&buf[..nul]).ok()?.to_string();
    Some((s, &buf[nul + 1..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rrq(filename: &str, mode: &str) -> Vec<u8> {
        let mut p = vec![0x00, 0x01];
        p.extend_from_slice(filename.as_bytes());
        p.push(0);
        p.extend_from_slice(mode.as_bytes());
        p.push(0);
        p
    }

    fn wrq(filename: &str, mode: &str) -> Vec<u8> {
        let mut p = vec![0x00, 0x02];
        p.extend_from_slice(filename.as_bytes());
        p.push(0);
        p.extend_from_slice(mode.as_bytes());
        p.push(0);
        p
    }

    fn data(block: u16, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x00, 0x03];
        p.extend_from_slice(&block.to_be_bytes());
        p.extend_from_slice(payload);
        p
    }

    fn ack(block: u16) -> Vec<u8> {
        let mut p = vec![0x00, 0x04];
        p.extend_from_slice(&block.to_be_bytes());
        p
    }

    fn err(code: u16, msg: &str) -> Vec<u8> {
        let mut p = vec![0x00, 0x05];
        p.extend_from_slice(&code.to_be_bytes());
        p.extend_from_slice(msg.as_bytes());
        p.push(0);
        p
    }

    #[test]
    fn parses_rrq() {
        let m = parse(&rrq("running-config", "octet")).unwrap();
        assert_eq!(m.opcode, TftpOpcode::ReadRequest);
        assert_eq!(m.filename.as_deref(), Some("running-config"));
        assert_eq!(m.mode, Some(TftpMode::Octet));
        assert!(m.is_device_config_transfer());
    }

    #[test]
    fn parses_wrq_with_netascii_mode() {
        let m = parse(&wrq("readme.txt", "netascii")).unwrap();
        assert_eq!(m.opcode, TftpOpcode::WriteRequest);
        assert_eq!(m.mode, Some(TftpMode::NetAscii));
    }

    #[test]
    fn parses_data_block() {
        let payload = b"\x00\x01\x02hello world";
        let m = parse(&data(7, payload)).unwrap();
        assert_eq!(m.opcode, TftpOpcode::Data);
        assert_eq!(m.block, Some(7));
        assert_eq!(m.data_len, Some(payload.len()));
    }

    #[test]
    fn parses_ack() {
        let m = parse(&ack(42)).unwrap();
        assert_eq!(m.opcode, TftpOpcode::Ack);
        assert_eq!(m.block, Some(42));
    }

    #[test]
    fn parses_error_packet() {
        let m = parse(&err(2, "Access violation")).unwrap();
        assert_eq!(m.opcode, TftpOpcode::Error);
        assert_eq!(m.error_code, Some(TftpErrorCode::AccessViolation));
        assert_eq!(m.error_message.as_deref(), Some("Access violation"));
    }

    #[test]
    fn parses_error_without_trailing_nul() {
        // Some implementations omit the NUL. Tolerate it.
        let mut p = vec![0x00, 0x05, 0x00, 0x06];
        p.extend_from_slice(b"File already exists");
        let m = parse(&p).unwrap();
        assert_eq!(m.error_code, Some(TftpErrorCode::FileAlreadyExists));
        assert_eq!(m.error_message.as_deref(), Some("File already exists"));
    }

    #[test]
    fn rejects_truncated_payload() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[0x00]).is_none());
        // RRQ opcode, no strings.
        assert!(parse(&[0x00, 0x01]).is_none());
        // DATA opcode with no block field.
        assert!(parse(&[0x00, 0x03]).is_none());
        // ACK opcode with no block field.
        assert!(parse(&[0x00, 0x04, 0x00]).is_none());
    }

    #[test]
    fn rejects_rrq_with_empty_filename() {
        let mut p = vec![0x00, 0x01];
        p.push(0); // empty filename
        p.extend_from_slice(b"octet");
        p.push(0);
        assert!(parse(&p).is_none());
    }

    #[test]
    fn unknown_opcode_yields_other() {
        let p = [0x00, 0x42];
        let m = parse(&p).unwrap();
        assert_eq!(m.opcode, TftpOpcode::Other(0x42));
        assert!(m.filename.is_none());
    }

    #[test]
    fn rrq_with_non_utf8_filename_is_rejected() {
        let mut p = vec![0x00, 0x01];
        p.extend_from_slice(&[0xff, 0xfe, 0xfd]);
        p.push(0);
        p.extend_from_slice(b"octet");
        p.push(0);
        assert!(parse(&p).is_none());
    }
}

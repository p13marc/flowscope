//! Wire-format helpers for the SMTP control channel.

use base64::Engine;
use bytes::BytesMut;

/// Extract the first `\r\n`-terminated line from `buf`. Caps
/// a single line at 8 KiB (RFC 5321 §4.5.3.1.6 mandates 512
/// for command lines but in practice EHLO / response lines
/// can be longer). Returns `None` if no full line is present.
pub(crate) fn extract_line(buf: &mut BytesMut) -> Option<Vec<u8>> {
    const MAX_LINE: usize = 8192;
    loop {
        let eol = find_crlf(buf);
        if eol.is_none() {
            if buf.len() > MAX_LINE {
                buf.clear();
            }
            return None;
        }
        let eol = eol.unwrap();
        if eol > MAX_LINE {
            advance_by(buf, eol + 2);
            continue;
        }
        let line = buf[..eol].to_vec();
        advance_by(buf, eol + 2);
        return Some(line);
    }
}

fn find_crlf(buf: &BytesMut) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

pub(crate) fn advance_by(buf: &mut BytesMut, n: usize) {
    use bytes::Buf;
    let n = n.min(buf.len());
    Buf::advance(buf, n);
}

/// Split a command line into `(verb, args)`. Returns `None`
/// for empty / non-UTF8 lines.
pub(crate) fn split_command(line: &[u8]) -> Option<(&str, &str)> {
    let s = std::str::from_utf8(line).ok()?;
    let s = s.trim_end();
    if s.is_empty() {
        return None;
    }
    if let Some(sp) = s.find(|c: char| c.is_whitespace()) {
        let (verb, rest) = s.split_at(sp);
        Some((verb, rest.trim_start()))
    } else {
        Some((s, ""))
    }
}

/// Split a reply line into `(code, text, is_final)`.
pub(crate) fn split_reply(line: &[u8]) -> Option<(u16, &str, bool)> {
    let s = std::str::from_utf8(line).ok()?;
    if s.len() < 4 {
        return None;
    }
    let code: u16 = s[..3].parse().ok()?;
    let separator = s.as_bytes()[3];
    let text = s[4..].trim_end();
    Some((code, text, separator == b' '))
}

/// Strip the `<>` brackets from an SMTP envelope address.
/// Tolerates upper/lowercase prefix (`MAIL FROM:` vs `From:`),
/// trailing parameters (`SIZE=1234`), and surrounding
/// whitespace.
pub(crate) fn extract_envelope_address(args: &str) -> Option<String> {
    // After ":", grab the `<...>` token.
    let after_colon = args.split_once(':').map(|(_, r)| r).unwrap_or(args);
    let trimmed = after_colon.trim_start();
    if !trimmed.starts_with('<') {
        return None;
    }
    let end = trimmed.find('>')?;
    Some(trimmed[1..end].to_string())
}

/// Decode an `AUTH PLAIN` base64 blob `\0user\0pass`. Returns
/// `(user, pass)`. Either may be empty.
pub(crate) fn decode_auth_plain(b64: &str) -> Option<(String, String)> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    // Layout: [authzid] \0 authcid \0 password
    let mut parts = raw.split(|&b| b == 0);
    let _authzid = parts.next();
    let authcid = parts.next()?;
    let password = parts.next()?;
    Some((
        String::from_utf8_lossy(authcid).to_string(),
        String::from_utf8_lossy(password).to_string(),
    ))
}

/// Decode an AUTH LOGIN base64 token (just the user or just
/// the password, depending on which prompt it follows).
pub(crate) fn decode_auth_login_token(b64: &str) -> Option<String> {
    let raw = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .ok()?;
    Some(String::from_utf8_lossy(&raw).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_line_handles_one_line() {
        let mut buf = BytesMut::from(&b"EHLO example.org\r\n"[..]);
        let line = extract_line(&mut buf).expect("line");
        assert_eq!(line, b"EHLO example.org");
        assert!(buf.is_empty());
    }

    #[test]
    fn extract_line_drops_overlong() {
        let mut buf = BytesMut::from(vec![b'X'; 10_000].as_slice());
        let _ = extract_line(&mut buf);
        assert!(buf.is_empty());
    }

    #[test]
    fn split_command_basic() {
        let (v, a) = split_command(b"MAIL FROM:<alice@x.com>").unwrap();
        assert_eq!(v, "MAIL");
        assert_eq!(a, "FROM:<alice@x.com>");
    }

    #[test]
    fn split_command_tab_separated() {
        let (v, a) = split_command(b"EHLO\texample.org").unwrap();
        assert_eq!(v, "EHLO");
        assert_eq!(a, "example.org");
    }

    #[test]
    fn split_reply_final_line() {
        let (code, text, is_final) = split_reply(b"250 OK").unwrap();
        assert_eq!(code, 250);
        assert_eq!(text, "OK");
        assert!(is_final);
    }

    #[test]
    fn split_reply_intermediate_line() {
        let (code, _, is_final) = split_reply(b"250-PIPELINING").unwrap();
        assert_eq!(code, 250);
        assert!(!is_final);
    }

    #[test]
    fn extract_envelope_address_basic() {
        let addr = extract_envelope_address("FROM:<alice@example.com>").unwrap();
        assert_eq!(addr, "alice@example.com");
    }

    #[test]
    fn extract_envelope_address_with_size_param() {
        let addr = extract_envelope_address("FROM:<bob@x.com> SIZE=1024").unwrap();
        assert_eq!(addr, "bob@x.com");
    }

    #[test]
    fn extract_envelope_address_null_sender() {
        let addr = extract_envelope_address("FROM:<>").unwrap();
        assert_eq!(addr, "");
    }

    #[test]
    fn extract_envelope_address_no_angles_is_none() {
        assert!(extract_envelope_address("FROM:alice@x.com").is_none());
    }

    #[test]
    fn decode_auth_plain_basic() {
        // "\0alice\0secret" → base64
        let b64 = base64::engine::general_purpose::STANDARD.encode("\0alice\0secret");
        let (user, pass) = decode_auth_plain(&b64).expect("decode");
        assert_eq!(user, "alice");
        assert_eq!(pass, "secret");
    }

    #[test]
    fn decode_auth_plain_with_authzid() {
        // "[authzid]\0[authcid]\0[password]" — authzid often
        // empty. Test with non-empty for completeness.
        let b64 = base64::engine::general_purpose::STANDARD.encode("admin\0alice\0secret");
        let (user, pass) = decode_auth_plain(&b64).expect("decode");
        assert_eq!(user, "alice");
        assert_eq!(pass, "secret");
    }

    #[test]
    fn decode_auth_login_token_basic() {
        let b64 = base64::engine::general_purpose::STANDARD.encode("alice");
        assert_eq!(decode_auth_login_token(&b64), Some("alice".to_string()));
    }

    #[test]
    fn decode_invalid_base64_returns_none() {
        assert!(decode_auth_plain("!!!not-base64!!!").is_none());
        assert!(decode_auth_login_token("!!!").is_none());
    }
}

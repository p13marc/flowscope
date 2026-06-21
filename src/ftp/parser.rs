//! Wire-format helpers for the FTP control channel.

use bytes::BytesMut;

/// Extract the first `\r\n`-terminated line from `buf` and
/// return it as a `&[u8]` view. Returns `None` if no full
/// line is present. Truncates the buffer past the `\r\n`.
///
/// Defensively caps a single line at 4 KiB — anything longer
/// is treated as garbage and dropped. (RFC 959 allows
/// arbitrary line lengths but real FTP never exceeds a few
/// hundred bytes.)
pub fn extract_line(buf: &mut BytesMut) -> Option<Vec<u8>> {
    const MAX_LINE: usize = 4096;
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
            buf.advance_by(eol + 2);
            continue;
        }
        let line = buf[..eol].to_vec();
        buf.advance_by(eol + 2);
        return Some(line);
    }
}

fn find_crlf(buf: &BytesMut) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

pub(crate) trait AdvanceBy {
    fn advance_by(&mut self, n: usize);
}

impl AdvanceBy for BytesMut {
    fn advance_by(&mut self, n: usize) {
        use bytes::Buf;
        let n = n.min(self.len());
        Buf::advance(self, n);
    }
}

/// Parse a command line `"VERB args"` into `(verb, args)`.
/// `verb` is trimmed; `args` may be empty.
pub(crate) fn split_command(line: &[u8]) -> Option<(&str, &str)> {
    let s = std::str::from_utf8(line).ok()?;
    let s = s.trim_end();
    if s.is_empty() {
        return None;
    }
    if let Some(sp) = s.find(' ') {
        let (verb, rest) = s.split_at(sp);
        Some((verb, rest.trim_start()))
    } else {
        Some((s, ""))
    }
}

/// Parse a reply line `"XYZ text"` or `"XYZ-text"` (multi-
/// line intermediate). Returns `(code, text, is_final)`.
/// `is_final` is `true` for `"XYZ "` (space separator) and
/// `false` for `"XYZ-"` (hyphen separator — multi-line not
/// terminated).
pub(crate) fn split_reply(line: &[u8]) -> Option<(u16, &str, bool)> {
    let s = std::str::from_utf8(line).ok()?;
    if s.len() < 4 {
        return None;
    }
    let code_str = &s[..3];
    let code: u16 = code_str.parse().ok()?;
    let separator = s.as_bytes()[3];
    let text = s[4..].trim_end();
    Some((code, text, separator == b' '))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_line_handles_one_line() {
        let mut buf = BytesMut::from(&b"USER alice\r\n"[..]);
        let line = extract_line(&mut buf).expect("line");
        assert_eq!(line, b"USER alice");
        assert!(buf.is_empty());
    }

    #[test]
    fn extract_line_handles_multiple_lines() {
        let mut buf = BytesMut::from(&b"USER alice\r\nPASS secret\r\n"[..]);
        let a = extract_line(&mut buf).unwrap();
        let b = extract_line(&mut buf).unwrap();
        assert_eq!(a, b"USER alice");
        assert_eq!(b, b"PASS secret");
    }

    #[test]
    fn extract_line_none_on_incomplete() {
        let mut buf = BytesMut::from(&b"USER alice"[..]);
        assert!(extract_line(&mut buf).is_none());
    }

    #[test]
    fn extract_line_drops_overlong_garbage() {
        let mut buf = BytesMut::from(vec![b'A'; 5000].as_slice());
        // No CRLF — should clear once the buffer exceeds 4096.
        let _ = extract_line(&mut buf);
        assert!(buf.is_empty());
    }

    #[test]
    fn split_command_basic() {
        let (verb, args) = split_command(b"USER alice").unwrap();
        assert_eq!(verb, "USER");
        assert_eq!(args, "alice");
    }

    #[test]
    fn split_command_no_args() {
        let (verb, args) = split_command(b"PASV").unwrap();
        assert_eq!(verb, "PASV");
        assert_eq!(args, "");
    }

    #[test]
    fn split_command_multiple_args() {
        let (verb, args) = split_command(b"PORT 192,168,1,1,4,5").unwrap();
        assert_eq!(verb, "PORT");
        assert_eq!(args, "192,168,1,1,4,5");
    }

    #[test]
    fn split_reply_final_line() {
        let (code, text, is_final) = split_reply(b"230 Login successful.").unwrap();
        assert_eq!(code, 230);
        assert_eq!(text, "Login successful.");
        assert!(is_final);
    }

    #[test]
    fn split_reply_intermediate_line() {
        let (code, text, is_final) = split_reply(b"220-banner part 1").unwrap();
        assert_eq!(code, 220);
        assert_eq!(text, "banner part 1");
        assert!(!is_final);
    }

    #[test]
    fn split_reply_rejects_too_short() {
        assert!(split_reply(b"230").is_none());
    }

    #[test]
    fn split_reply_rejects_non_numeric() {
        assert!(split_reply(b"ABC text").is_none());
    }
}

//! SSDP wire parser. UPnP Device Architecture 2.0 §1.2.

use super::types::{SsdpKind, SsdpMessage};

/// Maximum line length the header walker is willing to scan
/// before bailing — defense against malformed input.
const MAX_LINE_LEN: usize = 4096;
/// Maximum header count the walker keeps; real SSDP datagrams
/// carry well under 20.
const MAX_HEADERS: usize = 32;

/// Failure mode for [`parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// No `\r\n` line terminator, an over-long request line,
    /// or a non-UTF-8 request line.
    Malformed,
    /// The request line didn't match any of the three known
    /// SSDP shapes (`NOTIFY * HTTP/1.1`, `M-SEARCH * HTTP/1.1`,
    /// `HTTP/1.1 200 OK`).
    NotSsdp,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed => f.write_str("malformed SSDP request line"),
            Self::NotSsdp => f.write_str("not an SSDP request line"),
        }
    }
}

impl std::error::Error for ParseError {}

impl From<ParseError> for crate::Error {
    fn from(e: ParseError) -> Self {
        use crate::error::{ErrorCode, Module};
        let code = match &e {
            ParseError::Malformed | ParseError::NotSsdp => ErrorCode::Parse,
        };
        crate::Error::with_code(Module::Ssdp, code, e.to_string())
    }
}

/// Parse a UDP/1900 payload as an SSDP message.
///
/// Returns `Err` when:
/// - No `\r\n` line terminator separates request-line from
///   headers, the request line is over-long, or it isn't
///   UTF-8 ([`ParseError::Malformed`]).
/// - The payload doesn't start with one of the three known
///   request-line shapes (`NOTIFY * HTTP/1.1`,
///   `M-SEARCH * HTTP/1.1`, `HTTP/1.1 200 OK`)
///   ([`ParseError::NotSsdp`]).
///
/// Header malformations don't fail the parse — the offending
/// header is skipped.
pub fn parse(payload: &[u8]) -> Result<SsdpMessage, ParseError> {
    // Find the end of the request line.
    let crlf = find_crlf(payload, 0).ok_or(ParseError::Malformed)?;
    if crlf > MAX_LINE_LEN {
        return Err(ParseError::Malformed);
    }
    let request_line = std::str::from_utf8(&payload[..crlf]).map_err(|_| ParseError::Malformed)?;
    let kind = classify_request_line(request_line).ok_or(ParseError::NotSsdp)?;

    let mut msg = SsdpMessage {
        kind,
        host: None,
        nt: None,
        nts: None,
        st: None,
        usn: None,
        location: None,
        server: None,
        cache_control_max_age: None,
        user_agent: None,
    };

    let mut cursor = crlf + 2;
    for _ in 0..MAX_HEADERS {
        if cursor >= payload.len() {
            break;
        }
        let Some(eol) = find_crlf(payload, cursor) else {
            break;
        };
        if eol == cursor {
            // Empty line — end of headers per RFC 7230.
            break;
        }
        if eol - cursor > MAX_LINE_LEN {
            // Suspiciously long header line; abandon the rest
            // of the walk.
            break;
        }
        let line = &payload[cursor..eol];
        cursor = eol + 2;
        if let Some((name, value)) = split_header(line) {
            apply_header(&mut msg, &name, value);
        }
    }

    Ok(msg)
}

/// Find the next `\r\n` at-or-after `from` in `buf`. Returns
/// the index of the `\r`. `None` if no CRLF.
fn find_crlf(buf: &[u8], from: usize) -> Option<usize> {
    if from >= buf.len() {
        return None;
    }
    buf[from..]
        .windows(2)
        .position(|w| w == b"\r\n")
        .map(|p| p + from)
}

/// Classify the SSDP request line:
/// - `NOTIFY * HTTP/1.1` → Notify
/// - `M-SEARCH * HTTP/1.1` → MSearch
/// - `HTTP/1.1 200 OK` → Response
fn classify_request_line(line: &str) -> Option<SsdpKind> {
    // The match prefixes are case-sensitive per UPnP DA §1.1.2,
    // but real-world implementations vary; tolerate ASCII case.
    let upper = line.to_ascii_uppercase();
    if upper.starts_with("NOTIFY ") {
        Some(SsdpKind::Notify)
    } else if upper.starts_with("M-SEARCH ") {
        Some(SsdpKind::MSearch)
    } else if upper.starts_with("HTTP/1.1 200") || upper.starts_with("HTTP/1.0 200") {
        Some(SsdpKind::Response)
    } else {
        None
    }
}

/// Split a `Name: value` header line. Both sides are trimmed of
/// surrounding whitespace. Non-UTF-8 lines return `None`.
fn split_header(line: &[u8]) -> Option<(String, &str)> {
    let colon = line.iter().position(|&b| b == b':')?;
    let name = std::str::from_utf8(&line[..colon]).ok()?;
    let value_raw = &line[colon + 1..];
    let value = std::str::from_utf8(value_raw).ok()?.trim();
    Some((name.trim().to_ascii_uppercase(), value))
}

fn apply_header(msg: &mut SsdpMessage, name: &str, value: &str) {
    let slot = match name {
        "HOST" => &mut msg.host,
        "NT" => &mut msg.nt,
        "NTS" => &mut msg.nts,
        "ST" => &mut msg.st,
        "USN" => &mut msg.usn,
        "LOCATION" => &mut msg.location,
        "SERVER" => &mut msg.server,
        "USER-AGENT" => &mut msg.user_agent,
        "CACHE-CONTROL" => {
            // Format: `max-age=NNN` (UPnP DA §1.2.2). Tolerate
            // ASCII-case variants on the directive name.
            for token in value.split(',') {
                let token = token.trim();
                let rest = token
                    .strip_prefix("max-age=")
                    .or_else(|| token.strip_prefix("MAX-AGE="));
                if let Some(rest) = rest
                    && let Ok(n) = rest.trim().parse::<u32>()
                {
                    msg.cache_control_max_age = Some(n);
                }
            }
            return;
        }
        _ => return,
    };
    if slot.is_none() {
        *slot = Some(value.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_notify_alive() {
        let payload = concat!(
            "NOTIFY * HTTP/1.1\r\n",
            "HOST: 239.255.255.250:1900\r\n",
            "CACHE-CONTROL: max-age=1800\r\n",
            "LOCATION: http://192.168.1.10:80/desc.xml\r\n",
            "NT: upnp:rootdevice\r\n",
            "NTS: ssdp:alive\r\n",
            "SERVER: Linux/4.19 UPnP/1.0 IGD/1.1\r\n",
            "USN: uuid:550e8400-e29b-41d4-a716-446655440000::upnp:rootdevice\r\n",
            "\r\n",
        );
        let m = parse(payload.as_bytes()).unwrap();
        assert_eq!(m.kind, SsdpKind::Notify);
        assert_eq!(m.host.as_deref(), Some("239.255.255.250:1900"));
        assert_eq!(m.cache_control_max_age, Some(1800));
        assert_eq!(
            m.location.as_deref(),
            Some("http://192.168.1.10:80/desc.xml")
        );
        assert_eq!(m.nt.as_deref(), Some("upnp:rootdevice"));
        assert_eq!(m.nts.as_deref(), Some("ssdp:alive"));
        assert_eq!(m.server.as_deref(), Some("Linux/4.19 UPnP/1.0 IGD/1.1"));
        assert_eq!(
            m.usn.as_deref(),
            Some("uuid:550e8400-e29b-41d4-a716-446655440000::upnp:rootdevice")
        );
        assert!(m.is_alive());
    }

    #[test]
    fn parses_notify_byebye() {
        let payload = concat!(
            "NOTIFY * HTTP/1.1\r\n",
            "HOST: 239.255.255.250:1900\r\n",
            "NT: upnp:rootdevice\r\n",
            "NTS: ssdp:byebye\r\n",
            "USN: uuid:device-uuid::upnp:rootdevice\r\n",
            "\r\n",
        );
        let m = parse(payload.as_bytes()).unwrap();
        assert!(m.is_byebye());
        assert!(!m.is_alive());
    }

    #[test]
    fn parses_m_search() {
        let payload = concat!(
            "M-SEARCH * HTTP/1.1\r\n",
            "HOST: 239.255.255.250:1900\r\n",
            "MAN: \"ssdp:discover\"\r\n",
            "MX: 3\r\n",
            "ST: ssdp:all\r\n",
            "USER-AGENT: Roku/9.4.0 UPnP/1.0\r\n",
            "\r\n",
        );
        let m = parse(payload.as_bytes()).unwrap();
        assert_eq!(m.kind, SsdpKind::MSearch);
        assert_eq!(m.st.as_deref(), Some("ssdp:all"));
        assert_eq!(m.user_agent.as_deref(), Some("Roku/9.4.0 UPnP/1.0"));
    }

    #[test]
    fn parses_search_response() {
        let payload = concat!(
            "HTTP/1.1 200 OK\r\n",
            "CACHE-CONTROL: max-age=120\r\n",
            "LOCATION: http://10.0.0.50:1900/igd.xml\r\n",
            "SERVER: AsusWRT/3.0.0 UPnP/1.0 MiniUPnPd/1.9\r\n",
            "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n",
            "USN: uuid:abc-123::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n",
            "\r\n",
        );
        let m = parse(payload.as_bytes()).unwrap();
        assert_eq!(m.kind, SsdpKind::Response);
        assert_eq!(m.cache_control_max_age, Some(120));
        assert_eq!(
            m.server.as_deref(),
            Some("AsusWRT/3.0.0 UPnP/1.0 MiniUPnPd/1.9")
        );
        assert_eq!(
            m.st.as_deref(),
            Some("urn:schemas-upnp-org:device:InternetGatewayDevice:1")
        );
    }

    #[test]
    fn case_insensitive_headers() {
        let payload = concat!(
            "NOTIFY * HTTP/1.1\r\n",
            "host: 239.255.255.250:1900\r\n",
            "Cache-Control: max-age=900\r\n",
            "NtS: ssdp:alive\r\n",
            "Nt: upnp:rootdevice\r\n",
            "\r\n",
        );
        let m = parse(payload.as_bytes()).unwrap();
        assert_eq!(m.host.as_deref(), Some("239.255.255.250:1900"));
        assert_eq!(m.cache_control_max_age, Some(900));
        assert!(m.is_alive());
    }

    #[test]
    fn rejects_non_ssdp_payload() {
        assert!(parse(b"GET / HTTP/1.1\r\n\r\n").is_err());
        assert!(parse(b"random garbage no CRLF").is_err());
        assert!(parse(b"").is_err());
    }

    #[test]
    fn truncated_header_block_returns_partial_parse() {
        // Request line + one good header, then truncated.
        let payload = concat!(
            "NOTIFY * HTTP/1.1\r\n",
            "HOST: 239.255.255.250:1900\r\n",
            "NTS:",
        );
        let m = parse(payload.as_bytes()).unwrap();
        assert_eq!(m.host.as_deref(), Some("239.255.255.250:1900"));
        assert!(m.nts.is_none());
    }

    #[test]
    fn malformed_header_skipped() {
        let payload = concat!(
            "NOTIFY * HTTP/1.1\r\n",
            "HOST: 239.255.255.250:1900\r\n",
            "no_colon_here_so_invalid\r\n",
            "NTS: ssdp:alive\r\n",
            "\r\n",
        );
        let m = parse(payload.as_bytes()).unwrap();
        assert_eq!(m.host.as_deref(), Some("239.255.255.250:1900"));
        assert!(m.is_alive());
    }

    #[test]
    fn header_walker_caps_iteration() {
        // Many bogus headers — walker stops at MAX_HEADERS=32.
        let mut payload = String::from("NOTIFY * HTTP/1.1\r\n");
        for i in 0..200 {
            payload.push_str(&format!("X-Filler-{i}: value\r\n"));
        }
        payload.push_str("NTS: ssdp:alive\r\n\r\n");
        // We don't care about the NTS in this case — what we
        // care is no panic / unbounded loop.
        let m = parse(payload.as_bytes());
        assert!(m.is_ok());
    }

    #[test]
    fn cache_control_other_directives_dont_break() {
        let payload = concat!(
            "NOTIFY * HTTP/1.1\r\n",
            "HOST: 239.255.255.250:1900\r\n",
            "CACHE-CONTROL: no-cache, max-age=42, private\r\n",
            "NTS: ssdp:alive\r\n",
            "\r\n",
        );
        let m = parse(payload.as_bytes()).unwrap();
        assert_eq!(m.cache_control_max_age, Some(42));
    }
}

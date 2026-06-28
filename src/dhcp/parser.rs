//! DHCP wire parser — RFC 2131 BOOTP header + RFC 2132 options.
//!
//! Issue #11 (0.18).

use std::net::Ipv4Addr;

use super::types::{DhcpMessage, DhcpMessageType, DhcpOp};
use crate::MacAddr;

/// BOOTP fixed-header size (everything before the options).
const BOOTP_HEADER_LEN: usize = 236;
/// DHCP magic cookie (RFC 2131 §3) — first 4 bytes of the
/// options block.
const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

/// HType / HLen pair for IEEE 802.3 Ethernet — only combination
/// for which `chaddr` decodes to a `MacAddr`.
const HTYPE_ETHERNET: u8 = 1;
const HLEN_ETHERNET: u8 = 6;

// Option codes we surface as typed fields. Any others are
// walked over and ignored.
const OPT_PAD: u8 = 0;
const OPT_HOSTNAME: u8 = 12;
const OPT_REQUESTED_IP: u8 = 50;
const OPT_LEASE_TIME: u8 = 51;
const OPT_MSG_TYPE: u8 = 53;
const OPT_SERVER_ID: u8 = 54;
const OPT_PARAM_REQUEST_LIST: u8 = 55;
const OPT_VENDOR_CLASS: u8 = 60;
const OPT_CLIENT_FQDN: u8 = 81;
const OPT_END: u8 = 255;

/// Cap on the number of options walked — defense against
/// adversarial inputs that could otherwise loop the walker.
/// RFC 2132 has fewer than 256 defined codes; in practice
/// well under 30 options appear in real DHCP traffic.
const MAX_OPTIONS: usize = 256;

/// Failure mode for [`parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// Payload shorter than the 236-byte BOOTP fixed header.
    Truncated { need: usize, have: usize },
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated { need, have } => {
                write!(f, "truncated DHCP header: need {need}, have {have}")
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
        crate::Error::with_code(Module::Dhcp, code, e.to_string())
    }
}

/// Parse a UDP/67-68 payload as a DHCP message.
///
/// Returns `Err` when the payload is shorter than the BOOTP
/// fixed header. A missing DHCP magic cookie or a truncated
/// option block is *not* a failure — the BOOTP header alone
/// is already useful, so those cases return `Ok` with the
/// header-only message.
///
/// Per-option malformations (string options containing non-
/// UTF-8 bytes, length fields disagreeing with option-spec
/// minima, etc.) skip the offending option rather than
/// failing the whole parse.
pub fn parse(payload: &[u8]) -> Result<DhcpMessage, ParseError> {
    if payload.len() < BOOTP_HEADER_LEN {
        return Err(ParseError::Truncated {
            need: BOOTP_HEADER_LEN,
            have: payload.len(),
        });
    }
    let op = DhcpOp::from(payload[0]);
    let htype = payload[1];
    let hlen = payload[2];
    // hops = payload[3] — ignored.
    let xid = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    // secs = payload[8..10], flags = payload[10..12] — ignored.
    let ciaddr = ipv4(&payload[12..16]);
    let yiaddr = ipv4(&payload[16..20]);
    let siaddr = ipv4(&payload[20..24]);
    let giaddr = ipv4(&payload[24..28]);
    // chaddr is 16 bytes at payload[28..44]; only valid as a
    // MAC when htype/hlen identify Ethernet.
    let client_mac = if htype == HTYPE_ETHERNET && hlen == HLEN_ETHERNET {
        let mut mac = [0u8; 6];
        mac.copy_from_slice(&payload[28..34]);
        Some(MacAddr(mac))
    } else {
        None
    };
    // sname (64B) at payload[44..108], file (128B) at payload[108..236] — skipped.

    let mut msg = DhcpMessage {
        op,
        msg_type: None,
        xid,
        client_mac,
        ciaddr,
        yiaddr,
        siaddr,
        giaddr,
        ..DhcpMessage::default()
    };

    // Options follow at offset 236, prefixed by the DHCP magic
    // cookie. A payload that ends exactly at the BOOTP header is
    // legal BOOTP (no DHCP options) — return the header-only
    // message.
    if payload.len() < BOOTP_HEADER_LEN + 4 {
        return Ok(msg);
    }
    if payload[BOOTP_HEADER_LEN..BOOTP_HEADER_LEN + 4] != MAGIC_COOKIE {
        // Without the cookie this isn't DHCP. Some BOOTP variants
        // ship without it, but the option block isn't safe to walk.
        return Ok(msg);
    }

    walk_options(&payload[BOOTP_HEADER_LEN + 4..], &mut msg);
    Ok(msg)
}

fn ipv4(b: &[u8]) -> Ipv4Addr {
    Ipv4Addr::new(b[0], b[1], b[2], b[3])
}

fn walk_options(mut opts: &[u8], msg: &mut DhcpMessage) {
    for _ in 0..MAX_OPTIONS {
        if opts.is_empty() {
            return;
        }
        let code = opts[0];
        opts = &opts[1..];
        match code {
            OPT_PAD => continue,
            OPT_END => return,
            _ => {}
        }
        if opts.is_empty() {
            // Length byte missing — truncated.
            return;
        }
        let len = opts[0] as usize;
        opts = &opts[1..];
        if opts.len() < len {
            // Value truncated — abandon the walk; what we've
            // already populated stays.
            return;
        }
        let (value, rest) = opts.split_at(len);
        opts = rest;

        match code {
            OPT_MSG_TYPE if value.len() == 1 => {
                msg.msg_type = Some(DhcpMessageType::from(value[0]));
            }
            OPT_HOSTNAME => {
                if let Ok(s) = std::str::from_utf8(value) {
                    msg.hostname = Some(s.to_string());
                }
            }
            OPT_REQUESTED_IP if value.len() == 4 => {
                msg.requested_ip = Some(ipv4(value));
            }
            OPT_LEASE_TIME if value.len() == 4 => {
                msg.lease_time = Some(u32::from_be_bytes([value[0], value[1], value[2], value[3]]));
            }
            OPT_SERVER_ID if value.len() == 4 => {
                msg.server_id = Some(ipv4(value));
            }
            OPT_PARAM_REQUEST_LIST => {
                msg.param_request_list = value.to_vec();
            }
            OPT_VENDOR_CLASS => {
                if let Ok(s) = std::str::from_utf8(value) {
                    msg.vendor_class = Some(s.to_string());
                }
            }
            OPT_CLIENT_FQDN => {
                // RFC 4702: 3 flag/RCode bytes + FQDN. We surface
                // only the FQDN part; flags ignored.
                if value.len() > 3
                    && let Ok(s) = std::str::from_utf8(&value[3..])
                {
                    msg.client_fqdn = Some(s.to_string());
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build the BOOTP fixed header for a DHCPDISCOVER from a
    /// client at `mac`, with the given xid. Returns 236 bytes
    /// of header, no options.
    fn bootp_header(op: u8, mac: [u8; 6], xid: u32) -> Vec<u8> {
        let mut b = vec![0u8; BOOTP_HEADER_LEN];
        b[0] = op;
        b[1] = HTYPE_ETHERNET;
        b[2] = HLEN_ETHERNET;
        b[3] = 0; // hops
        b[4..8].copy_from_slice(&xid.to_be_bytes());
        // secs / flags / ci / yi / si / gi addr — left as zeros.
        b[28..34].copy_from_slice(&mac);
        b
    }

    fn opt(code: u8, value: &[u8]) -> Vec<u8> {
        let mut o = vec![code, value.len() as u8];
        o.extend_from_slice(value);
        o
    }

    #[test]
    fn parses_minimal_bootp_header() {
        let mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let p = bootp_header(1, mac, 0xdeadbeef);
        let msg = parse(&p).unwrap();
        assert_eq!(msg.op, DhcpOp::BootRequest);
        assert_eq!(msg.xid, 0xdeadbeef);
        assert_eq!(msg.client_mac, Some(MacAddr(mac)));
        assert_eq!(msg.msg_type, None);
        assert!(msg.param_request_list.is_empty());
    }

    #[test]
    fn parses_dhcpdiscover_with_full_fingerprint() {
        let mac = [0xaa; 6];
        let mut p = bootp_header(1, mac, 1);
        // Magic cookie.
        p.extend_from_slice(&MAGIC_COOKIE);
        // opt 53 = DISCOVER
        p.extend(opt(53, &[1]));
        // opt 55 = Parameter Request List
        p.extend(opt(55, &[1, 3, 6, 15, 33, 253]));
        // opt 60 = Vendor Class
        p.extend(opt(60, b"MSFT 5.0"));
        // opt 12 = hostname
        p.extend(opt(12, b"workstation01"));
        p.push(OPT_END);

        let msg = parse(&p).unwrap();
        assert_eq!(msg.msg_type, Some(DhcpMessageType::Discover));
        assert_eq!(msg.param_request_list, vec![1, 3, 6, 15, 33, 253]);
        assert_eq!(msg.vendor_class.as_deref(), Some("MSFT 5.0"));
        assert_eq!(msg.hostname.as_deref(), Some("workstation01"));
        assert_eq!(
            msg.fingerprint().as_deref(),
            Some("1,3,6,15,33,253|MSFT 5.0")
        );
    }

    #[test]
    fn parses_dhcpoffer_with_lease_and_server_id() {
        let mac = [0xbb; 6];
        let mut p = bootp_header(2, mac, 42);
        // yiaddr — server's assigned IP.
        p[16..20].copy_from_slice(&[192, 168, 1, 100]);
        p.extend_from_slice(&MAGIC_COOKIE);
        p.extend(opt(53, &[2])); // OFFER
        p.extend(opt(51, &86400u32.to_be_bytes())); // 24h lease
        p.extend(opt(54, &[192, 168, 1, 1])); // server identifier
        p.push(OPT_END);

        let msg = parse(&p).unwrap();
        assert_eq!(msg.op, DhcpOp::BootReply);
        assert_eq!(msg.msg_type, Some(DhcpMessageType::Offer));
        assert_eq!(msg.yiaddr, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(msg.lease_time, Some(86400));
        assert_eq!(msg.server_id, Some(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn parses_dhcprequest_with_requested_ip() {
        let mut p = bootp_header(1, [0xcc; 6], 99);
        p.extend_from_slice(&MAGIC_COOKIE);
        p.extend(opt(53, &[3])); // REQUEST
        p.extend(opt(50, &[10, 0, 0, 50])); // requested IP
        p.push(OPT_END);

        let msg = parse(&p).unwrap();
        assert_eq!(msg.msg_type, Some(DhcpMessageType::Request));
        assert_eq!(msg.requested_ip, Some(Ipv4Addr::new(10, 0, 0, 50)));
    }

    #[test]
    fn rejects_truncated_header() {
        assert!(parse(&[]).is_err());
        assert!(parse(&[0; 100]).is_err());
        assert!(parse(&[0; BOOTP_HEADER_LEN - 1]).is_err());
    }

    #[test]
    fn accepts_header_with_no_options() {
        // A pure BOOTP header (236 bytes, no cookie) is parsed —
        // we just get header fields, no DHCP options.
        let p = bootp_header(1, [0; 6], 0);
        let msg = parse(&p).unwrap();
        assert_eq!(msg.msg_type, None);
    }

    #[test]
    fn missing_magic_cookie_skips_options() {
        let mut p = bootp_header(1, [0; 6], 0);
        // Wrong cookie — options block isn't walked.
        p.extend_from_slice(&[0; 4]);
        p.extend(opt(53, &[1]));
        let msg = parse(&p).unwrap();
        assert_eq!(msg.msg_type, None);
    }

    #[test]
    fn non_ethernet_chaddr_returns_none() {
        let mut p = bootp_header(1, [0xaa; 6], 0);
        // Flip htype to a non-Ethernet value.
        p[1] = 6; // IEEE 802 networks
        p[2] = 6;
        let msg = parse(&p).unwrap();
        assert_eq!(msg.client_mac, None);
    }

    #[test]
    fn pad_options_are_skipped() {
        let mut p = bootp_header(1, [0; 6], 0);
        p.extend_from_slice(&MAGIC_COOKIE);
        p.extend_from_slice(&[OPT_PAD, OPT_PAD, OPT_PAD]);
        p.extend(opt(53, &[1]));
        p.push(OPT_END);

        let msg = parse(&p).unwrap();
        assert_eq!(msg.msg_type, Some(DhcpMessageType::Discover));
    }

    #[test]
    fn truncated_option_value_stops_walk_gracefully() {
        let mut p = bootp_header(1, [0; 6], 0);
        p.extend_from_slice(&MAGIC_COOKIE);
        // Option 12, length=200 but no value bytes — truncated.
        p.push(12);
        p.push(200);
        let msg = parse(&p).unwrap();
        // Earlier fields populated; later (truncated) skipped.
        assert!(msg.hostname.is_none());
    }

    #[test]
    fn end_option_stops_walk() {
        let mut p = bootp_header(1, [0; 6], 0);
        p.extend_from_slice(&MAGIC_COOKIE);
        p.push(OPT_END);
        // Anything past END is ignored — even if it looks valid.
        p.extend(opt(53, &[1]));
        let msg = parse(&p).unwrap();
        assert_eq!(msg.msg_type, None);
    }

    #[test]
    fn non_utf8_string_option_is_skipped() {
        let mut p = bootp_header(1, [0; 6], 0);
        p.extend_from_slice(&MAGIC_COOKIE);
        // Hostname with invalid UTF-8.
        p.extend(opt(12, &[0xff, 0xfe, 0xfd]));
        p.push(OPT_END);
        let msg = parse(&p).unwrap();
        assert!(msg.hostname.is_none());
    }

    #[test]
    fn client_fqdn_strips_flag_bytes() {
        let mut p = bootp_header(1, [0; 6], 0);
        p.extend_from_slice(&MAGIC_COOKIE);
        // RFC 4702: flags (1) + rcode1 (1) + rcode2 (1) + FQDN.
        let mut fqdn_val = vec![0x00, 0x00, 0x00];
        fqdn_val.extend_from_slice(b"host.example.com");
        p.extend(opt(81, &fqdn_val));
        p.push(OPT_END);

        let msg = parse(&p).unwrap();
        assert_eq!(msg.client_fqdn.as_deref(), Some("host.example.com"));
    }
}

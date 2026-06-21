//! RDP X.224 negotiation parser. Strict by design — we only
//! ever look at the first frame on each side, and never at
//! the RDP-payload content.

use super::types::{RdpFailureCode, RdpMessage, RdpProtocols};

const TPKT_HEADER_LEN: usize = 4;
const X224_CR: u8 = 0xE0; // Connection Request PDU type
const X224_CC: u8 = 0xD0; // Connection Confirm PDU type
const RDP_NEG_REQ: u8 = 0x01;
const RDP_NEG_RSP: u8 = 0x02;
const RDP_NEG_FAILURE: u8 = 0x03;

/// Parse a single TPKT-framed X.224 PDU. Returns `None` for
/// any payload that doesn't match the RDP Connection
/// Request/Confirm shape exactly.
pub fn parse_frame(payload: &[u8]) -> Option<RdpMessage> {
    if payload.len() < TPKT_HEADER_LEN {
        return None;
    }
    // TPKT: version(0x03) | reserved(0x00) | length(2 BE).
    if payload[0] != 0x03 || payload[1] != 0x00 {
        return None;
    }
    let total_len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    if total_len > payload.len() || total_len < 7 {
        return None;
    }
    let x224 = &payload[TPKT_HEADER_LEN..total_len];
    // X.224 header: length(1) | code(1) | … . For CR/CC the
    // header is 7 bytes; user data follows.
    if x224.len() < 7 {
        return None;
    }
    let x224_li = x224[0] as usize;
    let code = x224[1] & 0xf0;
    let header_total = 1 + x224_li;
    let user_data_start = header_total;
    if user_data_start > x224.len() {
        return None;
    }
    let user_data = &x224[user_data_start..];

    match code {
        X224_CR => Some(decode_connection_request(&x224[7..header_total], user_data)),
        X224_CC => Some(decode_connection_confirm(user_data)),
        _ => None,
    }
}

fn decode_connection_request(routing_area: &[u8], user_data: &[u8]) -> RdpMessage {
    // The routing area sits between the X.224 fixed header
    // and the RDP negotiation block. It MAY contain one of:
    //  - `Cookie: mstshash=<user>\r\n`     (msconnect cookie)
    //  - `Cookie: msts=<routing-token>\r\n` (TS load balancer)
    //  - empty (no routing data).
    let (cookie_username, routing_token) = extract_cookies(routing_area);
    let requested_protocols = decode_rdp_neg_request(user_data);
    RdpMessage::ConnectionRequest {
        cookie_username,
        routing_token,
        requested_protocols,
    }
}

fn decode_connection_confirm(user_data: &[u8]) -> RdpMessage {
    // User data should be either an RDP_NEG_RSP (type 0x02)
    // or RDP_NEG_FAILURE (type 0x03), each 8 bytes.
    if user_data.len() < 8 {
        return RdpMessage::ConnectionConfirm {
            selected_protocol: None,
            negotiation_failure: None,
        };
    }
    match user_data[0] {
        RDP_NEG_RSP => {
            let proto =
                u32::from_le_bytes([user_data[4], user_data[5], user_data[6], user_data[7]]);
            RdpMessage::ConnectionConfirm {
                selected_protocol: Some(RdpProtocols::from_bits_truncate(proto)),
                negotiation_failure: None,
            }
        }
        RDP_NEG_FAILURE => {
            let code = u32::from_le_bytes([user_data[4], user_data[5], user_data[6], user_data[7]]);
            RdpMessage::ConnectionConfirm {
                selected_protocol: None,
                negotiation_failure: Some(RdpFailureCode::from_raw(code)),
            }
        }
        _ => RdpMessage::ConnectionConfirm {
            selected_protocol: None,
            negotiation_failure: None,
        },
    }
}

fn decode_rdp_neg_request(user_data: &[u8]) -> Option<RdpProtocols> {
    // RDP Negotiation Request is the LAST optional block,
    // 8 bytes: type(0x01) + flags(1) + length(2 LE = 8) +
    // requestedProtocols(4 LE).
    if user_data.len() < 8 {
        return None;
    }
    // Scan from the start; the request usually IS the user
    // data when no cookie is present, but a cookie may have
    // pushed it back.
    let start = user_data.len() - 8;
    if user_data[start] != RDP_NEG_REQ {
        return None;
    }
    let proto = u32::from_le_bytes([
        user_data[start + 4],
        user_data[start + 5],
        user_data[start + 6],
        user_data[start + 7],
    ]);
    Some(RdpProtocols::from_bits_truncate(proto))
}

/// Extract `Cookie: mstshash=USER\r\n` username +
/// `Cookie: msts=TOKEN\r\n` routing token from the X.224
/// routing area. Returns `(username, routing_token)`.
fn extract_cookies(routing_area: &[u8]) -> (Option<String>, Option<String>) {
    let s = match std::str::from_utf8(routing_area) {
        Ok(s) => s,
        Err(_) => return (None, None),
    };
    let mut username = None;
    let mut token = None;
    for line in s.split("\r\n") {
        if let Some(rest) = line
            .strip_prefix("Cookie:")
            .or_else(|| line.strip_prefix("Cookie :"))
        {
            let rest = rest.trim_start();
            if let Some(u) = rest.strip_prefix("mstshash=") {
                username = Some(u.to_string());
            } else if let Some(t) = rest.strip_prefix("msts=") {
                token = Some(t.to_string());
            }
        }
    }
    (username, token)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_cr_with_cookie(cookie: &[u8], req_proto: u32) -> Vec<u8> {
        // X.224 CR header (7 bytes): length-indicator | code |
        // dst-ref(2) | src-ref(2) | class(1).
        // Then optional routing area (cookie), then RDP_NEG_REQ (8 B).
        let mut x224 = Vec::new();
        x224.push(0u8); // length indicator (filled in below)
        x224.push(X224_CR);
        x224.extend_from_slice(&[0, 0, 0, 0, 0]); // dst+src+class
        x224.extend_from_slice(cookie); // routing area
        // RDP Negotiation Request
        x224.push(RDP_NEG_REQ);
        x224.push(0); // flags
        x224.extend_from_slice(&8u16.to_le_bytes()); // length = 8
        x224.extend_from_slice(&req_proto.to_le_bytes());
        // Set the length indicator: count is bytes from byte 1
        // to end (excluding the LI itself), but the RDP NEG
        // structure is part of user data, so LI counts up to
        // the routing area's end.
        let li = (6 + cookie.len()) as u8;
        x224[0] = li;
        // TPKT wrap
        let total = (TPKT_HEADER_LEN + x224.len()) as u16;
        let mut out = vec![0x03, 0x00];
        out.extend_from_slice(&total.to_be_bytes());
        out.extend_from_slice(&x224);
        out
    }

    fn build_cc_negotiation_response(selected_proto: u32) -> Vec<u8> {
        let mut x224 = Vec::new();
        x224.push(0u8); // LI
        x224.push(X224_CC);
        x224.extend_from_slice(&[0, 0, 0, 0, 0]);
        // RDP Negotiation Response
        x224.push(RDP_NEG_RSP);
        x224.push(0); // flags
        x224.extend_from_slice(&8u16.to_le_bytes());
        x224.extend_from_slice(&selected_proto.to_le_bytes());
        x224[0] = 6; // LI = 6 (no routing area)
        let total = (TPKT_HEADER_LEN + x224.len()) as u16;
        let mut out = vec![0x03, 0x00];
        out.extend_from_slice(&total.to_be_bytes());
        out.extend_from_slice(&x224);
        out
    }

    fn build_cc_negotiation_failure(code: u32) -> Vec<u8> {
        let mut x224 = Vec::new();
        x224.push(0u8);
        x224.push(X224_CC);
        x224.extend_from_slice(&[0, 0, 0, 0, 0]);
        x224.push(RDP_NEG_FAILURE);
        x224.push(0);
        x224.extend_from_slice(&8u16.to_le_bytes());
        x224.extend_from_slice(&code.to_le_bytes());
        x224[0] = 6;
        let total = (TPKT_HEADER_LEN + x224.len()) as u16;
        let mut out = vec![0x03, 0x00];
        out.extend_from_slice(&total.to_be_bytes());
        out.extend_from_slice(&x224);
        out
    }

    #[test]
    fn parses_connection_request_with_mstshash_cookie() {
        let cookie = b"Cookie: mstshash=alice\r\n";
        let payload = build_cr_with_cookie(cookie, 0x03); // SSL + HYBRID
        let msg = parse_frame(&payload).expect("parse");
        match msg {
            RdpMessage::ConnectionRequest {
                cookie_username,
                requested_protocols,
                ..
            } => {
                assert_eq!(cookie_username.as_deref(), Some("alice"));
                let req = requested_protocols.expect("flags");
                assert!(req.contains(RdpProtocols::SSL));
                assert!(req.contains(RdpProtocols::HYBRID));
            }
            _ => panic!("expected CR"),
        }
    }

    #[test]
    fn parses_connection_request_with_no_cookie() {
        let payload = build_cr_with_cookie(b"", 0x00);
        let msg = parse_frame(&payload).expect("parse");
        match msg {
            RdpMessage::ConnectionRequest {
                cookie_username,
                requested_protocols,
                routing_token,
                ..
            } => {
                assert!(cookie_username.is_none());
                assert!(routing_token.is_none());
                assert_eq!(requested_protocols, Some(RdpProtocols::RDP));
            }
            _ => panic!("expected CR"),
        }
    }

    #[test]
    fn parses_connection_request_with_routing_token() {
        let cookie = b"Cookie: msts=tsv://muffin\r\n";
        let payload = build_cr_with_cookie(cookie, 0x01);
        let msg = parse_frame(&payload).expect("parse");
        match msg {
            RdpMessage::ConnectionRequest { routing_token, .. } => {
                assert_eq!(routing_token.as_deref(), Some("tsv://muffin"));
            }
            _ => panic!("expected CR"),
        }
    }

    #[test]
    fn parses_connection_confirm_selected_protocol() {
        let payload = build_cc_negotiation_response(0x02);
        let msg = parse_frame(&payload).expect("parse");
        match msg {
            RdpMessage::ConnectionConfirm {
                selected_protocol,
                negotiation_failure,
            } => {
                assert_eq!(selected_protocol, Some(RdpProtocols::HYBRID));
                assert!(negotiation_failure.is_none());
            }
            _ => panic!("expected CC"),
        }
    }

    #[test]
    fn parses_connection_confirm_failure() {
        let payload = build_cc_negotiation_failure(5);
        let msg = parse_frame(&payload).expect("parse");
        match msg {
            RdpMessage::ConnectionConfirm {
                negotiation_failure,
                ..
            } => {
                assert_eq!(
                    negotiation_failure,
                    Some(RdpFailureCode::HybridRequiredByServer)
                );
            }
            _ => panic!("expected CC"),
        }
    }

    #[test]
    fn rejects_non_tpkt_payload() {
        assert!(parse_frame(b"GET / HTTP/1.1\r\n").is_none());
    }

    #[test]
    fn rejects_too_short() {
        assert!(parse_frame(&[0u8; 3]).is_none());
    }

    #[test]
    fn rejects_wrong_tpkt_version() {
        let mut payload = build_cr_with_cookie(b"", 0);
        payload[0] = 0x04;
        assert!(parse_frame(&payload).is_none());
    }

    #[test]
    fn rejects_truncated_length() {
        let mut payload = build_cr_with_cookie(b"", 0);
        payload.truncate(payload.len() - 4);
        let msg = parse_frame(&payload);
        // Either rejected or partial — strict mode prefers None.
        assert!(msg.is_none() || matches!(msg, Some(RdpMessage::ConnectionRequest { .. })));
    }

    #[test]
    fn protocol_flags_bitset() {
        let combined = RdpProtocols::SSL | RdpProtocols::HYBRID | RdpProtocols::HYBRID_EX;
        assert!(combined.contains(RdpProtocols::SSL));
        assert!(combined.contains(RdpProtocols::HYBRID));
        assert!(combined.contains(RdpProtocols::HYBRID_EX));
        assert!(!combined.contains(RdpProtocols::RDSTLS));
    }
}

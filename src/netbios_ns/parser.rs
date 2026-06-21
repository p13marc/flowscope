//! NBNS wire-format parser. Returns `None` on any
//! malformed input — we never panic and never partial-emit.

use std::net::Ipv4Addr;

use smallvec::SmallVec;

use super::name::{decode_first_level, split_name_suffix};
use super::types::{NbnsMessage, NbnsOpcode};

/// Parse a single UDP/137 datagram. Returns `None` when the
/// payload is too short for the 12-byte header or the
/// question/answer encoding diverges from RFC 1002 §4.2.
pub fn parse(payload: &[u8]) -> Option<NbnsMessage> {
    if payload.len() < 12 {
        return None;
    }
    let transaction_id = u16::from_be_bytes([payload[0], payload[1]]);
    let flags = u16::from_be_bytes([payload[2], payload[3]]);
    // RFC 1002 §4.2.1.1: QR(1) | OPCODE(4) | NM_FLAGS(7) | RCODE(4).
    let is_response = (flags & 0x8000) != 0;
    let opcode_bits = ((flags >> 11) & 0x0f) as u8;
    let opcode = NbnsOpcode::from_bits(opcode_bits);
    let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
    let ancount = u16::from_be_bytes([payload[6], payload[7]]);

    let mut cursor = 12;
    let (queried_name, name_suffix) = if qdcount > 0 {
        let (decoded, advance) = decode_question(&payload[cursor..])?;
        cursor += advance;
        let (name, suffix) = split_name_suffix(&decoded);
        if name.is_empty() {
            (None, Some(suffix))
        } else {
            (Some(name), Some(suffix))
        }
    } else {
        (None, None)
    };

    let mut answer_addresses: SmallVec<[Ipv4Addr; 1]> = SmallVec::new();
    if ancount > 0
        && let Some(addrs) = parse_first_nb_answer(&payload[cursor..])
    {
        answer_addresses.extend(addrs);
    }

    Some(NbnsMessage {
        transaction_id,
        opcode,
        is_response,
        queried_name,
        name_suffix,
        answer_addresses,
    })
}

/// Decode the question section's NetBIOS name. The on-wire
/// layout is: a single length byte (`0x20` = 32) followed by
/// 32 first-level-encoded ASCII bytes, then a null byte
/// (label terminator), then 2 bytes QTYPE + 2 bytes QCLASS.
///
/// Returns `(decoded 16-byte raw name, bytes consumed)`.
fn decode_question(buf: &[u8]) -> Option<([u8; 16], usize)> {
    if buf.len() < 1 + 32 + 1 + 4 {
        return None;
    }
    let length = buf[0];
    if length != 32 {
        return None;
    }
    let encoded = &buf[1..33];
    let raw = decode_first_level(encoded)?;
    if buf[33] != 0x00 {
        // Compression pointers / multi-label names not
        // supported — NBNS uses the flat 32-byte form
        // exclusively in practice.
        return None;
    }
    Some((raw, 1 + 32 + 1 + 4))
}

/// Walk the first RR in the answer section. Returns the IPv4
/// addresses if the RR is type `NB` (0x0020), or `None`
/// otherwise.
fn parse_first_nb_answer(buf: &[u8]) -> Option<Vec<Ipv4Addr>> {
    // RR layout: NAME (encoded — usually a compression
    // pointer; we tolerate either the full 32-byte form or a
    // 2-byte 0xC0 pointer) | TYPE(2) | CLASS(2) | TTL(4) |
    // RDLENGTH(2) | RDATA. NB RDATA per RFC 1002 §4.2.16:
    // NB_FLAGS(2) | NB_ADDRESS(4) [+ more flag/addr pairs].
    let mut cursor = 0;
    if buf.first() == Some(&0xc0) {
        // Compression pointer (2 bytes total).
        cursor += 2;
    } else {
        // Full encoded name (34 bytes: length(1) + 32 + 0x00).
        if buf.len() < 34 {
            return None;
        }
        if buf[0] != 32 {
            return None;
        }
        cursor += 34;
    }
    if buf.len() < cursor + 10 {
        return None;
    }
    let rr_type = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]);
    cursor += 2;
    // CLASS (skip) + TTL (skip) = 6 bytes.
    cursor += 6;
    let rdlength = u16::from_be_bytes([buf[cursor], buf[cursor + 1]]) as usize;
    cursor += 2;
    if rr_type != 0x0020 {
        // Only NB records carry IPv4 addresses we can surface.
        return None;
    }
    if buf.len() < cursor + rdlength {
        return None;
    }
    let rdata = &buf[cursor..cursor + rdlength];
    // Walk 6-byte (NB_FLAGS + NB_ADDRESS) tuples.
    let mut addrs = Vec::new();
    let mut p = 0;
    while p + 6 <= rdata.len() {
        // Skip NB_FLAGS(2).
        let v4 = Ipv4Addr::new(rdata[p + 2], rdata[p + 3], rdata[p + 4], rdata[p + 5]);
        addrs.push(v4);
        p += 6;
    }
    if addrs.is_empty() { None } else { Some(addrs) }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a header (12 bytes) + question with the encoded
    /// `WORKSTATION` + workstation suffix.
    fn build_query(name: &str, suffix: u8, transaction_id: u16) -> Vec<u8> {
        let mut out = Vec::new();
        // Header: transaction_id, flags = 0x0110 (query, broadcast),
        // qdcount=1, ancount=0, nscount=0, arcount=0.
        out.extend_from_slice(&transaction_id.to_be_bytes());
        out.extend_from_slice(&0x0110u16.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes()); // qdcount
        out.extend_from_slice(&0u16.to_be_bytes()); // ancount
        out.extend_from_slice(&0u16.to_be_bytes()); // nscount
        out.extend_from_slice(&0u16.to_be_bytes()); // arcount
        // Question: length(1) + encoded(32) + null(1) + qtype(2) + qclass(2)
        out.push(32);
        out.extend_from_slice(&encode_name(name, suffix));
        out.push(0); // null terminator
        out.extend_from_slice(&0x0020u16.to_be_bytes()); // QTYPE = NB
        out.extend_from_slice(&0x0001u16.to_be_bytes()); // QCLASS = IN
        out
    }

    /// First-level encoding for a NetBIOS name string.
    /// Padded with spaces to 15 raw bytes + 1 suffix byte.
    fn encode_name(name: &str, suffix: u8) -> Vec<u8> {
        let mut raw = [b' '; 16];
        let bytes = name.as_bytes();
        let n = bytes.len().min(15);
        raw[..n].copy_from_slice(&bytes[..n]);
        raw[15] = suffix;
        let mut encoded = Vec::with_capacity(32);
        for b in raw.iter() {
            encoded.push(b'A' + (b >> 4));
            encoded.push(b'A' + (b & 0x0f));
        }
        encoded
    }

    #[test]
    fn parses_header_and_first_question() {
        let payload = build_query("WORKGROUP", 0x00, 0x1234);
        let msg = parse(&payload).expect("parse");
        assert_eq!(msg.transaction_id, 0x1234);
        assert_eq!(msg.opcode, NbnsOpcode::Query);
        assert!(!msg.is_response);
        assert_eq!(msg.queried_name.as_deref(), Some("WORKGROUP"));
        assert_eq!(msg.name_suffix, Some(0x00));
    }

    #[test]
    fn opcode_decodes_registration() {
        let mut payload = build_query("HOST", 0x00, 0);
        // OPCODE = 5 (Registration), at flags byte 2-3.
        // Flags = 0 | (5 << 11) = 0x2800.
        payload[2] = 0x28;
        payload[3] = 0x00;
        let msg = parse(&payload).expect("parse");
        assert_eq!(msg.opcode, NbnsOpcode::Registration);
    }

    #[test]
    fn qr_bit_sets_is_response() {
        let mut payload = build_query("X", 0x00, 0);
        // Set QR bit.
        payload[2] |= 0x80;
        let msg = parse(&payload).expect("parse");
        assert!(msg.is_response);
    }

    #[test]
    fn missing_question_yields_no_name() {
        let mut header = vec![0u8; 12];
        // qdcount stays 0.
        header[2] = 0x01;
        header[3] = 0x00;
        let msg = parse(&header).expect("header-only is valid");
        assert!(msg.queried_name.is_none());
        assert!(msg.name_suffix.is_none());
    }

    #[test]
    fn too_short_returns_none() {
        assert!(parse(&[0u8; 5]).is_none());
    }

    #[test]
    fn answer_section_carries_ipv4() {
        // Build a registration-response packet with one NB
        // record carrying 192.168.1.42.
        let mut payload = build_query("HOST", 0x00, 0x42);
        // Set QR + Registration opcode + 1 answer.
        payload[2] = 0xa8; // QR=1, OPCODE=5
        payload[6] = 0;
        payload[7] = 1; // ancount=1
        // Answer: name (compression pointer to qname),
        // type=NB, class=IN, TTL=300, rdlen=6, rdata = flags(2) + ipv4(4).
        payload.push(0xc0);
        payload.push(0x0c); // pointer to offset 12 (qname)
        payload.extend_from_slice(&0x0020u16.to_be_bytes()); // TYPE = NB
        payload.extend_from_slice(&0x0001u16.to_be_bytes()); // CLASS = IN
        payload.extend_from_slice(&300u32.to_be_bytes()); // TTL
        payload.extend_from_slice(&6u16.to_be_bytes()); // RDLENGTH
        payload.extend_from_slice(&[0u8, 0u8]); // NB_FLAGS
        payload.extend_from_slice(&[192, 168, 1, 42]); // NB_ADDRESS
        let msg = parse(&payload).expect("parse");
        assert_eq!(msg.answer_addresses.len(), 1);
        assert_eq!(msg.answer_addresses[0], Ipv4Addr::new(192, 168, 1, 42));
    }

    #[test]
    fn opcode_as_str_slugs_match() {
        assert_eq!(NbnsOpcode::Query.as_str(), "query");
        assert_eq!(NbnsOpcode::Registration.as_str(), "registration");
        assert_eq!(NbnsOpcode::Release.as_str(), "release");
        assert_eq!(NbnsOpcode::Wack.as_str(), "wack");
        assert_eq!(NbnsOpcode::Refresh.as_str(), "refresh");
        assert_eq!(NbnsOpcode::Other(15).as_str(), "other");
    }

    #[test]
    fn malformed_question_length_returns_none_on_question() {
        let mut payload = build_query("X", 0x00, 0);
        // Corrupt the question's length byte.
        payload[12] = 33;
        // Header survives but question doesn't parse.
        let msg = parse(&payload);
        assert!(msg.is_none(), "malformed question → reject entire msg");
    }
}

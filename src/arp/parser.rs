//! ARP wire parser.
//!
//! ARP doesn't have a 5-tuple flow concept, so the parser is a
//! **stateless free function** rather than a `DatagramParser`
//! implementation. Consumers integrate by checking the EtherType
//! (0x0806) and calling [`parse`] / [`parse_frame`] on the
//! payload.
//!
//! For full-frame parsing (with Ethernet header), use
//! [`parse_frame`]. For payload-only parsing (when the consumer
//! has already stripped the L2 header — e.g., when iterating
//! over [`crate::layers::ArpSlice`]), use [`parse`].

use std::net::Ipv4Addr;

use super::types::{ArpMessage, ArpOp};
use crate::MacAddr;

/// EtherType for ARP.
pub const ARP_ETHERTYPE: u16 = 0x0806;

const ETHERNET_HTYPE: u16 = 1;
const IPV4_PTYPE: u16 = 0x0800;
const HLEN_MAC: u8 = 6;
const PLEN_IPV4: u8 = 4;

/// Failure mode for the `parse*` functions (issue #85).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// Buffer shorter than the bytes required at this stage.
    Truncated {
        /// Bytes needed.
        need: usize,
        /// Bytes available.
        have: usize,
    },
    /// Ethernet frame EtherType wasn't ARP (0x0806).
    NotArp,
    /// Hardware / protocol type or address-length fields don't
    /// match Ethernet + IPv4 (htype != 1, ptype != 0x0800,
    /// hlen != 6, or plen != 4).
    UnsupportedHardware,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated { need, have } => {
                write!(f, "truncated ARP message: need {need}, have {have}")
            }
            Self::NotArp => f.write_str("not an ARP frame (EtherType != 0x0806)"),
            Self::UnsupportedHardware => {
                f.write_str("unsupported ARP hardware/protocol (not Ethernet/IPv4)")
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
            ParseError::NotArp => ErrorCode::Parse,
            ParseError::UnsupportedHardware => ErrorCode::Unsupported,
        };
        crate::Error::with_code(Module::Arp, code, e.to_string())
    }
}

/// Parse an ARP payload (no Ethernet header).
///
/// Returns `Err` for:
/// - Truncated payloads (< 28 bytes) → [`ParseError::Truncated`].
/// - Non-Ethernet hardware type, non-IPv4 protocol type, or
///   mismatched address lengths → [`ParseError::UnsupportedHardware`].
///
/// Issue #1 (0.17). Signature changed to `Result` in issue #85.
pub fn parse(payload: &[u8]) -> Result<ArpMessage, ParseError> {
    if payload.len() < 28 {
        return Err(ParseError::Truncated {
            need: 28,
            have: payload.len(),
        });
    }
    let htype = u16::from_be_bytes([payload[0], payload[1]]);
    let ptype = u16::from_be_bytes([payload[2], payload[3]]);
    let hlen = payload[4];
    let plen = payload[5];
    if htype != ETHERNET_HTYPE || ptype != IPV4_PTYPE || hlen != HLEN_MAC || plen != PLEN_IPV4 {
        return Err(ParseError::UnsupportedHardware);
    }
    let oper = ArpOp::from(u16::from_be_bytes([payload[6], payload[7]]));

    let mut sender_mac = [0u8; 6];
    sender_mac.copy_from_slice(&payload[8..14]);
    let sender_ip = Ipv4Addr::new(payload[14], payload[15], payload[16], payload[17]);

    let mut target_mac = [0u8; 6];
    target_mac.copy_from_slice(&payload[18..24]);
    let target_ip = Ipv4Addr::new(payload[24], payload[25], payload[26], payload[27]);

    Ok(ArpMessage {
        oper,
        sender: MacAddr(sender_mac),
        sender_ip,
        target: MacAddr(target_mac),
        target_ip,
    })
}

/// Parse an Ethernet frame whose EtherType is ARP (0x0806).
///
/// Returns `Err` if the frame is truncated, isn't ARP, or fails
/// the ARP-specific [`parse`] checks. Handles a single 802.1Q
/// VLAN tag transparently (most real captures aren't multi-tag
/// ARP).
///
/// Issue #1 (0.17). Signature changed to `Result` in issue #85.
pub fn parse_frame(frame: &[u8]) -> Result<ArpMessage, ParseError> {
    if frame.len() < 14 {
        return Err(ParseError::Truncated {
            need: 14,
            have: frame.len(),
        });
    }
    let mut offset = 12;
    let mut ethertype = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
    // Strip one 802.1Q VLAN tag — need 4 tag bytes + 2 inner-EtherType bytes.
    if ethertype == 0x8100 {
        if frame.len() < offset + 6 {
            return Err(ParseError::Truncated {
                need: offset + 6,
                have: frame.len(),
            });
        }
        offset += 4;
        ethertype = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
    }
    if ethertype != ARP_ETHERTYPE {
        return Err(ParseError::NotArp);
    }
    offset += 2;
    parse(&frame[offset..])
}

/// Stateless ARP "parser" tag — provided so consumers wiring up
/// arp_slots / event hooks can pass it as a marker. Calling
/// [`parse`] / [`parse_frame`] directly is also fully supported.
#[derive(Debug, Clone, Copy, Default)]
pub struct ArpParser;

impl ArpParser {
    /// See [`parse`].
    #[inline]
    pub fn parse(&self, payload: &[u8]) -> Result<ArpMessage, ParseError> {
        parse(payload)
    }

    /// See [`parse_frame`].
    #[inline]
    pub fn parse_frame(&self, frame: &[u8]) -> Result<ArpMessage, ParseError> {
        parse_frame(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an ARP payload (28 bytes, no Ethernet header).
    fn build_payload(
        op: u16,
        sender: [u8; 6],
        sender_ip: [u8; 4],
        target: [u8; 6],
        target_ip: [u8; 4],
    ) -> Vec<u8> {
        let mut p = Vec::with_capacity(28);
        p.extend_from_slice(&[0x00, 0x01]); // htype = Ethernet
        p.extend_from_slice(&[0x08, 0x00]); // ptype = IPv4
        p.push(6); // hlen
        p.push(4); // plen
        p.extend_from_slice(&op.to_be_bytes());
        p.extend_from_slice(&sender);
        p.extend_from_slice(&sender_ip);
        p.extend_from_slice(&target);
        p.extend_from_slice(&target_ip);
        p
    }

    /// Wrap an ARP payload in an Ethernet frame (no VLAN).
    fn build_frame(payload: &[u8]) -> Vec<u8> {
        let mut f = Vec::with_capacity(14 + payload.len());
        f.extend_from_slice(&[0xff; 6]); // broadcast dst
        f.extend_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]); // src
        f.extend_from_slice(&[0x08, 0x06]); // EtherType = ARP
        f.extend_from_slice(payload);
        f
    }

    #[test]
    fn parses_request() {
        let p = build_payload(
            1,
            [0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
            [10, 0, 0, 1],
            [0; 6],
            [10, 0, 0, 2],
        );
        let msg = parse(&p).unwrap();
        assert!(matches!(msg.oper, ArpOp::Request));
        assert_eq!(msg.sender, MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]));
        assert_eq!(msg.sender_ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(msg.target, MacAddr::ZERO);
        assert_eq!(msg.target_ip, Ipv4Addr::new(10, 0, 0, 2));
    }

    #[test]
    fn parses_reply() {
        let p = build_payload(2, [0xaa; 6], [10, 0, 0, 1], [0xbb; 6], [10, 0, 0, 2]);
        let msg = parse(&p).unwrap();
        assert!(matches!(msg.oper, ArpOp::Reply));
    }

    #[test]
    fn parses_rarp_codes() {
        for (op_code, expected) in [(3u16, ArpOp::RarpRequest), (4u16, ArpOp::RarpReply)] {
            let p = build_payload(op_code, [0xaa; 6], [0; 4], [0xbb; 6], [0; 4]);
            let msg = parse(&p).unwrap();
            assert_eq!(msg.oper, expected);
        }
    }

    #[test]
    fn parses_gratuitous_request() {
        let p = build_payload(
            1,
            [0xaa; 6],
            [10, 0, 0, 1],
            [0; 6],
            [10, 0, 0, 1], // same as sender
        );
        let msg = parse(&p).unwrap();
        assert!(msg.is_gratuitous());
    }

    #[test]
    fn rejects_truncated() {
        assert!(parse(&[]).is_err());
        assert!(parse(&[0; 10]).is_err());
        assert!(parse(&[0; 27]).is_err());
    }

    #[test]
    fn rejects_non_ethernet_htype() {
        let mut p = build_payload(1, [0xaa; 6], [0; 4], [0xbb; 6], [0; 4]);
        p[0] = 0x00;
        p[1] = 0x05; // some non-Ethernet htype
        assert!(parse(&p).is_err());
    }

    #[test]
    fn rejects_non_ipv4_ptype() {
        let mut p = build_payload(1, [0xaa; 6], [0; 4], [0xbb; 6], [0; 4]);
        p[2] = 0x86;
        p[3] = 0xdd; // IPv6 ptype
        assert!(parse(&p).is_err());
    }

    #[test]
    fn rejects_mismatched_hlen() {
        let mut p = build_payload(1, [0xaa; 6], [0; 4], [0xbb; 6], [0; 4]);
        p[4] = 8; // wrong hlen
        assert!(parse(&p).is_err());
    }

    #[test]
    fn rejects_mismatched_plen() {
        let mut p = build_payload(1, [0xaa; 6], [0; 4], [0xbb; 6], [0; 4]);
        p[5] = 16; // wrong plen
        assert!(parse(&p).is_err());
    }

    #[test]
    fn parse_frame_strips_ethernet() {
        let p = build_payload(2, [0xaa; 6], [10, 0, 0, 1], [0xbb; 6], [10, 0, 0, 2]);
        let frame = build_frame(&p);
        let msg = parse_frame(&frame).unwrap();
        assert!(matches!(msg.oper, ArpOp::Reply));
        assert_eq!(msg.sender_ip, Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn parse_frame_rejects_non_arp_ethertype() {
        let mut frame = build_frame(&[0; 28]);
        // Flip EtherType to IPv4.
        frame[12] = 0x08;
        frame[13] = 0x00;
        assert!(parse_frame(&frame).is_err());
    }

    #[test]
    fn parse_frame_handles_single_vlan_tag() {
        let p = build_payload(1, [0xaa; 6], [10, 0, 0, 1], [0; 6], [10, 0, 0, 2]);
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0xff; 6]); // dst
        frame.extend_from_slice(&[0x11; 6]); // src
        frame.extend_from_slice(&[0x81, 0x00]); // VLAN tag
        frame.extend_from_slice(&[0x00, 0x64]); // TCI: VID 100
        frame.extend_from_slice(&[0x08, 0x06]); // EtherType = ARP
        frame.extend_from_slice(&p);
        let msg = parse_frame(&frame).unwrap();
        assert!(matches!(msg.oper, ArpOp::Request));
    }

    #[test]
    fn arp_parser_marker_delegates() {
        let p = build_payload(1, [0xaa; 6], [0; 4], [0xbb; 6], [0; 4]);
        let frame = build_frame(&p);
        let parser = ArpParser;
        assert!(parser.parse(&p).is_ok());
        assert!(parser.parse_frame(&frame).is_ok());
    }

    #[test]
    fn parse_frame_rejects_qinq_double_tag() {
        // parse_frame strips ONE 802.1Q tag; a QinQ outer
        // 0x88a8 tag is not recognised and the frame must be
        // rejected. False-negative is fine; the wire shape is
        // niche and consumers can roll their own QinQ stripper.
        let p = build_payload(1, [0xaa; 6], [10, 0, 0, 1], [0; 6], [10, 0, 0, 2]);
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0xff; 6]); // dst
        frame.extend_from_slice(&[0x11; 6]); // src
        frame.extend_from_slice(&[0x88, 0xa8]); // QinQ outer
        frame.extend_from_slice(&[0x00, 0x64]); // outer TCI
        frame.extend_from_slice(&[0x81, 0x00]); // inner 802.1Q
        frame.extend_from_slice(&[0x00, 0x64]); // inner TCI
        frame.extend_from_slice(&[0x08, 0x06]); // EtherType = ARP
        frame.extend_from_slice(&p);
        assert!(parse_frame(&frame).is_err());
    }

    #[test]
    fn parse_frame_with_vlan_but_non_arp_inner_returns_none() {
        // 802.1Q tag wraps an IPv4 frame — should not call
        // parse() on garbage payload.
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0xff; 6]);
        frame.extend_from_slice(&[0x11; 6]);
        frame.extend_from_slice(&[0x81, 0x00]); // VLAN
        frame.extend_from_slice(&[0x00, 0x64]); // TCI
        frame.extend_from_slice(&[0x08, 0x00]); // EtherType = IPv4
        frame.extend_from_slice(&[0u8; 28]); // garbage payload
        assert!(parse_frame(&frame).is_err());
    }
}

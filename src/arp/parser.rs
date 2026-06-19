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

use crate::MacAddr;

use super::types::{ArpMessage, ArpOp};

/// EtherType for ARP.
pub const ARP_ETHERTYPE: u16 = 0x0806;

const ETHERNET_HTYPE: u16 = 1;
const IPV4_PTYPE: u16 = 0x0800;
const HLEN_MAC: u8 = 6;
const PLEN_IPV4: u8 = 4;

/// Parse an ARP payload (no Ethernet header).
///
/// Returns `None` for:
/// - Truncated payloads (< 28 bytes).
/// - Non-Ethernet hardware type (htype != 1).
/// - Non-IPv4 protocol type (ptype != 0x0800).
/// - Mismatched address lengths (hlen != 6 || plen != 4).
///
/// Issue #1 (0.17).
pub fn parse(payload: &[u8]) -> Option<ArpMessage> {
    if payload.len() < 28 {
        return None;
    }
    let htype = u16::from_be_bytes([payload[0], payload[1]]);
    let ptype = u16::from_be_bytes([payload[2], payload[3]]);
    let hlen = payload[4];
    let plen = payload[5];
    if htype != ETHERNET_HTYPE || ptype != IPV4_PTYPE || hlen != HLEN_MAC || plen != PLEN_IPV4 {
        return None;
    }
    let oper = ArpOp::from(u16::from_be_bytes([payload[6], payload[7]]));

    let mut sender_mac = [0u8; 6];
    sender_mac.copy_from_slice(&payload[8..14]);
    let sender_ip = Ipv4Addr::new(payload[14], payload[15], payload[16], payload[17]);

    let mut target_mac = [0u8; 6];
    target_mac.copy_from_slice(&payload[18..24]);
    let target_ip = Ipv4Addr::new(payload[24], payload[25], payload[26], payload[27]);

    Some(ArpMessage {
        oper,
        sender: MacAddr(sender_mac),
        sender_ip,
        target: MacAddr(target_mac),
        target_ip,
    })
}

/// Parse an Ethernet frame whose EtherType is ARP (0x0806).
///
/// Returns `None` if the frame is truncated, isn't ARP, or fails
/// the ARP-specific [`parse`] checks. Handles a single 802.1Q
/// VLAN tag transparently (most real captures aren't multi-tag
/// ARP).
///
/// Issue #1 (0.17).
pub fn parse_frame(frame: &[u8]) -> Option<ArpMessage> {
    if frame.len() < 14 {
        return None;
    }
    let mut offset = 12;
    let mut ethertype = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
    // Strip one 802.1Q VLAN tag.
    if ethertype == 0x8100 {
        if frame.len() < offset + 4 {
            return None;
        }
        offset += 4;
        ethertype = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
    }
    if ethertype != ARP_ETHERTYPE {
        return None;
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
    pub fn parse(&self, payload: &[u8]) -> Option<ArpMessage> {
        parse(payload)
    }

    /// See [`parse_frame`].
    #[inline]
    pub fn parse_frame(&self, frame: &[u8]) -> Option<ArpMessage> {
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
        assert_eq!(
            msg.sender,
            MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
        );
        assert_eq!(msg.sender_ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(msg.target, MacAddr::ZERO);
        assert_eq!(msg.target_ip, Ipv4Addr::new(10, 0, 0, 2));
    }

    #[test]
    fn parses_reply() {
        let p = build_payload(
            2,
            [0xaa; 6],
            [10, 0, 0, 1],
            [0xbb; 6],
            [10, 0, 0, 2],
        );
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
        assert!(parse(&[]).is_none());
        assert!(parse(&[0; 10]).is_none());
        assert!(parse(&[0; 27]).is_none());
    }

    #[test]
    fn rejects_non_ethernet_htype() {
        let mut p = build_payload(1, [0xaa; 6], [0; 4], [0xbb; 6], [0; 4]);
        p[0] = 0x00;
        p[1] = 0x05; // some non-Ethernet htype
        assert!(parse(&p).is_none());
    }

    #[test]
    fn rejects_non_ipv4_ptype() {
        let mut p = build_payload(1, [0xaa; 6], [0; 4], [0xbb; 6], [0; 4]);
        p[2] = 0x86;
        p[3] = 0xdd; // IPv6 ptype
        assert!(parse(&p).is_none());
    }

    #[test]
    fn rejects_mismatched_hlen() {
        let mut p = build_payload(1, [0xaa; 6], [0; 4], [0xbb; 6], [0; 4]);
        p[4] = 8; // wrong hlen
        assert!(parse(&p).is_none());
    }

    #[test]
    fn rejects_mismatched_plen() {
        let mut p = build_payload(1, [0xaa; 6], [0; 4], [0xbb; 6], [0; 4]);
        p[5] = 16; // wrong plen
        assert!(parse(&p).is_none());
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
        assert!(parse_frame(&frame).is_none());
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
        assert!(parser.parse(&p).is_some());
        assert!(parser.parse_frame(&frame).is_some());
    }
}

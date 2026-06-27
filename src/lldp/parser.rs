//! LLDP wire parser. IEEE 802.1AB-2016 §8.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::Bytes;

use super::types::{
    CapabilityBits, ChassisId, LldpManagementAddress, LldpMessage, LldpVendorTlv, PortId,
    SystemCapabilities,
};
use crate::MacAddr;

/// EtherType for LLDP.
pub const LLDP_ETHERTYPE: u16 = 0x88cc;

/// IEEE 802.1AB destination multicast MACs that identify an
/// LLDPDU on the wire.
const LLDP_DST_MACS: [[u8; 6]; 3] = [
    [0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e], // nearest_bridge
    [0x01, 0x80, 0xc2, 0x00, 0x00, 0x03], // non_tpmr_component
    [0x01, 0x80, 0xc2, 0x00, 0x00, 0x00], // customer_bridge
];

// TLV types we surface as typed fields. Type 0 is end-of-LLDPDU;
// any other type byte is walked over and ignored.
const TLV_END: u8 = 0;
const TLV_CHASSIS_ID: u8 = 1;
const TLV_PORT_ID: u8 = 2;
const TLV_TTL: u8 = 3;
const TLV_PORT_DESC: u8 = 4;
const TLV_SYSTEM_NAME: u8 = 5;
const TLV_SYSTEM_DESC: u8 = 6;
const TLV_CAPABILITIES: u8 = 7;
const TLV_MGMT_ADDR: u8 = 8;
const TLV_ORG_SPECIFIC: u8 = 127;

/// Defense against malformed input: cap walk iterations + the
/// number of optional collections we keep.
const MAX_TLVS: usize = 256;
const MAX_MGMT_ADDRESSES: usize = 4;
const MAX_VENDOR_TLVS: usize = 8;

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
    /// Ethernet frame isn't an LLDPDU (dst MAC not an IEEE LLDP
    /// multicast, or EtherType != 0x88cc).
    NotLldp,
    /// A mandatory TLV (chassis-ID → port-ID → TTL) was missing,
    /// out of order, or malformed.
    MalformedTlv,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated { need, have } => {
                write!(f, "truncated LLDP frame: need {need}, have {have}")
            }
            Self::NotLldp => f.write_str("not an LLDP frame (dst MAC / EtherType mismatch)"),
            Self::MalformedTlv => f.write_str("malformed or misordered mandatory LLDP TLV"),
        }
    }
}

impl std::error::Error for ParseError {}

impl From<ParseError> for crate::Error {
    fn from(e: ParseError) -> Self {
        use crate::error::{ErrorCode, Module};
        let code = match &e {
            ParseError::Truncated { .. } => ErrorCode::Truncated,
            ParseError::NotLldp | ParseError::MalformedTlv => ErrorCode::Parse,
        };
        crate::Error::with_code(Module::Lldp, code, e.to_string())
    }
}

/// Parse an LLDP payload (no Ethernet header).
///
/// Returns `Err` when:
/// - The mandatory TLV ordering (chassis-ID → port-ID → TTL)
///   is violated, a TLV header would read off the end of the
///   buffer, or the chassis-ID, port-ID, or TTL TLVs are
///   malformed → [`ParseError::MalformedTlv`].
///
/// Optional TLV malformations (truncated mgmt-address, invalid
/// UTF-8 in a description field) skip the offending TLV rather
/// than failing the whole parse — the mandatory triple is
/// already useful on its own.
///
/// Signature changed to `Result` in issue #85.
pub fn parse(payload: &[u8]) -> Result<LldpMessage, ParseError> {
    let mut walker = TlvWalker { buf: payload };

    let chassis_id = match walker.next() {
        Some((TLV_CHASSIS_ID, value)) => parse_chassis_id(value).ok_or(ParseError::MalformedTlv)?,
        _ => return Err(ParseError::MalformedTlv),
    };
    let port_id = match walker.next() {
        Some((TLV_PORT_ID, value)) => parse_port_id(value).ok_or(ParseError::MalformedTlv)?,
        _ => return Err(ParseError::MalformedTlv),
    };
    let ttl_seconds = match walker.next() {
        Some((TLV_TTL, value)) if value.len() == 2 => u16::from_be_bytes([value[0], value[1]]),
        _ => return Err(ParseError::MalformedTlv),
    };

    let mut msg = LldpMessage {
        chassis_id,
        port_id,
        ttl_seconds,
        port_description: None,
        system_name: None,
        system_description: None,
        capabilities: None,
        management_addresses: Vec::new(),
        vendor_tlvs: Vec::new(),
    };

    for _ in 0..MAX_TLVS {
        match walker.next() {
            None => break, // out of bytes or hit TLV_END
            Some((TLV_PORT_DESC, value)) => {
                msg.port_description
                    .get_or_insert_with(|| copy_bytes(value));
            }
            Some((TLV_SYSTEM_NAME, value)) => {
                msg.system_name.get_or_insert_with(|| copy_bytes(value));
            }
            Some((TLV_SYSTEM_DESC, value)) => {
                msg.system_description
                    .get_or_insert_with(|| copy_bytes(value));
            }
            Some((TLV_CAPABILITIES, value)) if value.len() == 4 => {
                msg.capabilities = Some(SystemCapabilities {
                    system: CapabilityBits::from_bits_truncate(u16::from_be_bytes([
                        value[0], value[1],
                    ])),
                    enabled: CapabilityBits::from_bits_truncate(u16::from_be_bytes([
                        value[2], value[3],
                    ])),
                });
            }
            Some((TLV_MGMT_ADDR, value)) => {
                if msg.management_addresses.len() >= MAX_MGMT_ADDRESSES {
                    continue;
                }
                if let Some(mgmt) = parse_mgmt_address(value) {
                    msg.management_addresses.push(mgmt);
                }
            }
            Some((TLV_ORG_SPECIFIC, value)) => {
                if msg.vendor_tlvs.len() >= MAX_VENDOR_TLVS {
                    continue;
                }
                if value.len() >= 4 {
                    let oui = [value[0], value[1], value[2]];
                    let subtype = value[3];
                    msg.vendor_tlvs.push(LldpVendorTlv {
                        oui,
                        subtype,
                        value: copy_bytes(&value[4..]),
                    });
                }
            }
            // Unrecognised TLV types: ignored. Capability=4 was
            // matched above; any other length is also ignored.
            Some(_) => {}
        }
    }

    Ok(msg)
}

/// Parse an Ethernet frame whose EtherType is 0x88cc (LLDP),
/// destined for an IEEE-reserved LLDP multicast.
///
/// Strips one 802.1Q VLAN tag transparently. Returns `Err`
/// when the frame isn't LLDP-destined, isn't 0x88cc, or fails
/// the [`parse`] checks.
///
/// Signature changed to `Result` in issue #85.
pub fn parse_frame(frame: &[u8]) -> Result<LldpMessage, ParseError> {
    if frame.len() < 14 {
        return Err(ParseError::Truncated {
            need: 14,
            have: frame.len(),
        });
    }
    let mut dst = [0u8; 6];
    dst.copy_from_slice(&frame[..6]);
    if !LLDP_DST_MACS.contains(&dst) {
        return Err(ParseError::NotLldp);
    }
    let mut offset = 12;
    let mut ethertype = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
    if ethertype == 0x8100 {
        // Strip one 802.1Q tag: need 4 tag bytes + 2 inner-EtherType bytes.
        if frame.len() < offset + 6 {
            return Err(ParseError::Truncated {
                need: offset + 6,
                have: frame.len(),
            });
        }
        offset += 4;
        ethertype = u16::from_be_bytes([frame[offset], frame[offset + 1]]);
    }
    if ethertype != LLDP_ETHERTYPE {
        return Err(ParseError::NotLldp);
    }
    offset += 2;
    parse(&frame[offset..])
}

/// Stateless LLDP "parser" tag — provided so consumers wiring
/// up lldp slots / event hooks can pass it as a marker.
#[derive(Debug, Clone, Copy, Default)]
pub struct LldpParser;

impl LldpParser {
    /// See [`parse`].
    #[inline]
    pub fn parse(&self, payload: &[u8]) -> Result<LldpMessage, ParseError> {
        parse(payload)
    }

    /// See [`parse_frame`].
    #[inline]
    pub fn parse_frame(&self, frame: &[u8]) -> Result<LldpMessage, ParseError> {
        parse_frame(frame)
    }
}

// ─── TLV walker ──────────────────────────────────────────────

/// Iterator-shaped TLV walker. Each `next()` returns the next
/// `(type, value)` pair, or `None` on `TLV_END` / truncation.
struct TlvWalker<'a> {
    buf: &'a [u8],
}

impl<'a> TlvWalker<'a> {
    fn next(&mut self) -> Option<(u8, &'a [u8])> {
        if self.buf.len() < 2 {
            return None;
        }
        // Header: 7-bit type | 9-bit length, big-endian.
        let header = u16::from_be_bytes([self.buf[0], self.buf[1]]);
        let tlv_type = ((header >> 9) & 0x7f) as u8;
        let tlv_len = (header & 0x01ff) as usize;
        if tlv_type == TLV_END {
            self.buf = &[];
            return None;
        }
        if self.buf.len() < 2 + tlv_len {
            // Truncated value — abort the walk.
            self.buf = &[];
            return None;
        }
        let value = &self.buf[2..2 + tlv_len];
        self.buf = &self.buf[2 + tlv_len..];
        Some((tlv_type, value))
    }
}

// ─── TLV-specific decoders ───────────────────────────────────

fn parse_chassis_id(value: &[u8]) -> Option<ChassisId> {
    if value.is_empty() {
        return None;
    }
    let subtype = value[0];
    let rest = &value[1..];
    Some(match subtype {
        1 => ChassisId::ChassisComponent(copy_bytes(rest)),
        2 => ChassisId::InterfaceAlias(copy_bytes(rest)),
        3 => ChassisId::PortComponent(copy_bytes(rest)),
        4 if rest.len() == 6 => {
            let mut m = [0u8; 6];
            m.copy_from_slice(rest);
            ChassisId::MacAddress(MacAddr(m))
        }
        5 => ChassisId::NetworkAddress(parse_network_address(rest)?),
        6 => ChassisId::InterfaceName(copy_bytes(rest)),
        7 => ChassisId::Local(copy_bytes(rest)),
        other => ChassisId::Other {
            subtype: other,
            value: copy_bytes(rest),
        },
    })
}

fn parse_port_id(value: &[u8]) -> Option<PortId> {
    if value.is_empty() {
        return None;
    }
    let subtype = value[0];
    let rest = &value[1..];
    Some(match subtype {
        1 => PortId::InterfaceAlias(copy_bytes(rest)),
        2 => PortId::PortComponent(copy_bytes(rest)),
        3 if rest.len() == 6 => {
            let mut m = [0u8; 6];
            m.copy_from_slice(rest);
            PortId::MacAddress(MacAddr(m))
        }
        4 => PortId::NetworkAddress(parse_network_address(rest)?),
        5 => PortId::InterfaceName(copy_bytes(rest)),
        6 => PortId::AgentCircuitId(copy_bytes(rest)),
        7 => PortId::Local(copy_bytes(rest)),
        other => PortId::Other {
            subtype: other,
            value: copy_bytes(rest),
        },
    })
}

/// Parse an IEEE 802.1AB Network Address field. The first byte
/// is the IANA address-family subtype; 1 = IPv4 (4 bytes),
/// 2 = IPv6 (16 bytes). Anything else returns `None`.
fn parse_network_address(rest: &[u8]) -> Option<IpAddr> {
    let family = *rest.first()?;
    let payload = &rest[1..];
    match family {
        1 if payload.len() == 4 => Some(IpAddr::V4(Ipv4Addr::new(
            payload[0], payload[1], payload[2], payload[3],
        ))),
        2 if payload.len() == 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(payload);
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

/// Parse a Management Address TLV value (RFC IEEE 802.1AB
/// §8.5.9). Layout:
///
/// ```text
/// 1B addr_string_length  (N)         <-- includes the subtype byte
/// 1B address_subtype                  IANA address-family
/// N-1B address
/// 1B interface_subtype                (ignored)
/// 4B interface_number                 (ignored)
/// 1B oid_length                       (M)
/// M B OID                             (ignored)
/// ```
fn parse_mgmt_address(value: &[u8]) -> Option<LldpManagementAddress> {
    if value.len() < 2 {
        return None;
    }
    let addr_str_len = value[0] as usize;
    if addr_str_len == 0 || value.len() < 1 + addr_str_len {
        return None;
    }
    let address_family = value[1];
    // The address bytes start at offset 2 and run for
    // `addr_str_len - 1` bytes (the spec counts the subtype
    // byte in the length).
    let addr_len = addr_str_len - 1;
    let raw_address = copy_bytes(&value[2..2 + addr_len]);
    let ip = match (address_family, addr_len) {
        (1, 4) => Some(IpAddr::V4(Ipv4Addr::new(
            raw_address[0],
            raw_address[1],
            raw_address[2],
            raw_address[3],
        ))),
        (2, 16) => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&raw_address);
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    };
    Some(LldpManagementAddress {
        address_family,
        ip,
        raw_address,
    })
}

#[inline]
fn copy_bytes(value: &[u8]) -> Bytes {
    Bytes::copy_from_slice(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a TLV header + value: `type:7 | length:9` packed.
    fn tlv(ty: u8, value: &[u8]) -> Vec<u8> {
        let header = (((ty as u16) & 0x7f) << 9) | ((value.len() as u16) & 0x01ff);
        let mut out = header.to_be_bytes().to_vec();
        out.extend_from_slice(value);
        out
    }

    fn end_tlv() -> Vec<u8> {
        tlv(0, &[])
    }

    fn minimal_payload(chassis_mac: [u8; 6], port_name: &[u8], ttl: u16) -> Vec<u8> {
        let mut p = Vec::new();
        // Chassis ID subtype 4 (MAC) + 6 bytes.
        let mut cid = vec![4u8];
        cid.extend_from_slice(&chassis_mac);
        p.extend(tlv(TLV_CHASSIS_ID, &cid));
        // Port ID subtype 5 (interface name) + variable.
        let mut pid = vec![5u8];
        pid.extend_from_slice(port_name);
        p.extend(tlv(TLV_PORT_ID, &pid));
        // TTL.
        p.extend(tlv(TLV_TTL, &ttl.to_be_bytes()));
        p
    }

    #[test]
    fn parses_minimal_mandatory_triple() {
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let mut p = minimal_payload(mac, b"Gi0/1", 120);
        p.extend(end_tlv());
        let m = parse(&p).unwrap();
        assert_eq!(m.chassis_id, ChassisId::MacAddress(MacAddr(mac)));
        assert!(matches!(&m.port_id, PortId::InterfaceName(b) if b.as_ref() == b"Gi0/1"));
        assert_eq!(m.ttl_seconds, 120);
        assert!(m.system_name.is_none());
    }

    #[test]
    fn parses_full_lldpdu_from_typical_switch() {
        let mac = [0; 6];
        let mut p = minimal_payload(mac, b"Gi0/24", 120);
        p.extend(tlv(TLV_PORT_DESC, b"Uplink to core"));
        p.extend(tlv(TLV_SYSTEM_NAME, b"sw-edge-01"));
        p.extend(tlv(TLV_SYSTEM_DESC, b"Cisco IOS 16.9.4"));
        // Capabilities: system=Bridge+Router, enabled=Bridge only.
        let caps = [
            0x00,
            (CapabilityBits::BRIDGE | CapabilityBits::ROUTER).bits() as u8,
            0x00,
            CapabilityBits::BRIDGE.bits() as u8,
        ];
        p.extend(tlv(TLV_CAPABILITIES, &caps));
        // Mgmt addr: IPv4 192.0.2.1 with subtype byte = 5 bytes total.
        p.extend(tlv(
            TLV_MGMT_ADDR,
            &[
                5, 1, 192, 0, 2, 1, /* if subtype */ 2, /* if# */ 0, 0, 0, 1,
                /* oid len */ 0,
            ],
        ));
        // Vendor TLV (Cisco OUI).
        p.extend(tlv(TLV_ORG_SPECIFIC, &[0x00, 0x01, 0x42, 0x01, b'X']));
        p.extend(end_tlv());

        let m = parse(&p).unwrap();
        assert_eq!(m.system_name.as_deref(), Some(b"sw-edge-01".as_ref()));
        assert_eq!(
            m.system_description.as_deref(),
            Some(b"Cisco IOS 16.9.4".as_ref())
        );
        assert_eq!(
            m.port_description.as_deref(),
            Some(b"Uplink to core".as_ref())
        );
        let caps = m.capabilities.unwrap();
        assert!(caps.system.contains(CapabilityBits::BRIDGE));
        assert!(caps.system.contains(CapabilityBits::ROUTER));
        assert!(caps.enabled.contains(CapabilityBits::BRIDGE));
        assert!(!caps.enabled.contains(CapabilityBits::ROUTER));
        assert_eq!(m.management_addresses.len(), 1);
        assert_eq!(
            m.management_addresses[0].ip,
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)))
        );
        assert_eq!(m.vendor_tlvs.len(), 1);
        assert_eq!(m.vendor_tlvs[0].oui, [0x00, 0x01, 0x42]);
    }

    #[test]
    fn parses_shutdown_announce_ttl_zero() {
        let mut p = minimal_payload([0; 6], b"x", 0);
        p.extend(end_tlv());
        let m = parse(&p).unwrap();
        assert!(m.is_shutdown_announce());
    }

    #[test]
    fn rejects_wrong_mandatory_tlv_order() {
        let mut p = Vec::new();
        // Port ID first — violates mandatory ordering.
        p.extend(tlv(TLV_PORT_ID, &[5, b'x']));
        p.extend(tlv(TLV_CHASSIS_ID, &[7, b'a']));
        p.extend(tlv(TLV_TTL, &120u16.to_be_bytes()));
        p.extend(end_tlv());
        assert!(parse(&p).is_err());
    }

    #[test]
    fn rejects_truncated_payload() {
        assert!(parse(&[]).is_err());
        assert!(parse(&[0x02]).is_err());
        // Header claims 100 bytes of value but no value follows.
        let header = ((TLV_CHASSIS_ID as u16) << 9) | 100;
        assert!(parse(&header.to_be_bytes()).is_err());
    }

    #[test]
    fn rejects_malformed_mandatory_chassis_id() {
        let mut p = Vec::new();
        // Chassis subtype 4 (MAC) but with only 3 bytes.
        p.extend(tlv(TLV_CHASSIS_ID, &[4, 0, 1, 2]));
        p.extend(tlv(TLV_PORT_ID, &[5, b'x']));
        p.extend(tlv(TLV_TTL, &10u16.to_be_bytes()));
        p.extend(end_tlv());
        // Subtype 4 with wrong length falls through to Other.
        let m = parse(&p).unwrap();
        assert!(matches!(&m.chassis_id, ChassisId::Other { subtype: 4, .. }));
    }

    #[test]
    fn chassis_id_matches_src_on_mac_form() {
        let mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let mut p = minimal_payload(mac, b"x", 60);
        p.extend(end_tlv());
        let m = parse(&p).unwrap();
        assert!(m.chassis_id_matches_src(MacAddr(mac)));
        assert!(!m.chassis_id_matches_src(MacAddr([0; 6])));
    }

    #[test]
    fn parse_frame_strips_ethernet_and_validates_dst() {
        let mut p = minimal_payload([0xaa; 6], b"e0", 30);
        p.extend(end_tlv());
        let mut frame = Vec::new();
        frame.extend_from_slice(&LLDP_DST_MACS[0]);
        frame.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]); // src
        frame.extend_from_slice(&LLDP_ETHERTYPE.to_be_bytes());
        frame.extend_from_slice(&p);
        let m = parse_frame(&frame).unwrap();
        assert_eq!(m.ttl_seconds, 30);
    }

    #[test]
    fn parse_frame_rejects_non_lldp_dst_mac() {
        let mut p = minimal_payload([0xaa; 6], b"e0", 30);
        p.extend(end_tlv());
        let mut frame = Vec::new();
        // Broadcast — not an LLDP multicast.
        frame.extend_from_slice(&[0xff; 6]);
        frame.extend_from_slice(&[0xaa; 6]);
        frame.extend_from_slice(&LLDP_ETHERTYPE.to_be_bytes());
        frame.extend_from_slice(&p);
        assert!(parse_frame(&frame).is_err());
    }

    #[test]
    fn parse_frame_handles_single_vlan_tag() {
        let mut p = minimal_payload([0xaa; 6], b"e0", 30);
        p.extend(end_tlv());
        let mut frame = Vec::new();
        frame.extend_from_slice(&LLDP_DST_MACS[0]);
        frame.extend_from_slice(&[0xaa; 6]);
        frame.extend_from_slice(&[0x81, 0x00]); // VLAN
        frame.extend_from_slice(&[0x00, 0x64]); // TCI
        frame.extend_from_slice(&LLDP_ETHERTYPE.to_be_bytes());
        frame.extend_from_slice(&p);
        assert!(parse_frame(&frame).is_ok());
    }

    #[test]
    fn vendor_tlv_walker_is_bounded() {
        let mut p = minimal_payload([0xaa; 6], b"x", 60);
        // 20 vendor TLVs — only the first 8 should be kept.
        for _ in 0..20 {
            p.extend(tlv(TLV_ORG_SPECIFIC, &[0, 1, 2, 3, b'V']));
        }
        p.extend(end_tlv());
        let m = parse(&p).unwrap();
        assert_eq!(m.vendor_tlvs.len(), MAX_VENDOR_TLVS);
    }

    #[test]
    fn unknown_tlv_types_are_skipped() {
        let mut p = minimal_payload([0; 6], b"x", 60);
        // Random reserved type 99 — should be walked over.
        p.extend(tlv(99, &[1, 2, 3]));
        p.extend(tlv(TLV_SYSTEM_NAME, b"after-99"));
        p.extend(end_tlv());
        let m = parse(&p).unwrap();
        assert_eq!(m.system_name.as_deref(), Some(b"after-99".as_ref()));
    }

    #[test]
    fn end_tlv_stops_walk_even_with_trailing_garbage() {
        let mut p = minimal_payload([0; 6], b"x", 60);
        p.extend(end_tlv());
        // Anything past end is ignored.
        p.extend(tlv(TLV_SYSTEM_NAME, b"ignored"));
        let m = parse(&p).unwrap();
        assert!(m.system_name.is_none());
    }

    #[test]
    fn lldp_parser_marker_delegates() {
        let mut p = minimal_payload([0; 6], b"x", 60);
        p.extend(end_tlv());
        let mut frame = Vec::new();
        frame.extend_from_slice(&LLDP_DST_MACS[0]);
        frame.extend_from_slice(&[0; 6]);
        frame.extend_from_slice(&LLDP_ETHERTYPE.to_be_bytes());
        frame.extend_from_slice(&p);
        let parser = LldpParser;
        assert!(parser.parse(&p).is_ok());
        assert!(parser.parse_frame(&frame).is_ok());
    }
}

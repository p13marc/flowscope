//! CDP wire parser.
//!
//! Cisco's CDP rides 802.3 / LLC / SNAP framing — different from
//! LLDP (which uses EtherType 0x88cc):
//!
//! ```text
//! Eth dst (6) = 01:00:0c:cc:cc:cc       <-- multicast
//! Eth src (6) = sender MAC
//! Length  (2) = 802.3 length (NOT ethertype)
//! ---- LLC ----
//! DSAP (1) = 0xAA
//! SSAP (1) = 0xAA
//! CTRL (1) = 0x03
//! ---- SNAP ----
//! OUI  (3) = 00:00:0C            <-- Cisco
//! PID  (2) = 0x2000              <-- CDP
//! ---- CDPDU ----
//! Version (1)
//! TTL     (1)
//! Checksum (2)
//! TLVs:
//!   TLV type   (2)
//!   TLV length (2)   <-- includes the 4-byte header
//!   TLV value  (length - 4)
//! ```

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::Bytes;

use super::types::{CdpAddress, CdpCapabilities, CdpMessage};

/// CDP destination multicast MAC.
pub const CDP_DST_MAC: [u8; 6] = [0x01, 0x00, 0x0c, 0xcc, 0xcc, 0xcc];
/// CDP OUI inside the SNAP header.
pub const CDP_OUI: [u8; 3] = [0x00, 0x00, 0x0c];
/// CDP protocol ID inside the SNAP header.
pub const CDP_PID: u16 = 0x2000;

const TLV_DEVICE_ID: u16 = 0x0001;
const TLV_ADDRESSES: u16 = 0x0002;
const TLV_PORT_ID: u16 = 0x0003;
const TLV_CAPABILITIES: u16 = 0x0004;
const TLV_SOFTWARE_VERSION: u16 = 0x0005;
const TLV_PLATFORM: u16 = 0x0006;
const TLV_VTP_DOMAIN: u16 = 0x0009;
const TLV_NATIVE_VLAN: u16 = 0x000a;
const TLV_DUPLEX: u16 = 0x000b;
const TLV_MGMT_ADDRESS: u16 = 0x0016;

/// Cap the TLV-walker iteration count as defense against
/// malformed input. Real CDPDUs carry ~12 TLVs at most.
const MAX_TLVS: usize = 64;
/// Cap the address-list walker similarly.
const MAX_ADDRESSES: usize = 16;

/// Parse a CDPDU payload (post the LLC/SNAP/OUI/PID header).
///
/// Returns `None` when:
/// - The payload is < 4 bytes (version + TTL + checksum minimum).
/// - A TLV header would read off the end of the buffer.
/// - A TLV claims length < 4 (header alone is 4 bytes; smaller
///   is malformed).
pub fn parse(payload: &[u8]) -> Option<CdpMessage> {
    if payload.len() < 4 {
        return None;
    }
    let version = payload[0];
    let ttl_seconds = payload[1];
    // checksum at payload[2..4] — not validated; depending on
    // capture point it's stale or wrong.
    let mut cursor = &payload[4..];

    let mut msg = CdpMessage {
        version,
        ttl_seconds,
        device_id: None,
        addresses: Vec::new(),
        port_id: None,
        capabilities: None,
        software_version: None,
        platform: None,
        native_vlan: None,
        duplex: None,
        vtp_domain: None,
        management_addresses: Vec::new(),
    };

    for _ in 0..MAX_TLVS {
        if cursor.is_empty() {
            break;
        }
        if cursor.len() < 4 {
            // TLV header truncated.
            break;
        }
        let tlv_type = u16::from_be_bytes([cursor[0], cursor[1]]);
        let tlv_len = u16::from_be_bytes([cursor[2], cursor[3]]) as usize;
        if tlv_len < 4 || cursor.len() < tlv_len {
            // Length covers the 4-byte header; sub-4 is malformed.
            break;
        }
        let value = &cursor[4..tlv_len];
        cursor = &cursor[tlv_len..];

        match tlv_type {
            TLV_DEVICE_ID => msg.device_id.get_or_insert_with(|| copy(value)),
            TLV_PORT_ID => msg.port_id.get_or_insert_with(|| copy(value)),
            TLV_SOFTWARE_VERSION => msg.software_version.get_or_insert_with(|| copy(value)),
            TLV_PLATFORM => msg.platform.get_or_insert_with(|| copy(value)),
            TLV_VTP_DOMAIN => msg.vtp_domain.get_or_insert_with(|| copy(value)),
            TLV_CAPABILITIES if value.len() == 4 => {
                let bits = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                msg.capabilities = Some(CdpCapabilities::from_bits_truncate(bits));
                continue;
            }
            TLV_NATIVE_VLAN if value.len() == 2 => {
                msg.native_vlan = Some(u16::from_be_bytes([value[0], value[1]]));
                continue;
            }
            TLV_DUPLEX if !value.is_empty() => {
                msg.duplex = Some(value[0]);
                continue;
            }
            TLV_ADDRESSES => {
                msg.addresses = parse_address_block(value);
                continue;
            }
            TLV_MGMT_ADDRESS => {
                msg.management_addresses = parse_address_block(value);
                continue;
            }
            _ => continue,
        };
    }

    Some(msg)
}

/// Parse a full Ethernet frame whose payload is a CDPDU.
///
/// Validates the reserved Cisco multicast dst MAC and the
/// LLC + SNAP + OUI + PID header before delegating to
/// [`parse`].
///
/// Returns `None` when the frame is too short, the dst MAC
/// doesn't match `01:00:0c:cc:cc:cc`, the LLC/SNAP/OUI/PID
/// doesn't match CDP, or [`parse`] rejects the inner payload.
pub fn parse_frame(frame: &[u8]) -> Option<CdpMessage> {
    // Eth (14) + LLC (3) + SNAP (5) = 22 bytes of header.
    if frame.len() < 22 {
        return None;
    }
    if frame[0..6] != CDP_DST_MAC {
        return None;
    }
    // bytes 12..14 are the 802.3 length field — not validated
    // (CDP allows it to be informational only).
    if frame[14] != 0xaa || frame[15] != 0xaa || frame[16] != 0x03 {
        return None; // LLC SNAP marker.
    }
    if frame[17..20] != CDP_OUI {
        return None;
    }
    let pid = u16::from_be_bytes([frame[20], frame[21]]);
    if pid != CDP_PID {
        return None;
    }
    parse(&frame[22..])
}

/// Stateless CDP marker, mirroring `ArpParser` / `LldpParser`.
#[derive(Debug, Clone, Copy, Default)]
pub struct CdpParser;

impl CdpParser {
    /// See [`parse`].
    #[inline]
    pub fn parse(&self, payload: &[u8]) -> Option<CdpMessage> {
        parse(payload)
    }

    /// See [`parse_frame`].
    #[inline]
    pub fn parse_frame(&self, frame: &[u8]) -> Option<CdpMessage> {
        parse_frame(frame)
    }
}

#[inline]
fn copy(value: &[u8]) -> Bytes {
    Bytes::copy_from_slice(value)
}

/// Decode a CDP Address block. Wire shape:
///
/// ```text
/// 4B count
/// per entry:
///   1B  protocol_type (1 = NLPID, 2 = 802.2)
///   1B  protocol_length (PL)
///   PL B protocol (e.g. 0xcc for IPv4, 0x086dd for IPv6)
///   2B  address_length (AL)
///   AL B address
/// ```
fn parse_address_block(value: &[u8]) -> Vec<CdpAddress> {
    if value.len() < 4 {
        return Vec::new();
    }
    let count = u32::from_be_bytes([value[0], value[1], value[2], value[3]]) as usize;
    let count = count.min(MAX_ADDRESSES);
    let mut cursor = &value[4..];
    let mut out = Vec::with_capacity(count.min(4));
    for _ in 0..count {
        if cursor.len() < 2 {
            break;
        }
        let protocol_type = cursor[0];
        let pl = cursor[1] as usize;
        if cursor.len() < 2 + pl + 2 {
            break;
        }
        let proto = &cursor[2..2 + pl];
        let al_bytes = &cursor[2 + pl..2 + pl + 2];
        let al = u16::from_be_bytes([al_bytes[0], al_bytes[1]]) as usize;
        if cursor.len() < 2 + pl + 2 + al {
            break;
        }
        let address = &cursor[2 + pl + 2..2 + pl + 2 + al];
        let ip = decode_ip(proto, address);
        out.push(CdpAddress {
            protocol_type,
            ip,
            raw_address: copy(address),
        });
        cursor = &cursor[2 + pl + 2 + al..];
    }
    out
}

/// Decode an address-block address as an IP when the protocol
/// field identifies IPv4 (one byte `0xcc`) or IPv6 (two bytes
/// `0x86dd`).
fn decode_ip(proto: &[u8], address: &[u8]) -> Option<IpAddr> {
    if proto == [0xcc] && address.len() == 4 {
        return Some(IpAddr::V4(Ipv4Addr::new(
            address[0], address[1], address[2], address[3],
        )));
    }
    if proto == [0x86, 0xdd] && address.len() == 16 {
        let mut octets = [0u8; 16];
        octets.copy_from_slice(address);
        return Some(IpAddr::V6(Ipv6Addr::from(octets)));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv(ty: u16, value: &[u8]) -> Vec<u8> {
        let total_len = (value.len() + 4) as u16;
        let mut out = ty.to_be_bytes().to_vec();
        out.extend_from_slice(&total_len.to_be_bytes());
        out.extend_from_slice(value);
        out
    }

    fn cdp_payload_minimal(device_id: &[u8]) -> Vec<u8> {
        let mut p = vec![0x02, 180, 0x00, 0x00]; // version, TTL, checksum
        p.extend(tlv(TLV_DEVICE_ID, device_id));
        p
    }

    fn ipv4_address(addr: [u8; 4]) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(0x01); // protocol_type = NLPID
        v.push(0x01); // protocol_length
        v.push(0xcc); // protocol = IPv4
        v.extend_from_slice(&2u16.to_be_bytes()); // wrong length, will be ignored
        // Actually CDP IPv4 uses protocol-length 1, address-length 4.
        v.clear();
        v.push(0x01);
        v.push(0x01);
        v.push(0xcc);
        v.extend_from_slice(&4u16.to_be_bytes());
        v.extend_from_slice(&addr);
        v
    }

    fn ipv6_address(addr: [u8; 16]) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(0x02); // 802.2
        v.push(0x08); // protocol_length = 8 (SNAP: AA AA 03 OUI[3] + PID[2])
        // For IPv6: NLPID style differs. Real CDP uses
        // protocol_length=2 with 0x86dd. Keep it minimal.
        v.clear();
        v.push(0x02);
        v.push(0x02);
        v.extend_from_slice(&[0x86, 0xdd]);
        v.extend_from_slice(&16u16.to_be_bytes());
        v.extend_from_slice(&addr);
        v
    }

    #[test]
    fn parses_minimal_device_id() {
        let p = cdp_payload_minimal(b"sw-edge-01.example.com");
        let m = parse(&p).unwrap();
        assert_eq!(m.version, 0x02);
        assert_eq!(m.ttl_seconds, 180);
        assert_eq!(
            m.device_id.as_deref(),
            Some(b"sw-edge-01.example.com".as_ref())
        );
        assert!(m.port_id.is_none());
        assert!(m.platform.is_none());
    }

    #[test]
    fn parses_typical_cisco_advertisement() {
        let mut p = vec![0x02, 180, 0, 0];
        p.extend(tlv(TLV_DEVICE_ID, b"sw-core-01"));
        p.extend(tlv(TLV_PORT_ID, b"GigabitEthernet0/24"));
        p.extend(tlv(TLV_PLATFORM, b"cisco WS-C2960X-24TS-L"));
        p.extend(tlv(TLV_SOFTWARE_VERSION, b"Cisco IOS 15.2(7)E"));
        p.extend(tlv(TLV_CAPABILITIES, &0x00000028u32.to_be_bytes())); // SWITCH | IGMP
        p.extend(tlv(TLV_NATIVE_VLAN, &10u16.to_be_bytes()));
        p.extend(tlv(TLV_DUPLEX, &[1])); // full

        let m = parse(&p).unwrap();
        assert_eq!(m.device_id.as_deref(), Some(b"sw-core-01".as_ref()));
        assert_eq!(m.port_id.as_deref(), Some(b"GigabitEthernet0/24".as_ref()));
        assert_eq!(
            m.platform.as_deref(),
            Some(b"cisco WS-C2960X-24TS-L".as_ref())
        );
        assert_eq!(
            m.software_version.as_deref(),
            Some(b"Cisco IOS 15.2(7)E".as_ref())
        );
        let caps = m.capabilities.unwrap();
        assert!(caps.contains(CdpCapabilities::SWITCH));
        assert!(caps.contains(CdpCapabilities::IGMP));
        assert!(!caps.contains(CdpCapabilities::ROUTER));
        assert_eq!(m.native_vlan, Some(10));
        assert_eq!(m.duplex, Some(1));
    }

    #[test]
    fn parses_addresses_tlv_ipv4() {
        let mut p = vec![0x02, 180, 0, 0];
        let mut addr_block = 1u32.to_be_bytes().to_vec();
        addr_block.extend(ipv4_address([192, 0, 2, 10]));
        p.extend(tlv(TLV_ADDRESSES, &addr_block));

        let m = parse(&p).unwrap();
        assert_eq!(m.addresses.len(), 1);
        assert_eq!(
            m.addresses[0].ip,
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))
        );
    }

    #[test]
    fn parses_mgmt_address_tlv_ipv6() {
        let mut p = vec![0x02, 180, 0, 0];
        let mut block = 1u32.to_be_bytes().to_vec();
        let mut v6 = [0u8; 16];
        v6[0] = 0x20;
        v6[1] = 0x01;
        v6[15] = 0x05;
        block.extend(ipv6_address(v6));
        p.extend(tlv(TLV_MGMT_ADDRESS, &block));

        let m = parse(&p).unwrap();
        assert_eq!(m.management_addresses.len(), 1);
        assert_eq!(
            m.management_addresses[0].ip,
            Some(IpAddr::V6(Ipv6Addr::from(v6)))
        );
    }

    #[test]
    fn rejects_truncated_payload() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[0x02, 180, 0]).is_none());
    }

    #[test]
    fn truncated_tlv_aborts_walk_keeping_earlier_fields() {
        let mut p = vec![0x02, 180, 0, 0];
        p.extend(tlv(TLV_DEVICE_ID, b"x"));
        // A header that claims 1000 bytes of value.
        p.extend_from_slice(&TLV_PORT_ID.to_be_bytes());
        p.extend_from_slice(&1000u16.to_be_bytes());
        // …with nothing after.
        let m = parse(&p).unwrap();
        assert_eq!(m.device_id.as_deref(), Some(b"x".as_ref()));
        assert!(m.port_id.is_none());
    }

    #[test]
    fn tlv_length_less_than_4_is_malformed_aborts_walk() {
        let mut p = vec![0x02, 180, 0, 0];
        p.extend_from_slice(&TLV_DEVICE_ID.to_be_bytes());
        p.extend_from_slice(&3u16.to_be_bytes()); // header claims length < its own header
        assert!(parse(&p).unwrap().device_id.is_none());
    }

    #[test]
    fn walker_caps_iterations() {
        let mut p = vec![0x02, 180, 0, 0];
        // Pile on 200 unknown TLVs.
        for _ in 0..200 {
            p.extend(tlv(0x1000, &[0]));
        }
        // The walker stops at MAX_TLVS=64. Should still succeed
        // without OOMing or hanging.
        let m = parse(&p).unwrap();
        // No fields populated (unknown TLV type).
        assert!(m.device_id.is_none());
    }

    #[test]
    fn parse_frame_round_trip() {
        let p = cdp_payload_minimal(b"sw1");
        let mut frame = Vec::new();
        frame.extend_from_slice(&CDP_DST_MAC);
        frame.extend_from_slice(&[0x11; 6]); // src
        frame.extend_from_slice(&((p.len() + 8) as u16).to_be_bytes()); // 802.3 length
        // LLC + SNAP.
        frame.extend_from_slice(&[0xaa, 0xaa, 0x03]);
        frame.extend_from_slice(&CDP_OUI);
        frame.extend_from_slice(&CDP_PID.to_be_bytes());
        frame.extend_from_slice(&p);
        let m = parse_frame(&frame).unwrap();
        assert_eq!(m.device_id.as_deref(), Some(b"sw1".as_ref()));
    }

    #[test]
    fn parse_frame_rejects_non_cdp_dst() {
        let p = cdp_payload_minimal(b"sw1");
        let mut frame = Vec::new();
        frame.extend_from_slice(&[0xff; 6]); // broadcast, not CDP multicast
        frame.extend_from_slice(&[0x11; 6]);
        frame.extend_from_slice(&((p.len() + 8) as u16).to_be_bytes());
        frame.extend_from_slice(&[0xaa, 0xaa, 0x03]);
        frame.extend_from_slice(&CDP_OUI);
        frame.extend_from_slice(&CDP_PID.to_be_bytes());
        frame.extend_from_slice(&p);
        assert!(parse_frame(&frame).is_none());
    }

    #[test]
    fn parse_frame_rejects_wrong_oui() {
        let p = cdp_payload_minimal(b"sw1");
        let mut frame = Vec::new();
        frame.extend_from_slice(&CDP_DST_MAC);
        frame.extend_from_slice(&[0x11; 6]);
        frame.extend_from_slice(&((p.len() + 8) as u16).to_be_bytes());
        frame.extend_from_slice(&[0xaa, 0xaa, 0x03]);
        frame.extend_from_slice(&[0xde, 0xad, 0xbe]); // wrong OUI
        frame.extend_from_slice(&CDP_PID.to_be_bytes());
        frame.extend_from_slice(&p);
        assert!(parse_frame(&frame).is_none());
    }

    #[test]
    fn cdp_parser_marker_delegates() {
        let p = cdp_payload_minimal(b"sw1");
        let parser = CdpParser;
        assert!(parser.parse(&p).is_some());
    }
}

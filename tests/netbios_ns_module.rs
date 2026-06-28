//! NetBIOS-NS module — wire parsing + asset adapter (issue #14).

#![cfg(feature = "netbios-ns")]

use flowscope::netbios_ns::{NBNS_PORT, NbnsOpcode, NbnsParser, parse};
use flowscope::{DatagramParser, FlowSide, Timestamp};

fn build_query(name: &str, suffix: u8, txn: u16, opcode_bits: u16) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&txn.to_be_bytes());
    let flags = (opcode_bits << 11) | 0x0010; // broadcast
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.push(32);
    out.extend_from_slice(&encode_name(name, suffix));
    out.push(0);
    out.extend_from_slice(&0x0020u16.to_be_bytes());
    out.extend_from_slice(&0x0001u16.to_be_bytes());
    out
}

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
fn port_constant_matches_iana() {
    assert_eq!(NBNS_PORT, 137);
}

#[test]
fn parse_function_handles_query() {
    let payload = build_query("HOSTNAME", 0x00, 0x4242, 0);
    let msg = parse(&payload).expect("parse");
    assert_eq!(msg.transaction_id, 0x4242);
    assert_eq!(msg.opcode, NbnsOpcode::Query);
    assert_eq!(msg.queried_name.as_deref(), Some("HOSTNAME"));
    assert_eq!(msg.name_suffix, Some(0x00));
}

#[test]
fn parser_kind_label_is_netbios_ns() {
    let p = NbnsParser;
    assert_eq!(p.parser_kind().as_str(), "netbios-ns");
}

#[test]
fn parser_emits_msg_on_valid_datagram() {
    let payload = build_query("HOST", 0x20, 0x1, 0);
    let mut parser = NbnsParser;
    let mut out = Vec::new();
    parser.parse(
        &payload,
        FlowSide::Initiator,
        Timestamp::default(),
        &mut out,
    );
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].name_suffix, Some(0x20));
}

#[test]
fn parser_drops_malformed_datagram() {
    let mut parser = NbnsParser;
    let mut out = Vec::new();
    parser.parse(
        b"too short",
        FlowSide::Initiator,
        Timestamp::default(),
        &mut out,
    );
    assert!(out.is_empty());
}

#[test]
fn opcode_release_and_refresh_decode() {
    let release = build_query("X", 0x00, 0, 6);
    assert_eq!(parse(&release).unwrap().opcode, NbnsOpcode::Release);
    let refresh = build_query("X", 0x00, 0, 8);
    assert_eq!(parse(&refresh).unwrap().opcode, NbnsOpcode::Refresh);
}

#[cfg(feature = "asset")]
mod asset {
    use super::*;
    use flowscope::asset::{Asset, AssetCapabilities, AssetSourceSet};
    use flowscope::{Inventory, MacAddr};

    #[test]
    fn from_netbios_ns_extracts_hostname() {
        let payload = build_query("CLIENT01", 0x00, 0, 0);
        let msg = parse(&payload).expect("parse");
        let mac = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01]);
        let asset = Asset::from_netbios_ns(&msg, mac).expect("populated");
        assert_eq!(asset.mac, mac);
        assert_eq!(asset.hostname.as_deref(), Some("CLIENT01"));
        assert!(asset.seen_via.contains(AssetSourceSet::NBNS));
        assert!(asset.capabilities.contains(AssetCapabilities::HOST));
    }

    #[test]
    fn from_netbios_ns_extracts_answer_address() {
        let mut payload = build_query("HOST", 0x00, 0x42, 5);
        payload[2] |= 0x80; // response
        payload[6] = 0;
        payload[7] = 1; // ancount=1
        // Append answer: pointer + NB type + class + TTL + rdlen + rdata
        payload.push(0xc0);
        payload.push(0x0c);
        payload.extend_from_slice(&0x0020u16.to_be_bytes());
        payload.extend_from_slice(&0x0001u16.to_be_bytes());
        payload.extend_from_slice(&300u32.to_be_bytes());
        payload.extend_from_slice(&6u16.to_be_bytes());
        payload.extend_from_slice(&[0, 0, 192, 168, 1, 100]);
        let msg = parse(&payload).expect("parse");
        let mac = MacAddr([1; 6]);
        let asset = Asset::from_netbios_ns(&msg, mac).expect("populated");
        assert!(
            asset
                .ipv4
                .contains(&std::net::Ipv4Addr::new(192, 168, 1, 100))
        );
    }

    #[test]
    fn from_netbios_ns_returns_none_when_neither_name_nor_address() {
        // Pure header with qdcount=0, ancount=0.
        let header = vec![0u8; 12];
        let msg = parse(&header).expect("header parses");
        let mac = MacAddr([0; 6]);
        assert!(Asset::from_netbios_ns(&msg, mac).is_none());
    }

    #[test]
    fn inventory_absorbs_netbios_ns_asset() {
        let mut inv = Inventory::new(8);
        let payload = build_query("LAPTOP", 0x00, 0, 0);
        let msg = parse(&payload).expect("parse");
        let mac = MacAddr([3; 6]);
        let asset = Asset::from_netbios_ns(&msg, mac).expect("populated");
        inv.absorb(asset);
        let got = inv.get(&mac).expect("present");
        assert_eq!(got.hostname.as_deref(), Some("LAPTOP"));
        assert!(got.seen_via.contains(AssetSourceSet::NBNS));
    }
}

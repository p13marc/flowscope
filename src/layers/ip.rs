//! Network-layer slices: IPv4 + IPv6 + ARP.
//!
//! Each slice wraps a `&[u8]` borrowed from the original frame
//! and exposes typed field accessors. No allocation; `Copy`.

use std::net::{Ipv4Addr, Ipv6Addr};

use super::LayerKind;

/// IPv4 header slice.
#[derive(Debug, Clone, Copy)]
pub struct Ipv4Slice<'a> {
    raw: &'a [u8],
    header_len: usize,
}

impl<'a> Ipv4Slice<'a> {
    pub(crate) fn new(raw: &'a [u8], header_len: usize) -> Self {
        Self { raw, header_len }
    }

    /// IP version (always 4).
    pub fn version(&self) -> u8 {
        (self.raw[0] >> 4) & 0x0F
    }

    /// Internet Header Length in 32-bit words.
    pub fn ihl(&self) -> u8 {
        self.raw[0] & 0x0F
    }

    /// Differentiated Services Code Point.
    pub fn dscp(&self) -> u8 {
        (self.raw[1] >> 2) & 0x3F
    }

    /// Explicit Congestion Notification.
    pub fn ecn(&self) -> u8 {
        self.raw[1] & 0x03
    }

    /// Total length in bytes (header + payload).
    pub fn total_length(&self) -> u16 {
        u16::from_be_bytes([self.raw[2], self.raw[3]])
    }

    /// 16-bit identification.
    pub fn identification(&self) -> u16 {
        u16::from_be_bytes([self.raw[4], self.raw[5]])
    }

    /// Don't Fragment flag.
    pub fn df(&self) -> bool {
        (self.raw[6] >> 6) & 0x01 == 1
    }

    /// More Fragments flag.
    pub fn mf(&self) -> bool {
        (self.raw[6] >> 5) & 0x01 == 1
    }

    /// Fragment offset in 8-byte units.
    pub fn fragment_offset(&self) -> u16 {
        u16::from_be_bytes([self.raw[6] & 0x1F, self.raw[7]])
    }

    /// Time To Live.
    pub fn ttl(&self) -> u8 {
        self.raw[8]
    }

    /// L4 protocol number (TCP=6, UDP=17, ICMP=1, …).
    pub fn protocol(&self) -> u8 {
        self.raw[9]
    }

    /// Header checksum (as observed on the wire).
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.raw[10], self.raw[11]])
    }

    /// Source address.
    pub fn source(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.raw[12], self.raw[13], self.raw[14], self.raw[15])
    }

    /// Destination address.
    pub fn destination(&self) -> Ipv4Addr {
        Ipv4Addr::new(self.raw[16], self.raw[17], self.raw[18], self.raw[19])
    }

    /// Full header bytes (including options if any).
    pub fn header(&self) -> &'a [u8] {
        &self.raw[..self.header_len]
    }

    /// L4 payload bytes.
    pub fn payload(&self) -> &'a [u8] {
        &self.raw[self.header_len..]
    }

    pub fn bytes(&self) -> &'a [u8] {
        self.raw
    }

    pub fn kind(&self) -> LayerKind {
        LayerKind::Ipv4
    }
}

/// IPv6 header slice. (40-byte fixed header; extension headers
/// are not parsed in this release.)
#[derive(Debug, Clone, Copy)]
pub struct Ipv6Slice<'a> {
    raw: &'a [u8],
    header_len: usize,
}

impl<'a> Ipv6Slice<'a> {
    pub(crate) fn new(raw: &'a [u8], header_len: usize) -> Self {
        Self { raw, header_len }
    }

    pub fn version(&self) -> u8 {
        (self.raw[0] >> 4) & 0x0F
    }

    pub fn traffic_class(&self) -> u8 {
        ((self.raw[0] & 0x0F) << 4) | (self.raw[1] >> 4)
    }

    /// 20-bit IPv6 flow label.
    pub fn flow_label(&self) -> u32 {
        ((self.raw[1] as u32 & 0x0F) << 16)
            | ((self.raw[2] as u32) << 8)
            | self.raw[3] as u32
    }

    pub fn payload_length(&self) -> u16 {
        u16::from_be_bytes([self.raw[4], self.raw[5]])
    }

    /// `next_header` field — for plain v6 this is the L4 protocol;
    /// with extension headers it's the first extension.
    pub fn next_header(&self) -> u8 {
        self.raw[6]
    }

    pub fn hop_limit(&self) -> u8 {
        self.raw[7]
    }

    pub fn source(&self) -> Ipv6Addr {
        let mut a = [0u8; 16];
        a.copy_from_slice(&self.raw[8..24]);
        Ipv6Addr::from(a)
    }

    pub fn destination(&self) -> Ipv6Addr {
        let mut a = [0u8; 16];
        a.copy_from_slice(&self.raw[24..40]);
        Ipv6Addr::from(a)
    }

    pub fn header(&self) -> &'a [u8] {
        &self.raw[..self.header_len]
    }

    pub fn payload(&self) -> &'a [u8] {
        &self.raw[self.header_len..]
    }

    pub fn bytes(&self) -> &'a [u8] {
        self.raw
    }

    pub fn kind(&self) -> LayerKind {
        LayerKind::Ipv6
    }
}

/// ARP packet slice (RFC 826).
///
/// Fixed-format 28-byte ARP for Ethernet/IPv4: 8-byte header
/// (htype, ptype, hlen, plen, oper) + sender HA/PA + target HA/PA.
#[derive(Debug, Clone, Copy)]
pub struct ArpSlice<'a> {
    raw: &'a [u8],
}

impl<'a> ArpSlice<'a> {
    pub(crate) fn new(raw: &'a [u8]) -> Self {
        Self { raw }
    }

    /// Hardware type (Ethernet = 1).
    pub fn htype(&self) -> u16 {
        u16::from_be_bytes([self.raw[0], self.raw[1]])
    }

    /// Protocol type (IPv4 = 0x0800).
    pub fn ptype(&self) -> u16 {
        u16::from_be_bytes([self.raw[2], self.raw[3]])
    }

    /// Hardware address length (6 for Ethernet).
    pub fn hlen(&self) -> u8 {
        self.raw[4]
    }

    /// Protocol address length (4 for IPv4).
    pub fn plen(&self) -> u8 {
        self.raw[5]
    }

    /// Operation (1 = request, 2 = reply).
    pub fn oper(&self) -> u16 {
        u16::from_be_bytes([self.raw[6], self.raw[7]])
    }

    /// Sender hardware address. Returns `None` if hlen ≠ 6.
    pub fn sender_ha(&self) -> Option<[u8; 6]> {
        if self.hlen() != 6 || self.raw.len() < 14 {
            return None;
        }
        let mut o = [0u8; 6];
        o.copy_from_slice(&self.raw[8..14]);
        Some(o)
    }

    /// Sender protocol address (assumes IPv4 — returns `None`
    /// if plen ≠ 4).
    pub fn sender_pa(&self) -> Option<std::net::Ipv4Addr> {
        if self.plen() != 4 || self.raw.len() < 18 {
            return None;
        }
        Some(std::net::Ipv4Addr::new(
            self.raw[14],
            self.raw[15],
            self.raw[16],
            self.raw[17],
        ))
    }

    /// Target hardware address (assumes hlen=6).
    pub fn target_ha(&self) -> Option<[u8; 6]> {
        if self.hlen() != 6 || self.raw.len() < 24 {
            return None;
        }
        let mut o = [0u8; 6];
        o.copy_from_slice(&self.raw[18..24]);
        Some(o)
    }

    /// Target protocol address (assumes IPv4).
    pub fn target_pa(&self) -> Option<std::net::Ipv4Addr> {
        if self.plen() != 4 || self.raw.len() < 28 {
            return None;
        }
        Some(std::net::Ipv4Addr::new(
            self.raw[24],
            self.raw[25],
            self.raw[26],
            self.raw[27],
        ))
    }

    pub fn header(&self) -> &'a [u8] {
        &self.raw[..self.raw.len().min(28)]
    }

    pub fn bytes(&self) -> &'a [u8] {
        self.raw
    }

    pub fn kind(&self) -> LayerKind {
        LayerKind::Arp
    }
}

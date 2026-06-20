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
        ((self.raw[1] as u32 & 0x0F) << 16) | ((self.raw[2] as u32) << 8) | self.raw[3] as u32
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

    /// Walk the IPv6 extension-header chain to the upper-layer
    /// protocol. Returns the final `next_header` (the true L4),
    /// the offset within `payload()` where that L4 header
    /// starts, observed extension types, and a
    /// `fragment_present` flag.
    ///
    /// Without this, [`Self::next_header`] returns the FIRST
    /// header — which is the first extension when ext headers
    /// are present, NOT the L4 protocol. The classic IPv6 NIDS
    /// evasion vector (Atlasis 2012, RFC 8200 §4) inserts
    /// Hop-by-Hop or Destination Options to hide the true L4
    /// from analyzers that don't walk the chain.
    ///
    /// **Bounded** at 8 ext headers (real-world chains are
    /// ≤4 deep; absurdly deep chains are an evasion attempt and
    /// produce [`Ipv6ExtensionWalk::chain_too_deep == true`]).
    ///
    /// Issue #22 (Release A).
    pub fn extensions(&self) -> Ipv6ExtensionWalk {
        const MAX_DEPTH: u8 = 8;
        let payload = self.payload();
        let mut nh = self.next_header();
        let mut offset = 0usize;
        let mut chain_depth = 0u8;
        let mut fragment_present = false;
        let mut chain_too_deep = false;
        let mut malformed = false;

        loop {
            if !is_extension_header(nh) {
                break;
            }
            if chain_depth >= MAX_DEPTH {
                chain_too_deep = true;
                break;
            }
            // Need at least 2 bytes (next_header + hdr_ext_len)
            // to walk. Anything shorter is malformed; stop with
            // the malformed flag set.
            if payload.len() < offset + 2 {
                malformed = true;
                break;
            }
            let hdr_next = payload[offset];
            let ext_len_bytes = ext_header_len(nh, payload[offset + 1]);
            // Truncated extension: cap offset at payload end and stop.
            if payload.len() < offset + ext_len_bytes {
                malformed = true;
                break;
            }
            if nh == 44 {
                fragment_present = true;
            }
            nh = hdr_next;
            offset += ext_len_bytes;
            chain_depth += 1;
        }

        Ipv6ExtensionWalk {
            upper_header: nh,
            payload_offset: offset,
            chain_depth,
            fragment_present,
            chain_too_deep,
            malformed,
        }
    }
}

/// Result of walking an IPv6 extension-header chain.
///
/// See [`Ipv6Slice::extensions`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Ipv6ExtensionWalk {
    /// The true upper-layer protocol (TCP=6, UDP=17, ICMPv6=58,
    /// SCTP=132, etc.) after walking the extension chain. When
    /// no extensions are present, equals [`Ipv6Slice::next_header`].
    pub upper_header: u8,
    /// Offset within [`Ipv6Slice::payload`] where the upper-layer
    /// header starts. `0` when there are no extensions.
    pub payload_offset: usize,
    /// Number of extension headers walked.
    pub chain_depth: u8,
    /// `true` if a Fragment header (next_header = 44) was
    /// observed in the chain.
    pub fragment_present: bool,
    /// `true` if the walker hit the 8-extension cap. Likely an
    /// evasion attempt — real-world chains are ≤4 deep.
    pub chain_too_deep: bool,
    /// `true` if the chain was truncated mid-extension or had
    /// an unparseable length field. Caller should treat the
    /// resulting `upper_header` as "best effort, not
    /// authoritative."
    pub malformed: bool,
}

/// `true` for IPv6 extension-header `next_header` values that
/// chain further (RFC 8200 §4).
///
/// Includes: Hop-by-Hop (0), Routing (43), Fragment (44),
/// Destination Options (60), AH (51), Mobility (135), HIP (139),
/// Shim6 (140). Notably excludes ESP (50), which is a terminal
/// "encrypted-payload, no further info" marker.
fn is_extension_header(nh: u8) -> bool {
    matches!(nh, 0 | 43 | 44 | 60 | 51 | 135 | 139 | 140)
}

/// Length in bytes of an IPv6 extension header keyed by its
/// `next_header` type code and the on-wire `hdr_ext_len` field
/// (in 8-byte units, NOT including the first 8 bytes per
/// RFC 8200 §4).
fn ext_header_len(this_header: u8, hdr_ext_len: u8) -> usize {
    match this_header {
        // Fragment header is FIXED at 8 bytes (RFC 8200 §4.5).
        44 => 8,
        // AH (RFC 4302 §2.2): payload length in 32-bit words
        // minus 2. We approximate as the standard 8-byte chunk
        // formula since the chain still proceeds linearly.
        51 => (hdr_ext_len as usize + 2) * 4,
        // All other extension headers (Hop-by-Hop, Routing,
        // Destination Options, Mobility, HIP, Shim6): the
        // standard "8 + hdr_ext_len * 8" formula.
        _ => 8 + (hdr_ext_len as usize) * 8,
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

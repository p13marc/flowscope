//! Link-layer slices: Ethernet II + 802.1Q VLAN + MPLS.

use super::LayerKind;

/// Ethernet II header slice.
#[derive(Debug, Clone, Copy)]
pub struct EthernetSlice<'a> {
    raw: &'a [u8],
}

impl<'a> EthernetSlice<'a> {
    pub(crate) fn new(raw: &'a [u8]) -> Self {
        Self { raw }
    }

    /// Destination MAC address.
    pub fn destination(&self) -> [u8; 6] {
        let mut o = [0u8; 6];
        o.copy_from_slice(&self.raw[0..6]);
        o
    }

    /// Source MAC address.
    pub fn source(&self) -> [u8; 6] {
        let mut o = [0u8; 6];
        o.copy_from_slice(&self.raw[6..12]);
        o
    }

    /// EtherType field. For VLAN-tagged frames this is the outer
    /// `0x8100`; the inner EtherType is on the [`VlanSlice`].
    pub fn ether_type(&self) -> u16 {
        u16::from_be_bytes([self.raw[12], self.raw[13]])
    }

    /// Full header bytes (14 bytes for Ethernet II without VLAN).
    pub fn header(&self) -> &'a [u8] {
        &self.raw[..14]
    }

    /// Header + payload — the original slice this was parsed from.
    pub fn bytes(&self) -> &'a [u8] {
        self.raw
    }

    /// Kind discriminant.
    pub fn kind(&self) -> LayerKind {
        LayerKind::Ethernet
    }
}

/// 802.1Q VLAN tag slice (single or outer of a Q-in-Q stack).
#[derive(Debug, Clone, Copy)]
pub struct VlanSlice<'a> {
    raw: &'a [u8],
}

impl<'a> VlanSlice<'a> {
    pub(crate) fn new(raw: &'a [u8]) -> Self {
        Self { raw }
    }

    /// VLAN identifier (12 bits).
    pub fn vid(&self) -> u16 {
        u16::from_be_bytes([self.raw[0], self.raw[1]]) & 0x0FFF
    }

    /// Priority Code Point (3 bits).
    pub fn priority(&self) -> u8 {
        (self.raw[0] >> 5) & 0x07
    }

    /// Drop-Eligible Indicator.
    pub fn dei(&self) -> bool {
        (self.raw[0] >> 4) & 0x01 == 1
    }

    /// EtherType of the *inner* protocol (after the VLAN tag).
    pub fn inner_ether_type(&self) -> u16 {
        u16::from_be_bytes([self.raw[2], self.raw[3]])
    }

    /// Full tag bytes (4 bytes).
    pub fn header(&self) -> &'a [u8] {
        &self.raw[..4]
    }

    pub fn bytes(&self) -> &'a [u8] {
        self.raw
    }

    pub fn kind(&self) -> LayerKind {
        LayerKind::Vlan
    }
}

/// MPLS label-stack entry (single 4-byte label).
///
/// A stack of multiple labels is represented as multiple
/// `MplsSlice` layers in the same `Layers`.
#[derive(Debug, Clone, Copy)]
pub struct MplsSlice<'a> {
    raw: &'a [u8],
}

impl<'a> MplsSlice<'a> {
    pub(crate) fn new(raw: &'a [u8]) -> Self {
        Self { raw }
    }

    /// 20-bit MPLS label.
    pub fn label(&self) -> u32 {
        ((self.raw[0] as u32) << 12) | ((self.raw[1] as u32) << 4) | ((self.raw[2] as u32) >> 4)
    }

    /// Traffic Class (3 bits).
    pub fn tc(&self) -> u8 {
        (self.raw[2] >> 1) & 0x07
    }

    /// Bottom-of-stack flag.
    pub fn bos(&self) -> bool {
        self.raw[2] & 0x01 == 1
    }

    /// Time-to-live.
    pub fn ttl(&self) -> u8 {
        self.raw[3]
    }

    pub fn header(&self) -> &'a [u8] {
        &self.raw[..4]
    }

    pub fn bytes(&self) -> &'a [u8] {
        self.raw
    }

    pub fn kind(&self) -> LayerKind {
        LayerKind::Mpls
    }
}

//! Tunnel-header slices: GRE + VXLAN + GTP-U.
//!
//! Each tunnel slice holds the tunnel header bytes. The inner
//! encapsulated frame is parsed into additional `Layer`s by the
//! tunnel-walking loop in [`super::Layers::from_sliced`].

use super::LayerKind;

/// GRE (Generic Routing Encapsulation) header slice.
///
/// RFC 2784 fixed 4-byte header; RFC 2890 + variants add
/// optional Checksum, Key, Sequence fields conditionally.
#[derive(Debug, Clone, Copy)]
pub struct GreSlice<'a> {
    raw: &'a [u8],
}

impl<'a> GreSlice<'a> {
    pub(crate) fn new(raw: &'a [u8]) -> Self {
        Self { raw }
    }

    /// Checksum-present bit.
    pub fn has_checksum(&self) -> bool {
        self.raw[0] & 0x80 != 0
    }

    /// Key-present bit.
    pub fn has_key(&self) -> bool {
        self.raw[0] & 0x20 != 0
    }

    /// Sequence-number-present bit.
    pub fn has_sequence(&self) -> bool {
        self.raw[0] & 0x10 != 0
    }

    /// Protocol type (EtherType of the encapsulated payload).
    pub fn protocol_type(&self) -> u16 {
        u16::from_be_bytes([self.raw[2], self.raw[3]])
    }

    /// Compute the header length in bytes given the present
    /// optional fields. 4-byte base + 4 each for checksum, key,
    /// sequence.
    pub fn header_len(&self) -> usize {
        let mut len = 4;
        if self.has_checksum() {
            len += 4;
        }
        if self.has_key() {
            len += 4;
        }
        if self.has_sequence() {
            len += 4;
        }
        len
    }

    pub fn header(&self) -> &'a [u8] {
        &self.raw[..self.header_len().min(self.raw.len())]
    }

    pub fn bytes(&self) -> &'a [u8] {
        self.raw
    }

    pub fn kind(&self) -> LayerKind {
        LayerKind::Gre
    }
}

/// VXLAN header slice (RFC 7348).
///
/// Fixed 8-byte header: 1-byte flags + 3-byte reserved +
/// 3-byte VNI (Virtual Network Identifier) + 1-byte reserved.
#[derive(Debug, Clone, Copy)]
pub struct VxlanSlice<'a> {
    raw: &'a [u8],
}

impl<'a> VxlanSlice<'a> {
    pub(crate) fn new(raw: &'a [u8]) -> Self {
        Self { raw }
    }

    /// VNI-valid flag (bit 4 of the flags byte; RFC mandates).
    pub fn valid(&self) -> bool {
        self.raw[0] & 0x08 != 0
    }

    /// 24-bit Virtual Network Identifier.
    pub fn vni(&self) -> u32 {
        ((self.raw[4] as u32) << 16) | ((self.raw[5] as u32) << 8) | (self.raw[6] as u32)
    }

    pub fn header(&self) -> &'a [u8] {
        &self.raw[..8.min(self.raw.len())]
    }

    pub fn bytes(&self) -> &'a [u8] {
        self.raw
    }

    pub fn kind(&self) -> LayerKind {
        LayerKind::Vxlan
    }
}

/// GTP-U header slice (3GPP TS 29.281).
///
/// Mandatory 8-byte header: flags + msg type + length + TEID.
/// Optional sequence + N-PDU + next-extension headers add
/// further bytes when their flag bits are set.
#[derive(Debug, Clone, Copy)]
pub struct GtpUSlice<'a> {
    raw: &'a [u8],
}

impl<'a> GtpUSlice<'a> {
    pub(crate) fn new(raw: &'a [u8]) -> Self {
        Self { raw }
    }

    /// GTP version (3 bits — should be `1` for GTP-U).
    pub fn version(&self) -> u8 {
        (self.raw[0] >> 5) & 0x07
    }

    /// Sequence-flag (S bit).
    pub fn has_sequence(&self) -> bool {
        self.raw[0] & 0x02 != 0
    }

    /// N-PDU-flag (PN bit).
    pub fn has_n_pdu(&self) -> bool {
        self.raw[0] & 0x01 != 0
    }

    /// Next-extension flag (E bit).
    pub fn has_extension(&self) -> bool {
        self.raw[0] & 0x04 != 0
    }

    /// Message type byte.
    pub fn msg_type(&self) -> u8 {
        self.raw[1]
    }

    /// 32-bit TEID (Tunnel Endpoint Identifier).
    pub fn teid(&self) -> u32 {
        u32::from_be_bytes([self.raw[4], self.raw[5], self.raw[6], self.raw[7]])
    }

    /// Header length including optional fields.
    pub fn header_len(&self) -> usize {
        let mut len = 8;
        if self.has_sequence() || self.has_n_pdu() || self.has_extension() {
            len += 4;
        }
        len
    }

    pub fn header(&self) -> &'a [u8] {
        &self.raw[..self.header_len().min(self.raw.len())]
    }

    pub fn bytes(&self) -> &'a [u8] {
        self.raw
    }

    pub fn kind(&self) -> LayerKind {
        LayerKind::GtpU
    }
}

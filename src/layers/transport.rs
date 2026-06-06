//! Transport-layer slices: TCP + UDP.
//!
//! `TcpSlice` exposes the flag byte as a typed [`TcpFlagsView`]
//! and the options array as an iterator over [`TcpOption`].

use super::LayerKind;

/// Decoded TCP flags (one bool per flag) for `match` ergonomics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpFlagsView {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
    pub ns: bool,
}

impl TcpFlagsView {
    pub(crate) fn from_bytes(flags_hi: u8, flags_lo: u8) -> Self {
        // flags_hi: low bit = NS
        // flags_lo: bit0=FIN, 1=SYN, 2=RST, 3=PSH, 4=ACK, 5=URG, 6=ECE, 7=CWR
        Self {
            ns: flags_hi & 0x01 != 0,
            fin: flags_lo & 0x01 != 0,
            syn: flags_lo & 0x02 != 0,
            rst: flags_lo & 0x04 != 0,
            psh: flags_lo & 0x08 != 0,
            ack: flags_lo & 0x10 != 0,
            urg: flags_lo & 0x20 != 0,
            ece: flags_lo & 0x40 != 0,
            cwr: flags_lo & 0x80 != 0,
        }
    }
}

/// Parsed TCP option.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum TcpOption<'a> {
    /// End-of-options marker (kind=0).
    EndOfList,
    /// No-Op padding (kind=1).
    Nop,
    /// Maximum Segment Size (kind=2).
    Mss(u16),
    /// Window-scale factor (kind=3).
    WindowScale(u8),
    /// SACK-permitted (kind=4).
    SackPermitted,
    /// Selective ACK blocks (kind=5).
    Sack(&'a [u8]),
    /// Timestamps (kind=8).
    Timestamp { tsval: u32, tsecr: u32 },
    /// Other option (kind, data — data excludes the kind + length bytes).
    Unknown { kind: u8, data: &'a [u8] },
}

/// TCP header slice. Bytes are borrowed from the original frame.
#[derive(Debug, Clone, Copy)]
pub struct TcpSlice<'a> {
    raw: &'a [u8],
    /// Total header length in bytes (5..=15 × 4).
    header_len: usize,
}

impl<'a> TcpSlice<'a> {
    pub(crate) fn new(raw: &'a [u8], header_len: usize) -> Self {
        Self { raw, header_len }
    }

    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes([self.raw[0], self.raw[1]])
    }

    pub fn dst_port(&self) -> u16 {
        u16::from_be_bytes([self.raw[2], self.raw[3]])
    }

    pub fn seq(&self) -> u32 {
        u32::from_be_bytes([self.raw[4], self.raw[5], self.raw[6], self.raw[7]])
    }

    pub fn ack(&self) -> u32 {
        u32::from_be_bytes([self.raw[8], self.raw[9], self.raw[10], self.raw[11]])
    }

    /// Data Offset (header length in 32-bit words).
    pub fn data_offset(&self) -> u8 {
        (self.raw[12] >> 4) & 0x0F
    }

    pub fn flags(&self) -> TcpFlagsView {
        TcpFlagsView::from_bytes(self.raw[12], self.raw[13])
    }

    pub fn window(&self) -> u16 {
        u16::from_be_bytes([self.raw[14], self.raw[15]])
    }

    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.raw[16], self.raw[17]])
    }

    pub fn urgent_pointer(&self) -> u16 {
        u16::from_be_bytes([self.raw[18], self.raw[19]])
    }

    pub fn header(&self) -> &'a [u8] {
        &self.raw[..self.header_len]
    }

    /// TCP payload (`raw[header_len..]`).
    pub fn payload(&self) -> &'a [u8] {
        &self.raw[self.header_len..]
    }

    /// Iterate parsed TCP options. Stops cleanly on a malformed
    /// length byte.
    pub fn options(&self) -> TcpOptionsIter<'a> {
        // Options live between byte 20 and `header_len`.
        let raw = if self.header_len > 20 {
            &self.raw[20..self.header_len]
        } else {
            &[][..]
        };
        TcpOptionsIter { raw }
    }

    pub fn bytes(&self) -> &'a [u8] {
        self.raw
    }

    pub fn kind(&self) -> LayerKind {
        LayerKind::Tcp
    }
}

/// Iterator over parsed TCP options.
#[derive(Debug, Clone)]
pub struct TcpOptionsIter<'a> {
    raw: &'a [u8],
}

impl<'a> Iterator for TcpOptionsIter<'a> {
    type Item = TcpOption<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.raw.is_empty() {
            return None;
        }
        let kind = self.raw[0];
        match kind {
            0 => {
                self.raw = &[];
                Some(TcpOption::EndOfList)
            }
            1 => {
                self.raw = &self.raw[1..];
                Some(TcpOption::Nop)
            }
            _ => {
                if self.raw.len() < 2 {
                    self.raw = &[];
                    return None;
                }
                let len = self.raw[1] as usize;
                if len < 2 || len > self.raw.len() {
                    self.raw = &[];
                    return None;
                }
                let data = &self.raw[2..len];
                let opt = match (kind, data.len()) {
                    (2, 2) => TcpOption::Mss(u16::from_be_bytes([data[0], data[1]])),
                    (3, 1) => TcpOption::WindowScale(data[0]),
                    (4, 0) => TcpOption::SackPermitted,
                    (5, _) => TcpOption::Sack(data),
                    (8, 8) => TcpOption::Timestamp {
                        tsval: u32::from_be_bytes([data[0], data[1], data[2], data[3]]),
                        tsecr: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
                    },
                    _ => TcpOption::Unknown { kind, data },
                };
                self.raw = &self.raw[len..];
                Some(opt)
            }
        }
    }
}

/// UDP header slice.
#[derive(Debug, Clone, Copy)]
pub struct UdpSlice<'a> {
    raw: &'a [u8],
}

impl<'a> UdpSlice<'a> {
    pub(crate) fn new(raw: &'a [u8]) -> Self {
        Self { raw }
    }

    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes([self.raw[0], self.raw[1]])
    }

    pub fn dst_port(&self) -> u16 {
        u16::from_be_bytes([self.raw[2], self.raw[3]])
    }

    /// Total length (header + payload).
    pub fn length(&self) -> u16 {
        u16::from_be_bytes([self.raw[4], self.raw[5]])
    }

    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.raw[6], self.raw[7]])
    }

    pub fn header(&self) -> &'a [u8] {
        &self.raw[..8]
    }

    /// UDP payload (`raw[8..]`).
    pub fn payload(&self) -> &'a [u8] {
        &self.raw[8..]
    }

    pub fn bytes(&self) -> &'a [u8] {
        self.raw
    }

    pub fn kind(&self) -> LayerKind {
        LayerKind::Udp
    }
}

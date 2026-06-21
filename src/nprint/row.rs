//! [`NPrintRow`] — one ternary header-bit vector per packet.

use crate::layers::{EthernetSlice, Ipv4Slice, Layers, TcpSlice, UdpSlice};

/// Bit-widths of each fixed region (one per nPrint convention).
pub const ETH_BITS: usize = 14 * 8; // 112
pub const IPV4_BITS: usize = 20 * 8; // 160 (base header only)
pub const TCP_BITS: usize = 20 * 8; // 160 (base header only)
pub const UDP_BITS: usize = 8 * 8; // 64

/// Compute the total number of bits per row given the config
/// flags.
pub fn bits_per_row(eth: bool, ipv4: bool, tcp: bool, udp: bool) -> usize {
    let mut n = 0;
    if eth {
        n += ETH_BITS;
    }
    if ipv4 {
        n += IPV4_BITS;
    }
    if tcp {
        n += TCP_BITS;
    }
    if udp {
        n += UDP_BITS;
    }
    n
}

/// One nPrint row — ternary per-bit encoding of one packet's
/// headers.
///
/// `-1` = absent, `0` = bit clear, `1` = bit set. Width is
/// fixed by the parent matrix's [`super::NPrintConfig`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct NPrintRow {
    /// Ternary bits, MSB-first within each byte of each header
    /// region (Eth → IPv4 → TCP → UDP, in that order, when
    /// enabled by the config).
    pub bits: Vec<i8>,
}

impl NPrintRow {
    /// Create an all-absent row (`-1` everywhere) of the given
    /// bit width.
    pub fn absent(width: usize) -> Self {
        Self {
            bits: vec![-1; width],
        }
    }

    /// Encode one Ethernet header into the row's prefix.
    pub(crate) fn fill_ethernet(&mut self, off: usize, eth: &EthernetSlice<'_>) {
        encode_bytes(&mut self.bits, off, eth.header());
    }

    /// Encode one IPv4 base header into the row.
    pub(crate) fn fill_ipv4(&mut self, off: usize, ip: &Ipv4Slice<'_>) {
        // Encode only the 20-byte base header to keep the row
        // width fixed. If the on-wire header is < 20 bytes (a
        // malformed packet), trailing bits stay -1.
        let h = ip.header();
        let n = h.len().min(20);
        encode_bytes(&mut self.bits, off, &h[..n]);
    }

    /// Encode one TCP base header into the row.
    pub(crate) fn fill_tcp(&mut self, off: usize, tcp: &TcpSlice<'_>) {
        let h = tcp.header();
        let n = h.len().min(20);
        encode_bytes(&mut self.bits, off, &h[..n]);
    }

    /// Encode one UDP header into the row.
    pub(crate) fn fill_udp(&mut self, off: usize, udp: &UdpSlice<'_>) {
        encode_bytes(&mut self.bits, off, udp.header());
    }
}

/// Encode `src` bytes MSB-first into `dst[off..off+8*src.len()]`.
fn encode_bytes(dst: &mut [i8], off: usize, src: &[u8]) {
    for (i, byte) in src.iter().enumerate() {
        for bit in 0..8 {
            let dst_idx = off + i * 8 + bit;
            if dst_idx >= dst.len() {
                return;
            }
            // MSB first: bit 0 = top bit of byte.
            let val = (byte >> (7 - bit)) & 0x01;
            dst[dst_idx] = val as i8;
        }
    }
}

/// Drive each enabled layer from `layers` into the row.
///
/// Returns the populated row. Layers not present in the packet
/// (e.g. UDP region for a TCP packet) stay as `-1` per nPrint
/// convention.
pub(crate) fn encode_from_layers(
    layers: &Layers<'_>,
    eth: bool,
    ipv4: bool,
    tcp: bool,
    udp: bool,
) -> NPrintRow {
    let width = bits_per_row(eth, ipv4, tcp, udp);
    let mut row = NPrintRow::absent(width);
    let mut off = 0;
    if eth {
        if let Some(e) = layers.ethernet() {
            row.fill_ethernet(off, e);
        }
        off += ETH_BITS;
    }
    if ipv4 {
        if let Some(ip) = layers.ipv4() {
            row.fill_ipv4(off, ip);
        }
        off += IPV4_BITS;
    }
    if tcp {
        if let Some(t) = layers.tcp() {
            row.fill_tcp(off, t);
        }
        off += TCP_BITS;
    }
    if udp {
        if let Some(u) = layers.udp() {
            row.fill_udp(off, u);
        }
        let _ = off; // silence unused on last-iter
    }
    row
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_row_is_all_minus_one() {
        let r = NPrintRow::absent(32);
        assert_eq!(r.bits.len(), 32);
        assert!(r.bits.iter().all(|&b| b == -1));
    }

    #[test]
    fn encode_bytes_msb_first() {
        let mut buf = vec![-1i8; 16];
        encode_bytes(&mut buf, 0, &[0b10110010]);
        assert_eq!(buf[..8], [1, 0, 1, 1, 0, 0, 1, 0]);
        // Remaining stay -1.
        assert!(buf[8..].iter().all(|&b| b == -1));
    }

    #[test]
    fn encode_bytes_truncates_at_dst_end() {
        let mut buf = vec![-1i8; 4];
        encode_bytes(&mut buf, 0, &[0xFF, 0xFF]); // would need 16 bits
        // Only first 4 written.
        assert_eq!(buf, vec![1, 1, 1, 1]);
    }

    #[test]
    fn bits_per_row_sums_enabled_regions() {
        assert_eq!(bits_per_row(false, false, false, false), 0);
        assert_eq!(bits_per_row(true, false, false, false), ETH_BITS);
        assert_eq!(bits_per_row(true, true, false, false), ETH_BITS + IPV4_BITS);
        assert_eq!(
            bits_per_row(true, true, true, true),
            ETH_BITS + IPV4_BITS + TCP_BITS + UDP_BITS
        );
    }
}

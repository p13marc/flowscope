//! [`NPrintMatrix`] — bounded append-only matrix of [`NPrintRow`]s.

use super::row::{NPrintRow, bits_per_row, encode_from_layers};
use crate::PacketView;

/// Default per-flow row cap, matching the nPrint reference
/// implementation.
pub const DEFAULT_MAX_PACKETS: usize = 100;

/// Per-matrix encoder configuration. Determines which header
/// regions are encoded into each row, and the cap on packets per
/// flow.
///
/// `Default::default()` enables Ethernet + IPv4 + TCP + UDP with
/// the default 100-packet cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct NPrintConfig {
    pub include_ethernet: bool,
    pub include_ipv4: bool,
    pub include_tcp: bool,
    pub include_udp: bool,
    pub max_packets: usize,
}

impl Default for NPrintConfig {
    fn default() -> Self {
        Self {
            include_ethernet: true,
            include_ipv4: true,
            include_tcp: true,
            include_udp: true,
            max_packets: DEFAULT_MAX_PACKETS,
        }
    }
}

impl NPrintConfig {
    /// Bit width of each row produced by a matrix built with
    /// this config.
    pub fn row_width(&self) -> usize {
        bits_per_row(
            self.include_ethernet,
            self.include_ipv4,
            self.include_tcp,
            self.include_udp,
        )
    }
}

/// Append-only bounded matrix of nPrint rows for a single flow.
///
/// `push_view` decodes the packet's layers and appends one row.
/// Returns `false` once `max_packets` is reached so callers can
/// skip further work.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct NPrintMatrix {
    config: NPrintConfig,
    rows: Vec<NPrintRow>,
}

impl NPrintMatrix {
    /// Construct an empty matrix with the given config.
    pub fn new(config: NPrintConfig) -> Self {
        Self {
            config,
            rows: Vec::new(),
        }
    }

    /// Construct a default-config matrix (Eth + IPv4 + TCP + UDP,
    /// 100-packet cap).
    pub fn with_default_config() -> Self {
        Self::new(NPrintConfig::default())
    }

    /// The encoder config in use.
    pub fn config(&self) -> &NPrintConfig {
        &self.config
    }

    /// Decoded rows in observation order.
    pub fn rows(&self) -> &[NPrintRow] {
        &self.rows
    }

    /// Number of rows recorded so far.
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// `true` when no packets have been encoded yet.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// `true` if `max_packets` has been reached.
    pub fn is_full(&self) -> bool {
        self.rows.len() >= self.config.max_packets
    }

    /// Append an all-absent row (no decode). Mostly useful for
    /// padding to a fixed row count downstream.
    pub fn push_absent(&mut self) -> bool {
        if self.is_full() {
            return false;
        }
        self.rows.push(NPrintRow::absent(self.config.row_width()));
        true
    }

    /// Decode the packet's layers and append one row.
    ///
    /// Returns `true` when a row was appended, `false` when the
    /// matrix is full or the layer parse fails (the row count is
    /// unchanged on a parse failure — nothing is pushed).
    pub fn push_view(&mut self, view: &PacketView<'_>) -> bool {
        if self.is_full() {
            return false;
        }
        let Ok(layers) = view.layers() else {
            return false;
        };
        let row = encode_from_layers(
            &layers,
            self.config.include_ethernet,
            self.config.include_ipv4,
            self.config.include_tcp,
            self.config.include_udp,
        );
        self.rows.push(row);
        true
    }

    /// Drop all rows. Config is retained.
    pub fn clear(&mut self) {
        self.rows.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Timestamp;

    /// Build a minimal Eth + IPv4 + TCP frame (54 bytes).
    fn make_frame_tcp(src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut f = Vec::new();
        // Eth: dst, src, ethertype 0x0800.
        f.extend_from_slice(&[0xAA; 6]);
        f.extend_from_slice(&[0xBB; 6]);
        f.extend_from_slice(&[0x08, 0x00]);
        // IPv4: version+ihl, dscp+ecn, total_length, id, frag,
        // ttl, proto, csum, src, dst.
        let ipv4 = [
            0x45, 0x00, 0x00, 0x28, // ver+ihl, dscp+ecn, total
            0x00, 0x01, 0x40, 0x00, // id, flags+frag
            0x40, 0x06, 0x00, 0x00, // ttl, proto=TCP, csum=0
            10, 0, 0, 1, // src
            10, 0, 0, 2, // dst
        ];
        f.extend_from_slice(&ipv4);
        // TCP: src/dst port, seq, ack, off+flags, window, csum,
        // urg.
        let mut tcp = vec![];
        tcp.extend_from_slice(&src_port.to_be_bytes());
        tcp.extend_from_slice(&dst_port.to_be_bytes());
        tcp.extend_from_slice(&[0, 0, 0, 0]); // seq
        tcp.extend_from_slice(&[0, 0, 0, 0]); // ack
        tcp.extend_from_slice(&[0x50, 0x02, 0x71, 0x10]); // off=5, syn, window
        tcp.extend_from_slice(&[0, 0, 0, 0]); // csum, urg
        f.extend_from_slice(&tcp);
        f
    }

    #[test]
    fn default_config_includes_all_layers() {
        let c = NPrintConfig::default();
        assert_eq!(c.row_width(), 112 + 160 + 160 + 64);
        assert_eq!(c.max_packets, 100);
    }

    #[test]
    fn push_view_appends_row_for_tcp_packet() {
        let frame = make_frame_tcp(443, 12345);
        let view = PacketView::new(&frame, Timestamp::default());
        let mut m = NPrintMatrix::with_default_config();
        assert!(m.push_view(&view));
        assert_eq!(m.len(), 1);
        let row = &m.rows()[0];
        assert_eq!(row.bits.len(), 112 + 160 + 160 + 64);

        // Ethernet dst byte 0 (0xAA = 10101010) is bits 0..8.
        use crate::nprint::NPrintBit::{One, Zero};
        assert_eq!(
            &row.bits[0..8],
            &[One, Zero, One, Zero, One, Zero, One, Zero]
        );

        // UDP region is all Absent (no UDP in this packet).
        let udp_off = 112 + 160 + 160;
        assert!(
            row.bits[udp_off..]
                .iter()
                .all(|b| *b == crate::nprint::NPrintBit::Absent)
        );
    }

    #[test]
    fn max_packets_caps_growth() {
        let cfg = NPrintConfig {
            max_packets: 3,
            ..NPrintConfig::default()
        };
        let mut m = NPrintMatrix::new(cfg);
        let frame = make_frame_tcp(80, 1234);
        let view = PacketView::new(&frame, Timestamp::default());
        for _ in 0..5 {
            m.push_view(&view);
        }
        assert_eq!(m.len(), 3);
        assert!(m.is_full());
        assert!(!m.push_view(&view));
    }

    #[test]
    fn ipv4_only_config_has_shorter_row() {
        let cfg = NPrintConfig {
            include_ethernet: false,
            include_ipv4: true,
            include_tcp: false,
            include_udp: false,
            max_packets: 10,
        };
        let m = NPrintMatrix::new(cfg);
        assert_eq!(m.config().row_width(), 160);
    }

    #[test]
    fn push_absent_pads_with_absent_bits() {
        let mut m = NPrintMatrix::with_default_config();
        assert!(m.push_absent());
        assert_eq!(m.len(), 1);
        assert!(
            m.rows()[0]
                .bits
                .iter()
                .all(|b| *b == crate::nprint::NPrintBit::Absent)
        );
    }

    #[test]
    fn clear_resets_rows_only() {
        let mut m = NPrintMatrix::with_default_config();
        m.push_absent();
        m.push_absent();
        m.clear();
        assert!(m.is_empty());
        assert_eq!(m.config().max_packets, 100);
    }

    #[test]
    fn push_view_fails_on_layer_parse_error() {
        // 4-byte frame: too short to parse as Ethernet.
        let view = PacketView::new(&[0u8, 0, 0, 0], Timestamp::default());
        let mut m = NPrintMatrix::with_default_config();
        assert!(!m.push_view(&view));
        assert_eq!(m.len(), 0);
    }
}

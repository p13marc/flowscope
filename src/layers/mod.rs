//! `flowscope::layers` — per-packet layered field access.
//!
//! [`Layers`] is a zero-copy, eagerly-parsed view of a frame.
//! Built atop [`etherparse::SlicedPacket`] with flowscope-shaped
//! slice types for ergonomic access. Two surfaces:
//!
//! 1. **Direct accessors** ([`Layers::tcp`], [`Layers::ipv4`],
//!    [`Layers::vlan`], …) — return the first layer of that kind.
//! 2. **Dynamic walk** ([`Layers::iter`], [`Layers::find`],
//!    [`Layers::find_all`]) — iterate or look up by
//!    [`LayerKind`].
//!
//! # Coverage (0.9.0)
//!
//! - **L2**: Ethernet II, 802.1Q VLAN.
//! - **L3**: IPv4, IPv6 (40-byte fixed header; extension headers
//!   are not parsed but `next_header` is exposed).
//! - **L4**: TCP (with options iterator), UDP.
//!
//! Out of scope for this cut (planned follow-ups):
//! ARP, MPLS, ICMPv4/v6 slices, GRE/VXLAN/GTP-U tunnel walking.
//! Tunnel headers are not followed yet — the L4 view stops at the
//! outermost transport.
//!
//! # Quick start
//!
//! ```no_run
//! use flowscope::PacketView;
//! use flowscope::layers::LayerKind;
//!
//! # fn ex(pv: PacketView<'_>) -> flowscope::Result<()> {
//! let layers = pv.layers()?;
//!
//! // Direct accessors — the common case.
//! if let Some(tcp)  = layers.tcp()  { println!("seq={}", tcp.seq()); }
//! if let Some(vlan) = layers.vlan() { println!("vid={}", vlan.vid()); }
//!
//! // Dynamic walk — "show me everything".
//! for layer in layers.iter() {
//!     println!("{} ({}B)", layer.kind(), layer.bytes().len());
//! }
//!
//! // First IPv4 layer.
//! if let Some(ip) = layers.find(LayerKind::Ipv4) {
//!     println!("kind = {}", ip.kind());
//! }
//! # Ok(()) }
//! ```

mod eth;
mod ip;
mod kind;
mod transport;

pub use eth::{EthernetSlice, VlanSlice};
pub use ip::{Ipv4Slice, Ipv6Slice};
pub use kind::LayerKind;
pub use transport::{TcpFlagsView, TcpOption, TcpOptionsIter, TcpSlice, UdpSlice};

use crate::error::{Error, Module};
use smallvec::SmallVec;

/// One parsed layer of a packet.
///
/// Layers are stored in outer-to-inner order in [`Layers`]; iterate
/// via [`Layers::iter`] to walk the stack.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum Layer<'a> {
    Ethernet(EthernetSlice<'a>),
    Vlan(VlanSlice<'a>),
    Ipv4(Ipv4Slice<'a>),
    Ipv6(Ipv6Slice<'a>),
    Tcp(TcpSlice<'a>),
    Udp(UdpSlice<'a>),
    /// Unparsed bytes after the last recognised header.
    Payload(&'a [u8]),
}

impl<'a> Layer<'a> {
    /// Discriminant for this layer.
    pub fn kind(&self) -> LayerKind {
        match self {
            Layer::Ethernet(_) => LayerKind::Ethernet,
            Layer::Vlan(_) => LayerKind::Vlan,
            Layer::Ipv4(_) => LayerKind::Ipv4,
            Layer::Ipv6(_) => LayerKind::Ipv6,
            Layer::Tcp(_) => LayerKind::Tcp,
            Layer::Udp(_) => LayerKind::Udp,
            Layer::Payload(_) => LayerKind::Payload,
        }
    }

    /// Header + everything after it that this layer points at.
    pub fn bytes(&self) -> &'a [u8] {
        match self {
            Layer::Ethernet(e) => e.bytes(),
            Layer::Vlan(v) => v.bytes(),
            Layer::Ipv4(ip) => ip.bytes(),
            Layer::Ipv6(ip) => ip.bytes(),
            Layer::Tcp(t) => t.bytes(),
            Layer::Udp(u) => u.bytes(),
            Layer::Payload(p) => p,
        }
    }
}

/// Parsed view of a packet's layers, outer to inner.
///
/// Constructed via [`Layers::parse_ethernet`] (frame with Ethernet
/// at the start) or [`Layers::parse_ip`] (raw IPv4/IPv6 datagram).
/// `PacketView::layers()` is the convenient entry point.
#[derive(Debug, Clone)]
pub struct Layers<'a> {
    /// 0..6 layers inline; 7+ heap-allocates. Tunnel-heavy
    /// pipelines would benefit from a larger inline buffer; the
    /// six-layer default covers ~99 % of frames.
    stack: SmallVec<[Layer<'a>; 6]>,
    payload: &'a [u8],
}

impl<'a> Layers<'a> {
    /// Parse an Ethernet frame.
    pub fn parse_ethernet(frame: &'a [u8]) -> crate::Result<Self> {
        let sp = etherparse::SlicedPacket::from_ethernet(frame)
            .map_err(|e| Error::parse_with(Module::Layers, "ethernet parse failed", e))?;
        Ok(Self::from_sliced(sp, frame))
    }

    /// Parse a raw IP datagram (no L2 prefix).
    pub fn parse_ip(frame: &'a [u8]) -> crate::Result<Self> {
        let sp = etherparse::SlicedPacket::from_ip(frame)
            .map_err(|e| Error::parse_with(Module::Layers, "ip parse failed", e))?;
        Ok(Self::from_sliced(sp, frame))
    }

    fn from_sliced(sp: etherparse::SlicedPacket<'a>, frame: &'a [u8]) -> Self {
        let mut stack: SmallVec<[Layer<'a>; 6]> = SmallVec::new();

        // L2: link + (optional) VLAN.
        if let Some(etherparse::LinkSlice::Ethernet2(eth)) = &sp.link {
            stack.push(Layer::Ethernet(EthernetSlice::new(eth.slice())));
        }
        // LinuxSll / EthPayload — no Ethernet II header to expose.

        if let Some(vlan) = &sp.vlan {
            match vlan {
                etherparse::VlanSlice::SingleVlan(v) => {
                    let s = v.slice();
                    if s.len() >= 4 {
                        stack.push(Layer::Vlan(VlanSlice::new(&s[..4])));
                    }
                }
                etherparse::VlanSlice::DoubleVlan(d) => {
                    // Outer + inner tags.
                    let bytes = d.slice();
                    if bytes.len() >= 8 {
                        stack.push(Layer::Vlan(VlanSlice::new(&bytes[..4])));
                        stack.push(Layer::Vlan(VlanSlice::new(&bytes[4..8])));
                    }
                }
            }
        }

        // L3 — reconstruct full slice from header().slice() + payload.
        if let Some(net) = &sp.net {
            match net {
                etherparse::NetSlice::Ipv4(v4) => {
                    let header_slice = v4.header().slice();
                    let header_len = header_slice.len();
                    if let Some(off) = byte_offset(frame, header_slice) {
                        let payload_len = v4.payload().payload.len();
                        let end = off + header_len + payload_len;
                        let bytes = &frame[off..end.min(frame.len())];
                        stack.push(Layer::Ipv4(Ipv4Slice::new(bytes, header_len)));
                    }
                }
                etherparse::NetSlice::Ipv6(v6) => {
                    let header_slice = v6.header().slice();
                    if let Some(off) = byte_offset(frame, header_slice) {
                        let payload_len = v6.payload().payload.len();
                        let end = off + 40 + payload_len;
                        let bytes = &frame[off..end.min(frame.len())];
                        stack.push(Layer::Ipv6(Ipv6Slice::new(bytes, 40)));
                    }
                }
            }
        }

        // L4.
        let mut payload: &[u8] = &[];
        if let Some(transport) = &sp.transport {
            match transport {
                etherparse::TransportSlice::Tcp(tcp) => {
                    let bytes = tcp.slice();
                    let hlen = (tcp.data_offset() as usize) * 4;
                    stack.push(Layer::Tcp(TcpSlice::new(bytes, hlen)));
                    payload = tcp.payload();
                }
                etherparse::TransportSlice::Udp(udp) => {
                    let bytes = udp.slice();
                    stack.push(Layer::Udp(UdpSlice::new(bytes)));
                    payload = udp.payload();
                }
                _ => {}
            }
        }

        if !payload.is_empty() {
            stack.push(Layer::Payload(payload));
        }

        Self { stack, payload }
    }

    /// Iterate the layer stack, outer to inner.
    pub fn iter(&self) -> impl Iterator<Item = &Layer<'a>> + '_ {
        self.stack.iter()
    }

    /// First layer matching `kind`.
    pub fn find(&self, kind: LayerKind) -> Option<&Layer<'a>> {
        self.stack.iter().find(|l| l.kind() == kind)
    }

    /// Every layer matching `kind`.
    pub fn find_all(&self, kind: LayerKind) -> impl Iterator<Item = &Layer<'a>> + '_ {
        self.stack.iter().filter(move |l| l.kind() == kind)
    }

    /// Bytes after the last recognised header.
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }

    /// Number of recognised layers (excluding the synthetic
    /// `Payload` entry).
    pub fn depth(&self) -> usize {
        self.stack
            .iter()
            .filter(|l| !matches!(l, Layer::Payload(_)))
            .count()
    }

    // ─── Direct convenience accessors ────────────────────────────

    pub fn ethernet(&self) -> Option<&EthernetSlice<'a>> {
        self.stack.iter().find_map(|l| match l {
            Layer::Ethernet(e) => Some(e),
            _ => None,
        })
    }

    pub fn vlan(&self) -> Option<&VlanSlice<'a>> {
        self.stack.iter().find_map(|l| match l {
            Layer::Vlan(v) => Some(v),
            _ => None,
        })
    }

    pub fn ipv4(&self) -> Option<&Ipv4Slice<'a>> {
        self.stack.iter().find_map(|l| match l {
            Layer::Ipv4(ip) => Some(ip),
            _ => None,
        })
    }

    pub fn ipv6(&self) -> Option<&Ipv6Slice<'a>> {
        self.stack.iter().find_map(|l| match l {
            Layer::Ipv6(ip) => Some(ip),
            _ => None,
        })
    }

    pub fn tcp(&self) -> Option<&TcpSlice<'a>> {
        self.stack.iter().find_map(|l| match l {
            Layer::Tcp(t) => Some(t),
            _ => None,
        })
    }

    pub fn udp(&self) -> Option<&UdpSlice<'a>> {
        self.stack.iter().find_map(|l| match l {
            Layer::Udp(u) => Some(u),
            _ => None,
        })
    }

    // ─── L-number group helpers ──────────────────────────────────

    /// First L2 layer (Ethernet or VLAN), outermost.
    pub fn l2(&self) -> Option<&Layer<'a>> {
        self.stack.iter().find(|l| l.kind().layer_number() == 2)
    }

    /// First L3 layer (IPv4 or IPv6).
    pub fn l3(&self) -> Option<&Layer<'a>> {
        self.stack.iter().find(|l| l.kind().layer_number() == 3)
    }

    /// First L4 layer (TCP or UDP).
    pub fn l4(&self) -> Option<&Layer<'a>> {
        self.stack.iter().find(|l| l.kind().layer_number() == 4)
    }
}

/// Compute the byte offset of `inner` inside `outer`, if `inner` is
/// fully contained within `outer`'s allocation.
fn byte_offset(outer: &[u8], inner: &[u8]) -> Option<usize> {
    let outer_start = outer.as_ptr() as usize;
    let inner_start = inner.as_ptr() as usize;
    let outer_end = outer_start.checked_add(outer.len())?;
    let inner_end = inner_start.checked_add(inner.len())?;
    if inner_start < outer_start || inner_end > outer_end {
        return None;
    }
    Some(inner_start - outer_start)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::parse::test_frames::{ipv4_tcp, ipv4_udp, ipv6_tcp};

    #[test]
    fn parse_eth_ipv4_tcp() {
        let f = ipv4_tcp(
            [1, 2, 3, 4, 5, 6],
            [7, 8, 9, 10, 11, 12],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            12345,
            80,
            1000,
            0,
            0x02, // SYN
            b"",
        );
        let layers = Layers::parse_ethernet(&f).unwrap();
        assert_eq!(layers.depth(), 3); // eth + ipv4 + tcp

        let eth = layers.ethernet().expect("eth");
        assert_eq!(eth.source(), [1, 2, 3, 4, 5, 6]);
        assert_eq!(eth.destination(), [7, 8, 9, 10, 11, 12]);
        assert_eq!(eth.ether_type(), 0x0800);

        let ip = layers.ipv4().expect("ipv4");
        assert_eq!(ip.source().octets(), [10, 0, 0, 1]);
        assert_eq!(ip.destination().octets(), [10, 0, 0, 2]);
        assert_eq!(ip.protocol(), 6);

        let tcp = layers.tcp().expect("tcp");
        assert_eq!(tcp.src_port(), 12345);
        assert_eq!(tcp.dst_port(), 80);
        assert!(tcp.flags().syn);
        assert_eq!(tcp.seq(), 1000);
    }

    #[test]
    fn parse_eth_ipv4_udp() {
        let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 5353, 53, b"hi");
        let layers = Layers::parse_ethernet(&f).unwrap();
        assert!(layers.udp().is_some());
        assert!(layers.tcp().is_none());
        let udp = layers.udp().unwrap();
        assert_eq!(udp.src_port(), 5353);
        assert_eq!(udp.dst_port(), 53);
        assert_eq!(udp.payload(), b"hi");
    }

    #[test]
    fn parse_eth_ipv6_tcp() {
        let f = ipv6_tcp(
            [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            12345,
            443,
            500,
            0x12, // SYN+ACK
            b"",
        );
        let layers = Layers::parse_ethernet(&f).unwrap();
        assert!(layers.ipv6().is_some());
        assert!(layers.ipv4().is_none());
        let tcp = layers.tcp().unwrap();
        let flags = tcp.flags();
        assert!(flags.syn);
        assert!(flags.ack);
    }

    #[test]
    fn iter_outer_to_inner() {
        let f = ipv4_tcp([0; 6], [0; 6], [1, 2, 3, 4], [5, 6, 7, 8], 10, 20, 0, 0, 0, b"x");
        let layers = Layers::parse_ethernet(&f).unwrap();
        let kinds: Vec<LayerKind> = layers.iter().map(|l| l.kind()).collect();
        assert_eq!(
            kinds,
            vec![
                LayerKind::Ethernet,
                LayerKind::Ipv4,
                LayerKind::Tcp,
                LayerKind::Payload,
            ]
        );
    }

    #[test]
    fn find_returns_first_match() {
        let f = ipv4_tcp([0; 6], [0; 6], [1, 2, 3, 4], [5, 6, 7, 8], 10, 20, 0, 0, 0, b"");
        let layers = Layers::parse_ethernet(&f).unwrap();
        let ip = layers.find(LayerKind::Ipv4).unwrap();
        assert!(matches!(ip, Layer::Ipv4(_)));
    }

    #[test]
    fn find_all_iterates_matching() {
        let f = ipv4_tcp([0; 6], [0; 6], [1, 2, 3, 4], [5, 6, 7, 8], 10, 20, 0, 0, 0, b"");
        let layers = Layers::parse_ethernet(&f).unwrap();
        let count = layers.find_all(LayerKind::Ipv4).count();
        assert_eq!(count, 1);
    }

    #[test]
    fn l_group_helpers() {
        let f = ipv4_tcp([0; 6], [0; 6], [1, 2, 3, 4], [5, 6, 7, 8], 10, 20, 0, 0, 0, b"");
        let layers = Layers::parse_ethernet(&f).unwrap();
        assert!(matches!(layers.l2().unwrap(), Layer::Ethernet(_)));
        assert!(matches!(layers.l3().unwrap(), Layer::Ipv4(_)));
        assert!(matches!(layers.l4().unwrap(), Layer::Tcp(_)));
    }

    #[test]
    fn truncated_frame_returns_err() {
        let r = Layers::parse_ethernet(&[0u8; 4]);
        let err = r.err().unwrap();
        assert_eq!(err.module(), crate::Module::Layers);
    }

    #[test]
    fn payload_accessor_on_tcp_payload() {
        let payload = b"hello-flowscope";
        let f = ipv4_tcp([0; 6], [0; 6], [1, 2, 3, 4], [5, 6, 7, 8], 10, 20, 0, 0, 0, payload);
        let layers = Layers::parse_ethernet(&f).unwrap();
        assert_eq!(layers.payload(), payload);
        assert_eq!(layers.tcp().unwrap().payload(), payload);
    }
}

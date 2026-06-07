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
mod fast;
mod ip;
mod kind;
mod transport;
mod tunnel;

pub use eth::{EthernetSlice, MplsSlice, VlanSlice};
pub use fast::{LayerParser, LayerStack};
pub use ip::{ArpSlice, Ipv4Slice, Ipv6Slice};
pub use kind::LayerKind;
pub use transport::{
    Icmpv4Slice, Icmpv6Slice, TcpFlagsView, TcpOption, TcpOptionsIter, TcpSlice, UdpSlice,
};
pub use tunnel::{GreSlice, GtpUSlice, VxlanSlice};

use crate::error::{Error, Module};
use smallvec::SmallVec;

/// UDP destination port that triggers VXLAN tunnel parsing.
const VXLAN_UDP_PORT: u16 = 4789;
/// UDP destination port that triggers GTP-U tunnel parsing.
const GTPU_UDP_PORT: u16 = 2152;
/// IP protocol numbers we recognise for tunnel walking.
const IP_PROTO_GRE: u8 = 47;
const IP_PROTO_IPV4: u8 = 4;
const IP_PROTO_IPV6: u8 = 41;

/// One parsed layer of a packet.
///
/// Layers are stored in outer-to-inner order in [`Layers`]; iterate
/// via [`Layers::iter`] to walk the stack.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum Layer<'a> {
    Ethernet(EthernetSlice<'a>),
    Vlan(VlanSlice<'a>),
    Mpls(MplsSlice<'a>),
    Ipv4(Ipv4Slice<'a>),
    Ipv6(Ipv6Slice<'a>),
    Arp(ArpSlice<'a>),
    Tcp(TcpSlice<'a>),
    Udp(UdpSlice<'a>),
    Icmpv4(Icmpv4Slice<'a>),
    Icmpv6(Icmpv6Slice<'a>),
    Gre(GreSlice<'a>),
    Vxlan(VxlanSlice<'a>),
    GtpU(GtpUSlice<'a>),
    /// Unparsed bytes after the last recognised header.
    Payload(&'a [u8]),
}

impl<'a> Layer<'a> {
    /// Discriminant for this layer.
    pub fn kind(&self) -> LayerKind {
        match self {
            Layer::Ethernet(_) => LayerKind::Ethernet,
            Layer::Vlan(_) => LayerKind::Vlan,
            Layer::Mpls(_) => LayerKind::Mpls,
            Layer::Ipv4(_) => LayerKind::Ipv4,
            Layer::Ipv6(_) => LayerKind::Ipv6,
            Layer::Arp(_) => LayerKind::Arp,
            Layer::Tcp(_) => LayerKind::Tcp,
            Layer::Udp(_) => LayerKind::Udp,
            Layer::Icmpv4(_) => LayerKind::Icmpv4,
            Layer::Icmpv6(_) => LayerKind::Icmpv6,
            Layer::Gre(_) => LayerKind::Gre,
            Layer::Vxlan(_) => LayerKind::Vxlan,
            Layer::GtpU(_) => LayerKind::GtpU,
            Layer::Payload(_) => LayerKind::Payload,
        }
    }

    /// Header + everything after it that this layer points at.
    pub fn bytes(&self) -> &'a [u8] {
        match self {
            Layer::Ethernet(e) => e.bytes(),
            Layer::Vlan(v) => v.bytes(),
            Layer::Mpls(m) => m.bytes(),
            Layer::Ipv4(ip) => ip.bytes(),
            Layer::Ipv6(ip) => ip.bytes(),
            Layer::Arp(a) => a.bytes(),
            Layer::Tcp(t) => t.bytes(),
            Layer::Udp(u) => u.bytes(),
            Layer::Icmpv4(i) => i.bytes(),
            Layer::Icmpv6(i) => i.bytes(),
            Layer::Gre(g) => g.bytes(),
            Layer::Vxlan(v) => v.bytes(),
            Layer::GtpU(g) => g.bytes(),
            Layer::Payload(p) => p,
        }
    }
}

impl<'a> std::fmt::Display for Layer<'a> {
    /// One-line summary with the layer kind, then a few defining
    /// fields. Format is stable and grep-friendly:
    /// `kind k1=v1 k2=v2 …`. New in 0.10.0.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Layer::Ethernet(e) => write!(
                f,
                "ethernet src={} dst={} type=0x{:04x}",
                format_mac(e.source()),
                format_mac(e.destination()),
                e.ether_type(),
            ),
            Layer::Vlan(v) => write!(
                f,
                "vlan vid={} pri={} type=0x{:04x}",
                v.vid(),
                v.priority(),
                v.inner_ether_type(),
            ),
            Layer::Mpls(m) => write!(
                f,
                "mpls label={} tc={} bos={} ttl={}",
                m.label(),
                m.tc(),
                m.bos() as u8,
                m.ttl(),
            ),
            Layer::Ipv4(ip) => write!(
                f,
                "ipv4 src={} dst={} proto={} ttl={}",
                ip.source(),
                ip.destination(),
                ip.protocol(),
                ip.ttl(),
            ),
            Layer::Ipv6(ip) => write!(
                f,
                "ipv6 src={} dst={} next_header={} hop_limit={}",
                ip.source(),
                ip.destination(),
                ip.next_header(),
                ip.hop_limit(),
            ),
            Layer::Arp(a) => write!(f, "arp oper={} htype={}", a.oper(), a.htype()),
            Layer::Tcp(t) => {
                let fl = t.flags();
                let mut flags = String::new();
                if fl.syn {
                    flags.push('S');
                }
                if fl.ack {
                    flags.push('A');
                }
                if fl.fin {
                    flags.push('F');
                }
                if fl.rst {
                    flags.push('R');
                }
                if fl.psh {
                    flags.push('P');
                }
                if fl.urg {
                    flags.push('U');
                }
                if fl.ece {
                    flags.push('E');
                }
                if fl.cwr {
                    flags.push('C');
                }
                if flags.is_empty() {
                    flags.push('-');
                }
                write!(
                    f,
                    "tcp src_port={} dst_port={} seq={} ack={} flags=[{}]",
                    t.src_port(),
                    t.dst_port(),
                    t.seq(),
                    t.ack(),
                    flags,
                )
            }
            Layer::Udp(u) => write!(
                f,
                "udp src_port={} dst_port={} length={}",
                u.src_port(),
                u.dst_port(),
                u.length(),
            ),
            Layer::Icmpv4(i) => write!(f, "icmpv4 type={} code={}", i.icmp_type(), i.code()),
            Layer::Icmpv6(i) => write!(f, "icmpv6 type={} code={}", i.icmp_type(), i.code()),
            Layer::Gre(g) => write!(
                f,
                "gre proto_type=0x{:04x} header_len={}",
                g.protocol_type(),
                g.header_len(),
            ),
            Layer::Vxlan(v) => write!(f, "vxlan vni={}", v.vni()),
            Layer::GtpU(g) => write!(f, "gtpu teid={} msg_type={}", g.teid(), g.msg_type()),
            Layer::Payload(p) => write!(f, "payload {}B", p.len()),
        }
    }
}

fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Parsed view of a packet's layers, outer to inner.
///
/// Constructed via [`Layers::parse_ethernet`] (frame with Ethernet
/// at the start) or [`Layers::parse_ip`] (raw IPv4/IPv6 datagram).
/// `PacketView::layers()` is the convenient entry point.
#[derive(Debug, Clone)]
pub struct Layers<'a> {
    /// 0..8 layers inline; 9+ heap-allocates. Eight handles the
    /// typical tunnel case (outer Eth+IP+UDP+VXLAN + inner
    /// Eth+IP+TCP+Payload = 8) without spilling.
    stack: SmallVec<[Layer<'a>; 8]>,
    payload: &'a [u8],
    /// `true` if a tunnel inner-payload re-parse failed
    /// partway through. The outer layers stay accessible.
    truncated: bool,
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
        let mut stack: SmallVec<[Layer<'a>; 8]> = SmallVec::new();
        let mut truncated = false;

        // L2: link + (optional) VLAN.
        let mut outer_ether_type: u16 = 0;
        if let Some(etherparse::LinkSlice::Ethernet2(eth)) = &sp.link {
            let eth_slice = EthernetSlice::new(eth.slice());
            outer_ether_type = eth_slice.ether_type();
            stack.push(Layer::Ethernet(eth_slice));
        }
        // LinuxSll / EthPayload — no Ethernet II header to expose.

        if let Some(vlan) = &sp.vlan {
            match vlan {
                etherparse::VlanSlice::SingleVlan(v) => {
                    let s = v.slice();
                    if s.len() >= 4 {
                        let slice = VlanSlice::new(&s[..4]);
                        outer_ether_type = slice.inner_ether_type();
                        stack.push(Layer::Vlan(slice));
                    }
                }
                etherparse::VlanSlice::DoubleVlan(d) => {
                    let bytes = d.slice();
                    if bytes.len() >= 8 {
                        stack.push(Layer::Vlan(VlanSlice::new(&bytes[..4])));
                        let inner = VlanSlice::new(&bytes[4..8]);
                        outer_ether_type = inner.inner_ether_type();
                        stack.push(Layer::Vlan(inner));
                    }
                }
            }
        }

        // ARP detection — etherparse stops at the link layer for
        // ARP frames, so detect via outer EtherType and synthesise
        // an ArpSlice. (etherparse 0.16 doesn't expose ARP.)
        if outer_ether_type == 0x0806
            && let Some(eth_layer) = stack.iter().find_map(|l| match l {
                Layer::Ethernet(e) => Some(e),
                _ => None,
            })
        {
            let eth_bytes = eth_layer.bytes();
            if eth_bytes.len() >= 14 + 28 {
                stack.push(Layer::Arp(ArpSlice::new(&eth_bytes[14..14 + 28])));
            }
            // ARP frames have no L3/L4 stages.
            let payload: &[u8] = &[];
            return Self {
                stack,
                payload,
                truncated,
            };
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

        // L4 + tunnel detection.
        let mut payload: &[u8] = &[];
        let mut tunnel_inner: Option<TunnelInner<'a>> = None;
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
                    let dst = udp.destination_port();
                    let udp_payload = udp.payload();
                    stack.push(Layer::Udp(UdpSlice::new(bytes)));
                    payload = udp_payload;
                    // Tunnel detection on UDP dst-port.
                    if dst == VXLAN_UDP_PORT && udp_payload.len() >= 8 {
                        let vx = VxlanSlice::new(&udp_payload[..8]);
                        stack.push(Layer::Vxlan(vx));
                        tunnel_inner = Some(TunnelInner::Ethernet(&udp_payload[8..]));
                    } else if dst == GTPU_UDP_PORT && udp_payload.len() >= 8 {
                        let gt = GtpUSlice::new(udp_payload);
                        let inner_off = gt.header_len();
                        if udp_payload.len() > inner_off {
                            stack.push(Layer::GtpU(gt));
                            tunnel_inner = Some(TunnelInner::Ip(&udp_payload[inner_off..]));
                        } else {
                            stack.push(Layer::GtpU(gt));
                            truncated = true;
                        }
                    }
                }
                etherparse::TransportSlice::Icmpv4(icmp) => {
                    let bytes = icmp.slice();
                    stack.push(Layer::Icmpv4(Icmpv4Slice::new(bytes)));
                    payload = icmp.payload();
                }
                etherparse::TransportSlice::Icmpv6(icmp) => {
                    let bytes = icmp.slice();
                    stack.push(Layer::Icmpv6(Icmpv6Slice::new(bytes)));
                    payload = icmp.payload();
                }
            }
        }

        // GRE / IP-in-IP detection — look at the *last* IP layer's
        // protocol byte. Re-parse via etherparse for the inner.
        if tunnel_inner.is_none()
            && let Some(last_ip) = stack.iter().rev().find_map(|l| match l {
                Layer::Ipv4(ip) => Some((ip.protocol(), ip.payload())),
                Layer::Ipv6(ip) => Some((ip.next_header(), ip.payload())),
                _ => None,
            })
        {
            let (proto, ip_payload) = last_ip;
            match proto {
                IP_PROTO_GRE if ip_payload.len() >= 4 => {
                    let gre = GreSlice::new(ip_payload);
                    let inner_off = gre.header_len();
                    if ip_payload.len() > inner_off {
                        let inner = &ip_payload[inner_off..];
                        let inner_kind = match gre.protocol_type() {
                            0x0800 | 0x86dd => TunnelInner::Ip(inner),
                            0x6558 => TunnelInner::Ethernet(inner), // Transparent Ethernet Bridging
                            _ => {
                                stack.push(Layer::Gre(gre));
                                return Self {
                                    stack,
                                    payload: inner,
                                    truncated,
                                };
                            }
                        };
                        stack.push(Layer::Gre(gre));
                        tunnel_inner = Some(inner_kind);
                    } else {
                        stack.push(Layer::Gre(gre));
                        truncated = true;
                    }
                }
                IP_PROTO_IPV4 | IP_PROTO_IPV6 if !ip_payload.is_empty() => {
                    tunnel_inner = Some(TunnelInner::Ip(ip_payload));
                }
                _ => {}
            }
        }

        // Walk the tunnel — recurse with a tunnel-aware parse on
        // the inner frame. Append its layers to ours.
        if let Some(inner) = tunnel_inner {
            let inner_layers_result = match inner {
                TunnelInner::Ethernet(b) => Layers::parse_ethernet(b),
                TunnelInner::Ip(b) => Layers::parse_ip(b),
            };
            match inner_layers_result {
                Ok(mut inner_layers) => {
                    payload = inner_layers.payload;
                    if inner_layers.truncated {
                        truncated = true;
                    }
                    // Drop the outer Payload entry that we might
                    // have appended speculatively, and append inner
                    // layers in order.
                    for layer in inner_layers.stack.drain(..) {
                        if !matches!(layer, Layer::Payload(_)) {
                            stack.push(layer);
                        }
                    }
                }
                Err(_) => {
                    truncated = true;
                }
            }
        }

        if !payload.is_empty() {
            stack.push(Layer::Payload(payload));
        }

        Self {
            stack,
            payload,
            truncated,
        }
    }

    /// `true` if a tunnel's inner-payload re-parse failed
    /// partway through. The outer layers stay accessible.
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// `true` if this frame includes a recognised tunnel
    /// (VXLAN, GTP-U, GRE, IP-in-IP).
    pub fn has_tunnel(&self) -> bool {
        self.stack
            .iter()
            .any(|l| matches!(l, Layer::Gre(_) | Layer::Vxlan(_) | Layer::GtpU(_)))
            || self
                .stack
                .iter()
                .filter(|l| matches!(l, Layer::Ipv4(_) | Layer::Ipv6(_)))
                .count()
                >= 2
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

    pub fn arp(&self) -> Option<&ArpSlice<'a>> {
        self.stack.iter().find_map(|l| match l {
            Layer::Arp(a) => Some(a),
            _ => None,
        })
    }

    pub fn mpls(&self) -> Option<&MplsSlice<'a>> {
        self.stack.iter().find_map(|l| match l {
            Layer::Mpls(m) => Some(m),
            _ => None,
        })
    }

    pub fn icmpv4(&self) -> Option<&Icmpv4Slice<'a>> {
        self.stack.iter().find_map(|l| match l {
            Layer::Icmpv4(i) => Some(i),
            _ => None,
        })
    }

    pub fn icmpv6(&self) -> Option<&Icmpv6Slice<'a>> {
        self.stack.iter().find_map(|l| match l {
            Layer::Icmpv6(i) => Some(i),
            _ => None,
        })
    }

    pub fn gre(&self) -> Option<&GreSlice<'a>> {
        self.stack.iter().find_map(|l| match l {
            Layer::Gre(g) => Some(g),
            _ => None,
        })
    }

    pub fn vxlan(&self) -> Option<&VxlanSlice<'a>> {
        self.stack.iter().find_map(|l| match l {
            Layer::Vxlan(v) => Some(v),
            _ => None,
        })
    }

    pub fn gtpu(&self) -> Option<&GtpUSlice<'a>> {
        self.stack.iter().find_map(|l| match l {
            Layer::GtpU(g) => Some(g),
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

/// Inner-frame kind for tunnel walking.
enum TunnelInner<'a> {
    Ethernet(&'a [u8]),
    Ip(&'a [u8]),
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
        let f = ipv4_tcp(
            [0; 6],
            [0; 6],
            [1, 2, 3, 4],
            [5, 6, 7, 8],
            10,
            20,
            0,
            0,
            0,
            b"x",
        );
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
        let f = ipv4_tcp(
            [0; 6],
            [0; 6],
            [1, 2, 3, 4],
            [5, 6, 7, 8],
            10,
            20,
            0,
            0,
            0,
            b"",
        );
        let layers = Layers::parse_ethernet(&f).unwrap();
        let ip = layers.find(LayerKind::Ipv4).unwrap();
        assert!(matches!(ip, Layer::Ipv4(_)));
    }

    #[test]
    fn find_all_iterates_matching() {
        let f = ipv4_tcp(
            [0; 6],
            [0; 6],
            [1, 2, 3, 4],
            [5, 6, 7, 8],
            10,
            20,
            0,
            0,
            0,
            b"",
        );
        let layers = Layers::parse_ethernet(&f).unwrap();
        let count = layers.find_all(LayerKind::Ipv4).count();
        assert_eq!(count, 1);
    }

    #[test]
    fn l_group_helpers() {
        let f = ipv4_tcp(
            [0; 6],
            [0; 6],
            [1, 2, 3, 4],
            [5, 6, 7, 8],
            10,
            20,
            0,
            0,
            0,
            b"",
        );
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
        let f = ipv4_tcp(
            [0; 6],
            [0; 6],
            [1, 2, 3, 4],
            [5, 6, 7, 8],
            10,
            20,
            0,
            0,
            0,
            payload,
        );
        let layers = Layers::parse_ethernet(&f).unwrap();
        assert_eq!(layers.payload(), payload);
        assert_eq!(layers.tcp().unwrap().payload(), payload);
    }
}

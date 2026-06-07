//! [`LayerParser`] + [`LayerStack`] — zero-allocation
//! per-packet parsing for high-throughput consumers.
//!
//! Mirror of gopacket's `DecodingLayerParser` pattern (the
//! dominant reference for this surface in the ecosystem). The
//! ergonomic [`super::Layers::parse_ethernet`] allocates a
//! `SmallVec` per call (~100 ns / packet, one heap alloc when
//! the inline buffer spills); this fast-path API moves the
//! storage to a caller-owned [`LayerStack`] that gets reused
//! across the packet loop with **zero per-frame allocations**.
//!
//! ```no_run
//! use flowscope::layers::{LayerParser, LayerStack, LayerKind};
//!
//! # fn ex(frames: impl IntoIterator<Item = Vec<u8>>) -> flowscope::Result<()> {
//! let parser = LayerParser::new()
//!     .only(&[LayerKind::Ipv4, LayerKind::Tcp]);  // skip everything else
//! let mut stack = LayerStack::new();
//!
//! for frame in frames {
//!     stack.reset();
//!     parser.parse_ethernet(&frame, &mut stack)?;
//!     if let Some(tcp) = stack.tcp() {
//!         let _ = tcp.seq();
//!     }
//! }
//! # Ok(()) }
//! ```
//!
//! The `only(&[LayerKind, ...])` mask tells the parser which
//! slots to populate — slots not in the mask stay `None` after
//! `parse_ethernet`. This skips work for layers the consumer
//! does not care about.

use crate::error::{Error, Module};

use super::eth::{EthernetSlice, VlanSlice};
use super::ip::{Ipv4Slice, Ipv6Slice};
use super::kind::LayerKind;
use super::transport::{TcpSlice, UdpSlice};

/// Caller-owned scratch buffer of layer slots, reused across a
/// packet loop. Call [`Self::reset`] between frames.
///
/// Each field is an `Option<…>` slot — the parser fills slots
/// it observes, leaves the rest `None`. Lifetimes elide via the
/// trait-object pattern (the slots reborrow from the frame each
/// call); use the typed accessors to retrieve a slice.
///
/// The fields are public for advanced consumers who want to
/// inspect every recognised slot at once; typical use is via
/// the typed accessors ([`Self::tcp`], [`Self::ipv4`], …).
#[derive(Debug, Default)]
pub struct LayerStack {
    eth: Option<*const u8>,
    eth_len: usize,
    vlan: Option<*const u8>,
    vlan_len: usize,
    ipv4: Option<(*const u8, usize, usize)>, // (ptr, total_len, header_len)
    ipv6: Option<(*const u8, usize, usize)>,
    tcp: Option<(*const u8, usize, usize)>,
    udp: Option<(*const u8, usize)>,
    /// Bitmask of [`LayerKind`]s actually populated this round.
    /// Encoded with [`kind_bit`].
    decoded_mask: u32,
}

// Safety: LayerStack stores raw pointers to bytes borrowed from
// the frame passed into parse_ethernet. The Send/Sync bounds
// don't apply because the slots are only used with the borrow
// scope of the parse call.
unsafe impl Send for LayerStack {}

impl LayerStack {
    /// Construct an empty stack.
    pub fn new() -> Self {
        Self::default()
    }

    /// Clear every slot back to `None`. Cheap — just resets the
    /// bitmask and zeroes the Option discriminants. Call between
    /// frames.
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    fn store_eth(&mut self, slice: &[u8]) {
        self.eth = Some(slice.as_ptr());
        self.eth_len = slice.len();
        self.decoded_mask |= kind_bit(LayerKind::Ethernet);
    }

    fn store_vlan(&mut self, slice: &[u8]) {
        self.vlan = Some(slice.as_ptr());
        self.vlan_len = slice.len();
        self.decoded_mask |= kind_bit(LayerKind::Vlan);
    }

    fn store_ipv4(&mut self, slice: &[u8], header_len: usize) {
        self.ipv4 = Some((slice.as_ptr(), slice.len(), header_len));
        self.decoded_mask |= kind_bit(LayerKind::Ipv4);
    }

    fn store_ipv6(&mut self, slice: &[u8], header_len: usize) {
        self.ipv6 = Some((slice.as_ptr(), slice.len(), header_len));
        self.decoded_mask |= kind_bit(LayerKind::Ipv6);
    }

    fn store_tcp(&mut self, slice: &[u8], header_len: usize) {
        self.tcp = Some((slice.as_ptr(), slice.len(), header_len));
        self.decoded_mask |= kind_bit(LayerKind::Tcp);
    }

    fn store_udp(&mut self, slice: &[u8]) {
        self.udp = Some((slice.as_ptr(), slice.len()));
        self.decoded_mask |= kind_bit(LayerKind::Udp);
    }

    /// Borrow the populated Ethernet slice, if any.
    ///
    /// Safety contract: lifetime tied to the most recent
    /// `parse_ethernet` call's frame argument.
    pub fn ethernet<'a>(&'a self) -> Option<EthernetSlice<'a>> {
        let ptr = self.eth?;
        let bytes = unsafe { std::slice::from_raw_parts(ptr, self.eth_len) };
        Some(EthernetSlice::new(bytes))
    }

    pub fn vlan<'a>(&'a self) -> Option<VlanSlice<'a>> {
        let ptr = self.vlan?;
        let bytes = unsafe { std::slice::from_raw_parts(ptr, self.vlan_len) };
        Some(VlanSlice::new(bytes))
    }

    pub fn ipv4<'a>(&'a self) -> Option<Ipv4Slice<'a>> {
        let (ptr, total_len, header_len) = self.ipv4?;
        let bytes = unsafe { std::slice::from_raw_parts(ptr, total_len) };
        Some(Ipv4Slice::new(bytes, header_len))
    }

    pub fn ipv6<'a>(&'a self) -> Option<Ipv6Slice<'a>> {
        let (ptr, total_len, header_len) = self.ipv6?;
        let bytes = unsafe { std::slice::from_raw_parts(ptr, total_len) };
        Some(Ipv6Slice::new(bytes, header_len))
    }

    pub fn tcp<'a>(&'a self) -> Option<TcpSlice<'a>> {
        let (ptr, total_len, header_len) = self.tcp?;
        let bytes = unsafe { std::slice::from_raw_parts(ptr, total_len) };
        Some(TcpSlice::new(bytes, header_len))
    }

    pub fn udp<'a>(&'a self) -> Option<UdpSlice<'a>> {
        let (ptr, total_len) = self.udp?;
        let bytes = unsafe { std::slice::from_raw_parts(ptr, total_len) };
        Some(UdpSlice::new(bytes))
    }

    /// `true` if `kind` was populated by the most recent
    /// `parse_*` call.
    pub fn has(&self, kind: LayerKind) -> bool {
        self.decoded_mask & kind_bit(kind) != 0
    }

    /// Number of populated slots. New in 0.10.0.
    pub fn depth(&self) -> usize {
        self.decoded_mask.count_ones() as usize
    }

    /// Iterate the [`LayerKind`]s populated by the most recent
    /// `parse_*` call, in outer-to-inner order
    /// (Ethernet → VLAN → IPv4/v6 → TCP/UDP). New in 0.10.0.
    pub fn iter_kinds(&self) -> impl Iterator<Item = LayerKind> + '_ {
        const ORDER: [LayerKind; 6] = [
            LayerKind::Ethernet,
            LayerKind::Vlan,
            LayerKind::Ipv4,
            LayerKind::Ipv6,
            LayerKind::Tcp,
            LayerKind::Udp,
        ];
        ORDER.into_iter().filter(|k| self.has(*k))
    }
}

/// Configurable zero-allocation parser.
///
/// Construct via [`Self::new`]; chain [`Self::only`] to limit
/// which slots get populated. Then call [`Self::parse_ethernet`]
/// in a hot loop, reusing the same [`LayerStack`] across frames.
#[derive(Debug, Clone)]
pub struct LayerParser {
    /// Bitmask of kinds the consumer cares about. `0` = none.
    /// Default (all-ones) means populate every recognised slot.
    target_mask: u32,
}

impl Default for LayerParser {
    fn default() -> Self {
        Self::new()
    }
}

impl LayerParser {
    /// Construct a parser that populates every recognised slot.
    pub fn new() -> Self {
        Self {
            target_mask: u32::MAX,
        }
    }

    /// Limit which slots the parser populates. Slots not in the
    /// list stay `None` after `parse_ethernet`; the parser
    /// skips the per-slot work for them when feasible.
    pub fn only(mut self, kinds: &[LayerKind]) -> Self {
        self.target_mask = kinds.iter().copied().fold(0u32, |m, k| m | kind_bit(k));
        self
    }

    /// Parse an Ethernet frame into the caller-owned `out`.
    ///
    /// Reuse the same `out` across frames after calling
    /// [`LayerStack::reset`] — no per-frame heap allocation.
    pub fn parse_ethernet(&self, frame: &[u8], out: &mut LayerStack) -> crate::Result<()> {
        let sp = etherparse::SlicedPacket::from_ethernet(frame)
            .map_err(|e| Error::parse_with(Module::Layers, "ethernet parse failed", e))?;
        self.populate(sp, out);
        Ok(())
    }

    /// Parse a raw IP datagram (no L2 prefix).
    pub fn parse_ip(&self, frame: &[u8]) -> crate::Result<LayerStack> {
        let mut stack = LayerStack::new();
        let sp = etherparse::SlicedPacket::from_ip(frame)
            .map_err(|e| Error::parse_with(Module::Layers, "ip parse failed", e))?;
        self.populate(sp, &mut stack);
        Ok(stack)
    }

    fn populate(&self, sp: etherparse::SlicedPacket<'_>, out: &mut LayerStack) {
        let want = |k: LayerKind| self.target_mask & kind_bit(k) != 0;

        if want(LayerKind::Ethernet)
            && let Some(etherparse::LinkSlice::Ethernet2(eth)) = &sp.link
        {
            out.store_eth(eth.slice());
        }

        if want(LayerKind::Vlan)
            && let Some(vlan) = &sp.vlan
        {
            let bytes = match vlan {
                etherparse::VlanSlice::SingleVlan(v) => v.slice(),
                etherparse::VlanSlice::DoubleVlan(d) => &d.slice()[..4.min(d.slice().len())],
            };
            if bytes.len() >= 4 {
                out.store_vlan(&bytes[..4]);
            }
        }

        if let Some(net) = &sp.net {
            match net {
                etherparse::NetSlice::Ipv4(v4) if want(LayerKind::Ipv4) => {
                    let header_slice = v4.header().slice();
                    let header_len = header_slice.len();
                    let payload_len = v4.payload().payload.len();
                    // Reconstruct contiguous slice from header pointer.
                    let total = header_len + payload_len;
                    let bytes =
                        unsafe { std::slice::from_raw_parts(header_slice.as_ptr(), total) };
                    out.store_ipv4(bytes, header_len);
                }
                etherparse::NetSlice::Ipv6(v6) if want(LayerKind::Ipv6) => {
                    let header_slice = v6.header().slice();
                    let payload_len = v6.payload().payload.len();
                    let total = 40 + payload_len;
                    let bytes =
                        unsafe { std::slice::from_raw_parts(header_slice.as_ptr(), total) };
                    out.store_ipv6(bytes, 40);
                }
                _ => {}
            }
        }

        if let Some(transport) = &sp.transport {
            match transport {
                etherparse::TransportSlice::Tcp(tcp) if want(LayerKind::Tcp) => {
                    let bytes = tcp.slice();
                    let hlen = (tcp.data_offset() as usize) * 4;
                    out.store_tcp(bytes, hlen);
                }
                etherparse::TransportSlice::Udp(udp) if want(LayerKind::Udp) => {
                    out.store_udp(udp.slice());
                }
                _ => {}
            }
        }
    }
}

/// Map a [`LayerKind`] to its bitmask position.
const fn kind_bit(k: LayerKind) -> u32 {
    1u32 << match k {
        LayerKind::Ethernet => 0,
        LayerKind::Vlan => 1,
        LayerKind::Mpls => 2,
        LayerKind::Ipv4 => 3,
        LayerKind::Ipv6 => 4,
        LayerKind::Arp => 5,
        LayerKind::Tcp => 6,
        LayerKind::Udp => 7,
        LayerKind::Icmpv4 => 8,
        LayerKind::Icmpv6 => 9,
        LayerKind::Gre => 10,
        LayerKind::Vxlan => 11,
        LayerKind::GtpU => 12,
        LayerKind::Payload => 13,
    }
}

#[cfg(test)]
#[cfg(feature = "test-helpers")]
mod tests {
    use super::*;
    use crate::extract::parse::test_frames::{ipv4_tcp, ipv4_udp, ipv6_tcp};

    #[test]
    fn ipv4_tcp_populates_all_slots() {
        let f = ipv4_tcp(
            [1; 6], [2; 6], [10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, 1000, 0, 0x02, b"",
        );
        let parser = LayerParser::new();
        let mut stack = LayerStack::new();
        parser.parse_ethernet(&f, &mut stack).unwrap();
        let eth = stack.ethernet().unwrap();
        assert_eq!(eth.source(), [1, 1, 1, 1, 1, 1]);
        let ip = stack.ipv4().unwrap();
        assert_eq!(ip.protocol(), 6);
        let tcp = stack.tcp().unwrap();
        assert_eq!(tcp.src_port(), 12345);
        assert!(stack.has(LayerKind::Tcp));
    }

    #[test]
    fn reset_clears_state() {
        let f1 = ipv4_tcp([0; 6], [0; 6], [1, 2, 3, 4], [5, 6, 7, 8], 10, 20, 0, 0, 0, b"");
        let f2 = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 5353, 53, b"x");
        let parser = LayerParser::new();
        let mut stack = LayerStack::new();
        parser.parse_ethernet(&f1, &mut stack).unwrap();
        assert!(stack.tcp().is_some());
        stack.reset();
        parser.parse_ethernet(&f2, &mut stack).unwrap();
        assert!(stack.tcp().is_none());
        assert!(stack.udp().is_some());
    }

    #[test]
    fn only_mask_skips_unrequested_slots() {
        let f = ipv4_tcp([0; 6], [0; 6], [1, 2, 3, 4], [5, 6, 7, 8], 10, 20, 0, 0, 0, b"");
        let parser = LayerParser::new().only(&[LayerKind::Ipv4, LayerKind::Tcp]);
        let mut stack = LayerStack::new();
        parser.parse_ethernet(&f, &mut stack).unwrap();
        // Ethernet was NOT requested.
        assert!(stack.ethernet().is_none());
        // IPv4 and TCP were.
        assert!(stack.ipv4().is_some());
        assert!(stack.tcp().is_some());
    }

    #[test]
    fn ipv6_path_works() {
        let f = ipv6_tcp(
            [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            12345,
            443,
            500,
            0x02,
            b"",
        );
        let parser = LayerParser::new();
        let mut stack = LayerStack::new();
        parser.parse_ethernet(&f, &mut stack).unwrap();
        assert!(stack.ipv6().is_some());
        assert!(stack.ipv4().is_none());
    }

    #[test]
    fn parse_ip_path() {
        use etherparse::{IpNumber, Ipv4Header, UdpHeader};
        let payload = b"hi";
        let udp = UdpHeader::without_ipv4_checksum(5353, 53, payload.len()).unwrap();
        let ip = Ipv4Header::new(
            (udp.header_len_u16() as usize + payload.len()) as u16,
            64,
            IpNumber::UDP,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
        )
        .unwrap();
        let mut buf = Vec::new();
        ip.write(&mut buf).unwrap();
        udp.write(&mut buf).unwrap();
        buf.extend_from_slice(payload);

        let parser = LayerParser::new();
        let stack = parser.parse_ip(&buf).unwrap();
        assert!(stack.ipv4().is_some());
        assert!(stack.udp().is_some());
    }

    #[test]
    fn truncated_frame_returns_layers_error() {
        let parser = LayerParser::new();
        let mut stack = LayerStack::new();
        let err = parser.parse_ethernet(&[0u8; 4], &mut stack).err().unwrap();
        assert_eq!(err.module(), crate::Module::Layers);
    }
}

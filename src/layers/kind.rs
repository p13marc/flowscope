//! [`LayerKind`] — discriminant used by [`Layers::find`](super::Layers::find)
//! / [`Layers::find_all`](super::Layers::find_all) and on every
//! per-layer slice.

use std::fmt;

/// Identifies one parsed layer in a packet.
///
/// Used as the discriminant for `Layer<'_>` and as the lookup key
/// in [`Layers::find`](super::Layers::find) /
/// [`Layers::find_all`](super::Layers::find_all). Pattern-match on
/// it for "any IP layer", "any L4", etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LayerKind {
    /// Ethernet II (link layer).
    Ethernet,
    /// 802.1Q VLAN tag.
    Vlan,
    /// MPLS label-stack entry.
    Mpls,
    /// IPv4.
    Ipv4,
    /// IPv6.
    Ipv6,
    /// ARP (Address Resolution Protocol).
    Arp,
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// ICMPv4.
    Icmpv4,
    /// ICMPv6.
    Icmpv6,
    /// GRE tunnel header (RFC 2784 / 2890).
    Gre,
    /// VXLAN tunnel header (RFC 7348).
    Vxlan,
    /// GTP-U tunnel header (3GPP TS 29.281).
    GtpU,
    /// Unparsed bytes after the last recognised header.
    Payload,
}

impl LayerKind {
    /// OSI L-number group: 2 (link), 3 (net), 4 (transport),
    /// 4.5 returned as 4 (ICMP/tunnels conventionally L4), or
    /// 7 (payload).
    pub fn layer_number(&self) -> u8 {
        match self {
            LayerKind::Ethernet | LayerKind::Vlan | LayerKind::Mpls => 2,
            LayerKind::Ipv4 | LayerKind::Ipv6 | LayerKind::Arp => 3,
            LayerKind::Tcp
            | LayerKind::Udp
            | LayerKind::Icmpv4
            | LayerKind::Icmpv6
            | LayerKind::Gre
            | LayerKind::Vxlan
            | LayerKind::GtpU => 4,
            LayerKind::Payload => 7,
        }
    }

    /// `true` if this kind is a link-layer header (Ethernet / VLAN
    /// / MPLS). New in 0.10.0.
    pub const fn is_l2(self) -> bool {
        matches!(
            self,
            LayerKind::Ethernet | LayerKind::Vlan | LayerKind::Mpls
        )
    }

    /// `true` if this kind is a network-layer header
    /// (IPv4 / IPv6 / ARP). New in 0.10.0.
    pub const fn is_l3(self) -> bool {
        matches!(self, LayerKind::Ipv4 | LayerKind::Ipv6 | LayerKind::Arp)
    }

    /// `true` if this kind is a transport-layer header
    /// (TCP / UDP / ICMPv4 / ICMPv6). Tunnel headers are reported
    /// by [`Self::is_tunnel`], not here, even though they share
    /// the L4 group via [`Self::layer_number`]. New in 0.10.0.
    pub const fn is_l4(self) -> bool {
        matches!(
            self,
            LayerKind::Tcp | LayerKind::Udp | LayerKind::Icmpv4 | LayerKind::Icmpv6
        )
    }

    /// `true` if this kind wraps another layered stack
    /// (GRE / VXLAN / GTP-U). New in 0.10.0.
    pub const fn is_tunnel(self) -> bool {
        matches!(self, LayerKind::Gre | LayerKind::Vxlan | LayerKind::GtpU)
    }
}

impl fmt::Display for LayerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            LayerKind::Ethernet => "ethernet",
            LayerKind::Vlan => "vlan",
            LayerKind::Mpls => "mpls",
            LayerKind::Ipv4 => "ipv4",
            LayerKind::Ipv6 => "ipv6",
            LayerKind::Arp => "arp",
            LayerKind::Tcp => "tcp",
            LayerKind::Udp => "udp",
            LayerKind::Icmpv4 => "icmpv4",
            LayerKind::Icmpv6 => "icmpv6",
            LayerKind::Gre => "gre",
            LayerKind::Vxlan => "vxlan",
            LayerKind::GtpU => "gtpu",
            LayerKind::Payload => "payload",
        };
        f.write_str(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layer_numbers() {
        assert_eq!(LayerKind::Ethernet.layer_number(), 2);
        assert_eq!(LayerKind::Vlan.layer_number(), 2);
        assert_eq!(LayerKind::Mpls.layer_number(), 2);
        assert_eq!(LayerKind::Ipv4.layer_number(), 3);
        assert_eq!(LayerKind::Ipv6.layer_number(), 3);
        assert_eq!(LayerKind::Arp.layer_number(), 3);
        assert_eq!(LayerKind::Tcp.layer_number(), 4);
        assert_eq!(LayerKind::Udp.layer_number(), 4);
        assert_eq!(LayerKind::Icmpv4.layer_number(), 4);
        assert_eq!(LayerKind::Icmpv6.layer_number(), 4);
        assert_eq!(LayerKind::Gre.layer_number(), 4);
        assert_eq!(LayerKind::Vxlan.layer_number(), 4);
        assert_eq!(LayerKind::GtpU.layer_number(), 4);
        assert_eq!(LayerKind::Payload.layer_number(), 7);
    }

    #[test]
    fn display_lowercase() {
        assert_eq!(LayerKind::Tcp.to_string(), "tcp");
        assert_eq!(LayerKind::Ethernet.to_string(), "ethernet");
    }
}

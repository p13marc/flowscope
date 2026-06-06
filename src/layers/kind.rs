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
    /// 802.1Q VLAN tag (sandwiched between link and net layers).
    Vlan,
    /// IPv4.
    Ipv4,
    /// IPv6.
    Ipv6,
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// Unparsed bytes after the last recognised header.
    Payload,
}

impl LayerKind {
    /// OSI L-number group for this kind: 2 (link), 3 (net), 4
    /// (transport), or 7 (payload).
    pub fn layer_number(&self) -> u8 {
        match self {
            LayerKind::Ethernet | LayerKind::Vlan => 2,
            LayerKind::Ipv4 | LayerKind::Ipv6 => 3,
            LayerKind::Tcp | LayerKind::Udp => 4,
            LayerKind::Payload => 7,
        }
    }
}

impl fmt::Display for LayerKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            LayerKind::Ethernet => "ethernet",
            LayerKind::Vlan => "vlan",
            LayerKind::Ipv4 => "ipv4",
            LayerKind::Ipv6 => "ipv6",
            LayerKind::Tcp => "tcp",
            LayerKind::Udp => "udp",
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
        assert_eq!(LayerKind::Ipv4.layer_number(), 3);
        assert_eq!(LayerKind::Ipv6.layer_number(), 3);
        assert_eq!(LayerKind::Tcp.layer_number(), 4);
        assert_eq!(LayerKind::Udp.layer_number(), 4);
        assert_eq!(LayerKind::Payload.layer_number(), 7);
    }

    #[test]
    fn display_lowercase() {
        assert_eq!(LayerKind::Tcp.to_string(), "tcp");
        assert_eq!(LayerKind::Ethernet.to_string(), "ethernet");
    }
}

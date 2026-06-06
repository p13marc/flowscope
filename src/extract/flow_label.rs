//! [`FlowLabel`] — augment a flow key with the IPv6 flow label.
//!
//! IPv6 dedicates 20 bits in the header to a flow label (RFC 6437).
//! ECMP-aware networks use it to keep correlated flows on the same
//! path. For traffic where many connections share a 5-tuple
//! (e.g., MPTCP subflows on top of one source IP/port), the flow
//! label is the differentiator.
//!
//! `FlowLabel<E>` wraps another extractor and appends the inner
//! IPv6 flow label to its key. IPv4 packets get `label = 0`.

use std::hash::Hash;
use std::net::IpAddr;

use crate::extractor::{Extracted, FlowExtractor};
use crate::view::PacketView;

use super::parse;

/// Wraps an inner key with a 20-bit IPv6 flow label.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FlowLabelKey<K> {
    /// The inner extractor's key.
    pub inner: K,
    /// The IPv6 flow label. Lower 20 bits significant; IPv4 traffic
    /// has `label == 0`.
    pub label: u32,
}

/// Augment `extractor`'s key with the inner packet's IPv6 flow label.
#[derive(Debug, Clone, Copy)]
pub struct FlowLabel<E> {
    /// The wrapped extractor.
    pub extractor: E,
}

impl<E> FlowLabel<E> {
    /// Construct.
    pub fn new(extractor: E) -> Self {
        Self { extractor }
    }
}

impl<E> FlowExtractor for FlowLabel<E>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + Sync + 'static,
{
    type Key = FlowLabelKey<E::Key>;

    fn extract(&self, view: PacketView<'_>) -> Option<Extracted<FlowLabelKey<E::Key>>> {
        let inner = self.extractor.extract(view)?;
        let label = read_flow_label(view.frame).unwrap_or(0);
        Some(Extracted {
            key: FlowLabelKey {
                inner: inner.key,
                label,
            },
            orientation: inner.orientation,
            l4: inner.l4,
            tcp: inner.tcp,
        })
    }
}

/// Read the 20-bit IPv6 flow label from `frame`. Returns `None` for
/// IPv4 frames (caller treats as label = 0). Walks past optional
/// VLAN tags.
fn read_flow_label(frame: &[u8]) -> Option<u32> {
    let parsed = parse::parse_eth(frame)?;
    let ip = parsed.ip?;
    if !matches!(ip.src, IpAddr::V6(_)) {
        return None;
    }
    // Re-parse to walk past VLANs and locate the IPv6 header bytes.
    // etherparse does this for us.
    let sp = etherparse::SlicedPacket::from_ethernet(frame).ok()?;
    let net = sp.net?;
    let v6 = match net {
        etherparse::NetSlice::Ipv6(v6) => v6,
        _ => return None,
    };
    let header = v6.header();
    Some(header.flow_label().value())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Timestamp;
    use crate::extract::FiveTuple;
    use crate::extract::parse::test_frames::ipv4_tcp;
    use etherparse::{Ethernet2Header, IpNumber, Ipv6FlowLabel, Ipv6Header, TcpHeader};

    fn build_ipv6_tcp(label: u32) -> Vec<u8> {
        let mut tcp = TcpHeader::new(1234, 80, 0, 8192);
        tcp.syn = true;
        let mut tcp_bytes = Vec::new();
        tcp.write(&mut tcp_bytes).unwrap();

        let v6 = Ipv6Header {
            traffic_class: 0,
            flow_label: Ipv6FlowLabel::try_new(label).unwrap(),
            payload_length: tcp_bytes.len() as u16,
            next_header: IpNumber::TCP,
            hop_limit: 64,
            source: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            destination: [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
        };
        let eth = Ethernet2Header {
            source: [0; 6],
            destination: [0; 6],
            ether_type: etherparse::EtherType::IPV6,
        };
        let mut frame = Vec::new();
        eth.write(&mut frame).unwrap();
        v6.write(&mut frame).unwrap();
        frame.extend_from_slice(&tcp_bytes);
        frame
    }

    #[test]
    fn ipv6_label_extracted() {
        let f = build_ipv6_tcp(0xabcde);
        let v = PacketView::new(&f, Timestamp::default());
        let e = FlowLabel::new(FiveTuple::bidirectional());
        let extracted = e.extract(v).expect("extract");
        assert_eq!(extracted.key.label, 0xabcde);
    }

    #[test]
    fn ipv6_zero_label() {
        let f = build_ipv6_tcp(0);
        let v = PacketView::new(&f, Timestamp::default());
        let e = FlowLabel::new(FiveTuple::bidirectional());
        let extracted = e.extract(v).expect("extract");
        assert_eq!(extracted.key.label, 0);
    }

    #[test]
    fn ipv4_label_is_zero() {
        let bytes = ipv4_tcp(
            [0; 6],
            [0; 6],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            0,
            0,
            0x02,
            b"",
        );
        let v = PacketView::new(&bytes, Timestamp::default());
        let e = FlowLabel::new(FiveTuple::bidirectional());
        let extracted = e.extract(v).expect("extract");
        assert_eq!(extracted.key.label, 0);
    }

    #[test]
    fn distinct_labels_are_distinct_keys() {
        let f1 = build_ipv6_tcp(0x12345);
        let f2 = build_ipv6_tcp(0x12346);
        let v1 = PacketView::new(&f1, Timestamp::default());
        let v2 = PacketView::new(&f2, Timestamp::default());
        let e = FlowLabel::new(FiveTuple::bidirectional());
        let k1 = e.extract(v1).unwrap().key;
        let k2 = e.extract(v2).unwrap().key;
        assert_ne!(k1, k2);
        // The inner FiveTuple key is the same — only the label differs.
        assert_eq!(k1.inner, k2.inner);
    }
}

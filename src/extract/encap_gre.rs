//! [`InnerGre`] — decap GRE, run inner extractor on the carried
//! protocol's frame.
//!
//! GRE (Generic Routing Encapsulation, RFC 2784/2890) carries an
//! inner protocol over IP protocol number 47. Common payloads:
//!
//! - IPv4 (ethertype `0x0800`)
//! - IPv6 (ethertype `0x86dd`)
//! - Transparent Ethernet Bridging (ethertype `0x6558`) — inner is
//!   a full Ethernet frame.
//!
//! Header layout (RFC 2784 + RFC 2890 keys):
//!
//! ```text
//!   0                   1                   2                   3
//!   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |C| |K|S|       Reserved0       | Ver |         Protocol         |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |    Checksum (optional)        |    Reserved1 (optional)        |  ← 4 bytes if C
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                            Key                                 |  ← 4 bytes if K
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                  Sequence Number                               |  ← 4 bytes if S
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```
//!
//! Version must be 0 (PPTP uses version 1; not handled here).

use crate::extractor::{Extracted, FlowExtractor};
use crate::view::PacketView;

use super::parse;

/// IP protocol number for GRE (RFC 2784).
pub const GRE_IP_PROTO: u8 = 47;

/// Ethertype for IPv4-in-GRE.
const ETH_IPV4: u16 = 0x0800;
/// Ethertype for IPv6-in-GRE.
const ETH_IPV6: u16 = 0x86dd;
/// Ethertype for Transparent Ethernet Bridging (inner is full Eth frame).
const ETH_TEB: u16 = 0x6558;

/// Decapsulate GRE and delegate to `extractor` on the inner frame.
///
/// IPv4-in-GRE and IPv6-in-GRE are wrapped in a synthetic 14-byte
/// Ethernet header before being handed to the inner extractor (so
/// L2-aware extractors keep working). Transparent Ethernet Bridging
/// (TEB) inner frames are passed through unchanged.
#[derive(Debug, Clone, Copy)]
pub struct InnerGre<E> {
    /// The wrapped extractor that processes the inner frame.
    pub extractor: E,
}

impl<E> InnerGre<E> {
    /// Construct.
    pub fn new(extractor: E) -> Self {
        Self { extractor }
    }
}

impl<E: FlowExtractor> FlowExtractor for InnerGre<E> {
    type Key = E::Key;

    fn extract(&self, view: PacketView<'_>) -> Option<Extracted<E::Key>> {
        let parsed = parse::parse_eth(view.frame)?;
        let ip = parsed.ip?;
        if ip.proto != GRE_IP_PROTO {
            return None;
        }
        let (ethertype, after_gre) = peel_gre(ip.l4_payload)?;
        let synthetic = synthesize_eth(ethertype, after_gre)?;
        self.extractor.extract(PacketView {
            frame: &synthetic,
            timestamp: view.timestamp,
        })
    }
}

/// Peel a GRE header off `bytes` (the IP payload, starting with the
/// GRE header). Returns `(inner_ethertype, inner_bytes)`.
fn peel_gre(bytes: &[u8]) -> Option<(u16, &[u8])> {
    if bytes.len() < 4 {
        return None;
    }
    let flags_hi = bytes[0];
    let flags_lo = bytes[1];
    let c = flags_hi & 0x80 != 0; // checksum present
    let k = flags_hi & 0x20 != 0; // key present
    let s = flags_hi & 0x10 != 0; // sequence present
    let version = flags_lo & 0x07;
    if version != 0 {
        // Version 1 is PPTP-GRE; not in our scope.
        return None;
    }
    let ethertype = u16::from_be_bytes([bytes[2], bytes[3]]);

    let mut header_len = 4usize;
    if c {
        header_len += 4;
    }
    if k {
        header_len += 4;
    }
    if s {
        header_len += 4;
    }
    if bytes.len() < header_len {
        return None;
    }
    Some((ethertype, &bytes[header_len..]))
}

/// Wrap an inner protocol payload in a 14-byte synthetic Ethernet
/// header. For TEB (`0x6558`) the inner is already an Ethernet frame
/// and is returned as-is.
fn synthesize_eth(ethertype: u16, inner: &[u8]) -> Option<Vec<u8>> {
    if inner.is_empty() {
        return None;
    }
    if ethertype == ETH_TEB {
        // Inner is already a full Ethernet frame.
        return Some(inner.to_vec());
    }
    if ethertype != ETH_IPV4 && ethertype != ETH_IPV6 {
        // Unknown inner protocol — let the caller fall through to None.
        return None;
    }
    let mut out = Vec::with_capacity(14 + inner.len());
    out.extend_from_slice(&[0u8; 12]); // dst+src MAC, zeros
    out.extend_from_slice(&ethertype.to_be_bytes());
    out.extend_from_slice(inner);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Timestamp;
    use crate::extract::FiveTuple;
    use etherparse::{Ethernet2Header, IpNumber, Ipv4Header, TcpHeader};

    /// Build an Ethernet+IPv4(GRE)+IPv4+TCP synthetic frame.
    fn build_ipv4_in_gre(gre_flags: u8, gre_extra: usize) -> Vec<u8> {
        // Innermost TCP/IPv4 from 1.1.1.1 → 2.2.2.2:80
        let mut tcp = TcpHeader::new(12345, 80, 0, 8192);
        tcp.syn = true;
        let inner_ip = Ipv4Header::new(
            tcp.header_len() as u16,
            64,
            IpNumber::TCP,
            [1, 1, 1, 1],
            [2, 2, 2, 2],
        )
        .unwrap();

        let mut inner_l3 = Vec::new();
        inner_ip.write(&mut inner_l3).unwrap();
        tcp.write(&mut inner_l3).unwrap();

        // GRE header: flags(1) + version_lo(1) + ethertype(2) + extras
        let mut gre = Vec::new();
        gre.push(gre_flags);
        gre.push(0); // version 0
        gre.extend_from_slice(&ETH_IPV4.to_be_bytes());
        gre.extend(std::iter::repeat_n(0u8, gre_extra));

        // Outer IPv4 carrying GRE (proto 47)
        let outer_ip_len = (gre.len() + inner_l3.len()) as u16;
        let outer_ip = Ipv4Header::new(
            outer_ip_len,
            64,
            IpNumber(GRE_IP_PROTO),
            [10, 0, 0, 1],
            [10, 0, 0, 2],
        )
        .unwrap();

        // Ethernet
        let eth = Ethernet2Header {
            source: [0; 6],
            destination: [0; 6],
            ether_type: etherparse::EtherType::IPV4,
        };

        let mut frame = Vec::new();
        eth.write(&mut frame).unwrap();
        outer_ip.write(&mut frame).unwrap();
        frame.extend_from_slice(&gre);
        frame.extend_from_slice(&inner_l3);
        frame
    }

    #[test]
    fn ipv4_in_gre_no_extras() {
        let f = build_ipv4_in_gre(0, 0);
        let v = PacketView::new(&f, Timestamp::default());
        let e = InnerGre::new(FiveTuple::bidirectional());
        let extracted = e.extract(v).expect("extract");
        // Inner key should reflect 1.1.1.1:* ↔ 2.2.2.2:80
        let dbg = format!("{:?}", extracted.key);
        assert!(dbg.contains("1.1.1.1"), "{dbg}");
        assert!(dbg.contains("2.2.2.2"), "{dbg}");
    }

    #[test]
    fn ipv4_in_gre_with_checksum() {
        // C flag set → 4 extra bytes for checksum+reserved.
        let f = build_ipv4_in_gre(0x80, 4);
        let v = PacketView::new(&f, Timestamp::default());
        let e = InnerGre::new(FiveTuple::bidirectional());
        assert!(e.extract(v).is_some());
    }

    #[test]
    fn ipv4_in_gre_with_key() {
        // K flag set → 4 extra bytes for key.
        let f = build_ipv4_in_gre(0x20, 4);
        let v = PacketView::new(&f, Timestamp::default());
        let e = InnerGre::new(FiveTuple::bidirectional());
        assert!(e.extract(v).is_some());
    }

    #[test]
    fn ipv4_in_gre_with_checksum_and_key() {
        // C + K → 8 extra bytes.
        let f = build_ipv4_in_gre(0x80 | 0x20, 8);
        let v = PacketView::new(&f, Timestamp::default());
        let e = InnerGre::new(FiveTuple::bidirectional());
        assert!(e.extract(v).is_some());
    }

    #[test]
    fn rejects_non_gre_ip() {
        // Plain TCP, no GRE.
        let bytes = crate::extract::parse::test_frames::ipv4_tcp(
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
        let e = InnerGre::new(FiveTuple::bidirectional());
        assert!(e.extract(v).is_none());
    }

    #[test]
    fn rejects_pptp_version_1() {
        // C=0,K=0,S=0, version=1 (PPTP) → reject.
        let f = build_ipv4_in_gre(0, 0);
        let mut bad = f.clone();
        // Patch the version byte (second byte of GRE header) to 1.
        // GRE starts after Ethernet (14) + outer IP (20) = 34.
        bad[34 + 1] = 1;
        let v = PacketView::new(&bad, Timestamp::default());
        let e = InnerGre::new(FiveTuple::bidirectional());
        assert!(e.extract(v).is_none());
    }
}

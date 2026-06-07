//! [`FiveTuple`] — protocol + (src, dst) endpoints.

use std::net::SocketAddr;

use crate::extractor::{Extracted, FlowExtractor, L4Proto, Orientation, TcpInfo};
use crate::view::PacketView;

use super::parse::{self, ParsedL4};

/// Standard 5-tuple flow extractor: protocol + source + destination
/// IP/port. Bidirectional by default — A→B and B→A merge into one
/// flow with [`Orientation::Forward`] / [`Orientation::Reverse`].
#[derive(Debug, Clone, Copy)]
pub struct FiveTuple {
    bidirectional: bool,
}

impl FiveTuple {
    /// A→B and B→A are tracked as **separate** flows.
    pub const fn directional() -> Self {
        Self {
            bidirectional: false,
        }
    }

    /// A→B and B→A are merged into one flow. The endpoints are
    /// canonically sorted into `(a, b)` where `a < b`.
    pub const fn bidirectional() -> Self {
        Self {
            bidirectional: true,
        }
    }

    /// Whether this extractor canonicalizes endpoint ordering.
    pub const fn is_bidirectional(&self) -> bool {
        self.bidirectional
    }
}

impl Default for FiveTuple {
    /// Defaults to bidirectional.
    fn default() -> Self {
        Self::bidirectional()
    }
}

/// Flow key for [`FiveTuple`].
///
/// In bidirectional mode, `a < b` (lexicographic on `SocketAddr`).
/// In directional mode, `a` is always source, `b` always destination.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FiveTupleKey {
    pub proto: L4Proto,
    pub a: SocketAddr,
    pub b: SocketAddr,
}

impl FiveTupleKey {
    /// Convenience: matches either endpoint's port.
    ///
    /// Useful in idle-timeout predicates (see
    /// [`crate::FlowTracker::set_idle_timeout_fn`]) and any place
    /// where you want to route on "either side talks to port X."
    ///
    /// In bidirectional-mode flows (default), `a` and `b` are
    /// canonicalised lexicographically so neither is "source" —
    /// this helper avoids that footgun.
    #[inline]
    pub fn either_port(&self, port: u16) -> bool {
        self.a.port() == port || self.b.port() == port
    }

    /// Lower-numbered endpoint port — the "well-known" side for
    /// client/server flows. Useful for protocol labelling without
    /// having to remember which of `a` / `b` is which.
    ///
    /// New in 0.10.0.
    #[inline]
    pub fn well_known_port(&self) -> u16 {
        self.a.port().min(self.b.port())
    }

    /// Canonical short protocol label (`"http"`, `"tls/https"`,
    /// `"dns"`, …) for this flow, or `None` if neither endpoint
    /// hits a known port. See [`crate::well_known::protocol_label`]
    /// for the curated table and disambiguation rules.
    ///
    /// New in 0.10.0.
    #[inline]
    pub fn protocol_label(&self) -> Option<&'static str> {
        crate::well_known::protocol_label(self.proto, self.a.port(), self.b.port())
    }
}

impl FlowExtractor for FiveTuple {
    type Key = FiveTupleKey;

    fn extract(&self, view: PacketView<'_>) -> Option<Extracted<FiveTupleKey>> {
        let parsed = parse::parse_eth(view.frame)?;
        extract_from_parsed(parsed, self.bidirectional)
    }
}

/// Shared logic between L2 and post-decap (raw IP) entry points.
/// Used by [`crate::extract::InnerGtpU`] for inner-flow keying.
pub(crate) fn extract_from_parsed(
    parsed: parse::ParsedFrame<'_>,
    bidirectional: bool,
) -> Option<Extracted<FiveTupleKey>> {
    let ip = parsed.ip?;
    let (src_port, dst_port, l4, tcp_info) = match parsed.l4 {
        Some(ParsedL4::Tcp(t)) => (
            t.src_port,
            t.dst_port,
            L4Proto::Tcp,
            Some(TcpInfo {
                flags: t.flags,
                seq: t.seq,
                ack: t.ack,
                payload_offset: t.payload_offset,
                payload_len: t.payload_len,
                window: t.window,
            }),
        ),
        Some(ParsedL4::Udp(u)) => (u.src_port, u.dst_port, L4Proto::Udp, None),
        Some(ParsedL4::Other) | None => {
            // ICMP / ICMPv6 / SCTP / unknown — keep the flow but
            // ports are unavailable.
            let l4 = match ip.proto {
                1 => L4Proto::Icmp,
                58 => L4Proto::IcmpV6,
                132 => L4Proto::Sctp,
                p => L4Proto::Other(p),
            };
            (0u16, 0u16, l4, None)
        }
    };

    let src = SocketAddr::new(ip.src, src_port);
    let dst = SocketAddr::new(ip.dst, dst_port);

    let (a, b, orientation) = if bidirectional && src > dst {
        (dst, src, Orientation::Reverse)
    } else {
        (src, dst, Orientation::Forward)
    };

    Some(Extracted {
        key: FiveTupleKey { proto: l4, a, b },
        orientation,
        l4: Some(l4),
        tcp: tcp_info,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Timestamp;
    use crate::extract::parse::test_frames::*;
    use crate::extractor::TcpFlags;

    #[test]
    fn syn_packet_forward() {
        let f = ipv4_tcp(
            [0; 6],
            [0; 6],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            1000,
            0,
            0x02,
            b"",
        );
        let view = PacketView::new(&f, Timestamp::default());
        let e = FiveTuple::bidirectional().extract(view).unwrap();
        assert_eq!(e.key.proto, L4Proto::Tcp);
        // 10.0.0.1:1234 < 10.0.0.2:80 in SocketAddr ordering, so a=src.
        assert_eq!(e.orientation, Orientation::Forward);
        assert!(e.tcp.is_some());
        let tcp = e.tcp.unwrap();
        assert!(tcp.flags.contains(TcpFlags::SYN));
        assert_eq!(tcp.seq, 1000);
    }

    #[test]
    fn bidirectional_canonicalizes() {
        // A→B (forward) and B→A (reverse) should yield the same key
        // but opposite orientations.
        let fwd = ipv4_tcp(
            [0; 6],
            [0; 6],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            1000,
            0,
            0x02,
            b"",
        );
        let rev = ipv4_tcp(
            [0; 6],
            [0; 6],
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            80,
            1234,
            0,
            1001,
            0x12,
            b"",
        );
        let e_fwd = FiveTuple::bidirectional()
            .extract(PacketView::new(&fwd, Timestamp::default()))
            .unwrap();
        let e_rev = FiveTuple::bidirectional()
            .extract(PacketView::new(&rev, Timestamp::default()))
            .unwrap();
        assert_eq!(e_fwd.key, e_rev.key, "keys must match");
        assert_ne!(e_fwd.orientation, e_rev.orientation);
    }

    #[test]
    fn directional_distinguishes_directions() {
        let fwd = ipv4_tcp(
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
        let rev = ipv4_tcp(
            [0; 6],
            [0; 6],
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            80,
            1234,
            0,
            0,
            0x12,
            b"",
        );
        let e_fwd = FiveTuple::directional()
            .extract(PacketView::new(&fwd, Timestamp::default()))
            .unwrap();
        let e_rev = FiveTuple::directional()
            .extract(PacketView::new(&rev, Timestamp::default()))
            .unwrap();
        assert_ne!(e_fwd.key, e_rev.key, "directional keys must differ");
    }

    #[test]
    fn udp_no_tcp_info() {
        let f = ipv4_udp([1, 2, 3, 4], [5, 6, 7, 8], 53, 5353, b"hello");
        let e = FiveTuple::bidirectional()
            .extract(PacketView::new(&f, Timestamp::default()))
            .unwrap();
        assert_eq!(e.key.proto, L4Proto::Udp);
        assert!(e.tcp.is_none());
    }

    #[test]
    fn ipv6_supported() {
        let f = ipv6_tcp(
            [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            1,
            2,
            0,
            0x02,
            b"",
        );
        let e = FiveTuple::bidirectional()
            .extract(PacketView::new(&f, Timestamp::default()))
            .unwrap();
        assert_eq!(e.key.proto, L4Proto::Tcp);
    }

    #[test]
    fn malformed_returns_none() {
        let f = [0u8; 4];
        assert!(
            FiveTuple::bidirectional()
                .extract(PacketView::new(&f, Timestamp::default()))
                .is_none()
        );
    }

    #[test]
    fn key_hash_eq_consistency() {
        use std::collections::HashSet;
        let f1 = ipv4_tcp(
            [0; 6],
            [0; 6],
            [1, 1, 1, 1],
            [2, 2, 2, 2],
            10,
            20,
            0,
            0,
            0x02,
            b"",
        );
        let f2 = ipv4_tcp(
            [0; 6],
            [0; 6],
            [2, 2, 2, 2],
            [1, 1, 1, 1],
            20,
            10,
            0,
            0,
            0x12,
            b"",
        );
        let e1 = FiveTuple::bidirectional()
            .extract(PacketView::new(&f1, Timestamp::default()))
            .unwrap();
        let e2 = FiveTuple::bidirectional()
            .extract(PacketView::new(&f2, Timestamp::default()))
            .unwrap();
        let mut set = HashSet::new();
        set.insert(e1.key);
        set.insert(e2.key);
        assert_eq!(set.len(), 1, "bidirectional keys must hash equal");
    }
}

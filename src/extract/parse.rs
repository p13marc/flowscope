//! Internal frame-parsing helpers shared by built-in extractors.
//!
//! Wraps [`etherparse`] for the protocols it handles and adds
//! inline parsers for what it doesn't (MPLS, VXLAN, GTP-U).

use std::net::IpAddr;

use crate::extractor::TcpFlags;

/// Parsed bits of an Ethernet (or post-decap-Ethernet) frame.
pub(crate) struct ParsedFrame<'a> {
    pub ip: Option<ParsedIp<'a>>,
    pub l4: Option<ParsedL4>,
}

pub(crate) struct ParsedIp<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: u8,
    /// Slice of L4 payload (for inspection or hashing). Lifetime
    /// borrowed from the original frame. Consumed by the GRE
    /// decap combinator and any future inspection paths. Only the
    /// captured bytes: shorter than [`Self::l4_wire_len`] when the
    /// capture cut the packet.
    pub l4_payload: &'a [u8],
    /// Offset of `l4_payload` in the parsed frame.
    pub l4_offset: usize,
    /// Length of the IP packet on the wire, header included: the
    /// IPv4 total length / 40 + the IPv6 payload length. When the
    /// header gives no usable length (an IPv4 total length of 0 from
    /// TCP segmentation offload, an IPv6 jumbogram), the captured IP
    /// length.
    pub l3_len: u32,
    /// Length of the L4 region (header + payload) on the wire, as the
    /// IP header claims it; never less than `l4_payload.len()`.
    pub l4_wire_len: usize,
}

pub(crate) enum ParsedL4 {
    Tcp(ParsedTcp),
    Udp(ParsedUdp),
    Other,
}

pub(crate) struct ParsedTcp {
    pub src_port: u16,
    pub dst_port: u16,
    pub flags: TcpFlags,
    pub seq: u32,
    pub ack: u32,
    /// Offset into the original frame where the TCP payload starts.
    pub payload_offset: usize,
    /// Captured payload bytes.
    pub payload_len: usize,
    /// Payload bytes on the wire (≥ `payload_len`; larger when the
    /// capture cut the segment).
    pub wire_payload_len: usize,
    pub window: u16,
}

pub(crate) struct ParsedUdp {
    pub src_port: u16,
    pub dst_port: u16,
    /// Offset into the original frame where the UDP payload starts.
    pub payload_offset: usize,
    /// Captured payload bytes.
    pub payload_len: usize,
    /// Payload bytes on the wire (≥ `payload_len`).
    pub wire_payload_len: usize,
}

/// Parse an L2 Ethernet frame (with optional VLAN/MACsec link
/// extensions handled by `etherparse`).
///
/// Lax about the one thing a capture does to a packet: cutting its
/// end (a snap length, #212). A packet whose IP header claims more
/// bytes than were captured is parsed as far as its headers go, and
/// the lengths the headers claim are reported next to the captured
/// ones (`l3_len`, `l4_wire_len`, `wire_payload_len`). Everything
/// else that `etherparse` rejects — a malformed header or body in a
/// packet that is *not* cut short (bad TCP data offset, a short IGMP
/// message, an ARP body shorter than its address lengths, a broken
/// MACsec header, IP extension headers cut by the snap length) —
/// still skips the packet, as the strict parse did. So does a packet
/// cut inside its TCP / UDP header: without ports there is no flow
/// key.
pub(crate) fn parse_eth(frame: &[u8]) -> Option<ParsedFrame<'_>> {
    let sp = etherparse::LaxSlicedPacket::from_ethernet(frame).ok()?;
    parse_from_lax(&sp, frame)
}

fn parse_from_lax<'a>(
    sp: &etherparse::LaxSlicedPacket<'a>,
    frame: &'a [u8],
) -> Option<ParsedFrame<'a>> {
    use etherparse::{IpNumber, LaxNetSlice, LenSource, err::Layer, err::packet::SliceError};

    let net = sp.net.as_ref()?;
    // (src, dst, protocol, start of the IP header, length the header
    // claims, payload)
    let (src, dst, proto, l3_start, claimed, payload) = match net {
        LaxNetSlice::Ipv4(v4) => {
            let h = v4.header();
            (
                IpAddr::V4(h.source_addr()),
                IpAddr::V4(h.destination_addr()),
                u8::from(h.protocol()),
                h.slice().as_ptr(),
                usize::from(h.total_len()),
                v4.payload(),
            )
        }
        LaxNetSlice::Ipv6(v6) => {
            let h = v6.header();
            (
                IpAddr::V6(h.source_addr()),
                IpAddr::V6(h.destination_addr()),
                // After any IPv6 extensions, this is the L4 proto.
                u8::from(v6.payload().ip_number),
                h.slice().as_ptr(),
                40 + usize::from(h.payload_length()),
                v6.payload(),
            )
        }
        // ARP has no IP endpoints, so no flow (etherparse >= 0.17 parses it).
        LaxNetSlice::Arp(_) => return None,
    };

    // The only stop tolerated is the capture running out inside the
    // transport layer of a packet whose IP header claims more bytes.
    if let Some((err, layer)) = &sp.stop_err {
        let cut = matches!(err, SliceError::Len(_))
            && payload.incomplete
            && matches!(
                layer,
                Layer::TcpHeader | Layer::UdpHeader | Layer::Icmpv4 | Layer::Icmpv6 | Layer::Igmp
            );
        if !cut {
            return None;
        }
    }
    // A TCP / UDP header the capture cut: no ports, no flow key.
    if sp.transport.is_none()
        && !payload.fragmented
        && (payload.ip_number == IpNumber::TCP || payload.ip_number == IpNumber::UDP)
    {
        return None;
    }

    let l4_payload_slice: &[u8] = payload.payload;
    // Offset of the L4 payload region (header + body for TCP/UDP)
    // relative to the original frame.
    let l4_region_offset = byte_offset(frame, l4_payload_slice)?;
    let l3_offset = (l3_start as usize).checked_sub(frame.as_ptr() as usize)?;
    let l3_header = l4_region_offset.checked_sub(l3_offset)?;
    let captured_l3 = l3_header + l4_payload_slice.len();
    // The header's own length, unless it gave none (TSO total length
    // 0, IPv6 jumbogram) and etherparse fell back to the slice.
    let l3_wire = if payload.incomplete || payload.len_source != LenSource::Slice {
        claimed.max(captured_l3)
    } else {
        captured_l3
    };
    let incomplete = payload.incomplete;
    let l4_wire_len = if incomplete {
        l3_wire
            .saturating_sub(l3_header)
            .max(l4_payload_slice.len())
    } else {
        l4_payload_slice.len()
    };
    let l3_len = u32::try_from(l3_wire).unwrap_or(u32::MAX);

    let l4 = match sp.transport.as_ref() {
        Some(etherparse::TransportSlice::Tcp(tcp)) => {
            let payload = tcp.payload();
            let payload_offset = byte_offset(frame, payload).unwrap_or(l4_region_offset);
            let mut flags = TcpFlags::empty();
            if tcp.fin() {
                flags |= TcpFlags::FIN;
            }
            if tcp.syn() {
                flags |= TcpFlags::SYN;
            }
            if tcp.rst() {
                flags |= TcpFlags::RST;
            }
            if tcp.psh() {
                flags |= TcpFlags::PSH;
            }
            if tcp.ack() {
                flags |= TcpFlags::ACK;
            }
            if tcp.urg() {
                flags |= TcpFlags::URG;
            }
            if tcp.ece() {
                flags |= TcpFlags::ECE;
            }
            if tcp.cwr() {
                flags |= TcpFlags::CWR;
            }
            Some(ParsedL4::Tcp(ParsedTcp {
                src_port: tcp.source_port(),
                dst_port: tcp.destination_port(),
                flags,
                seq: tcp.sequence_number(),
                ack: tcp.acknowledgment_number(),
                payload_offset,
                payload_len: payload.len(),
                wire_payload_len: l4_wire_len
                    .saturating_sub(tcp.header_slice().len())
                    .max(payload.len()),
                window: tcp.window_size(),
            }))
        }
        Some(etherparse::TransportSlice::Udp(udp)) => {
            let payload = udp.payload();
            let payload_offset = byte_offset(frame, payload).unwrap_or(l4_region_offset);
            // A complete datagram is what UDP's length field delimits
            // (bytes after it in the IP payload — UDP options, trailing
            // data — are no truncation). A cut one is as long as that
            // field says, when it is plausible, else as the IP header
            // says.
            let wire_payload_len = if incomplete {
                match usize::from(udp.length()) {
                    claimed @ 8.. if claimed <= l4_wire_len => claimed - 8,
                    _ => l4_wire_len.saturating_sub(8),
                }
            } else {
                payload.len()
            };
            Some(ParsedL4::Udp(ParsedUdp {
                src_port: udp.source_port(),
                dst_port: udp.destination_port(),
                payload_offset,
                payload_len: payload.len(),
                wire_payload_len: wire_payload_len.max(payload.len()),
            }))
        }
        Some(_) => Some(ParsedL4::Other),
        None => None,
    };

    Some(ParsedFrame {
        ip: Some(ParsedIp {
            src,
            dst,
            proto,
            l4_payload: l4_payload_slice,
            l4_offset: l4_region_offset,
            l3_len,
            l4_wire_len,
        }),
        l4,
    })
}

/// Compute the byte offset of `inner` inside `outer`, if `inner` is
/// fully contained within `outer`'s allocation. Returns None if not.
pub(crate) fn byte_offset(outer: &[u8], inner: &[u8]) -> Option<usize> {
    let outer_start = outer.as_ptr() as usize;
    let inner_start = inner.as_ptr() as usize;
    let outer_end = outer_start.checked_add(outer.len())?;
    let inner_end = inner_start.checked_add(inner.len())?;
    if inner_start < outer_start || inner_end > outer_end {
        return None;
    }
    Some(inner_start - outer_start)
}

#[cfg(any(test, feature = "test-helpers"))]
pub mod test_frames {
    //! Synthetic frame builders used across extractor tests.
    //!
    //! Available behind the `test-helpers` feature for downstream
    //! crates (proptest, fuzz harnesses, fixture generators).

    /// Build an Ethernet/IPv4/TCP frame with the given fields.
    /// Returns the byte buffer.
    #[allow(clippy::too_many_arguments)]
    pub fn ipv4_tcp(
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        use etherparse::{Ethernet2Header, IpNumber, Ipv4Header, TcpHeader};

        let mut tcp = TcpHeader::new(src_port, dst_port, seq, 8192);
        tcp.acknowledgment_number = ack;
        tcp.fin = flags & 0x01 != 0;
        tcp.syn = flags & 0x02 != 0;
        tcp.rst = flags & 0x04 != 0;
        tcp.psh = flags & 0x08 != 0;
        tcp.ack = flags & 0x10 != 0;
        tcp.urg = flags & 0x20 != 0;

        let ip = Ipv4Header::new(
            (tcp.header_len() + payload.len()) as u16,
            64,
            IpNumber::TCP,
            src_ip,
            dst_ip,
        )
        .unwrap();

        let eth = Ethernet2Header {
            destination: dst_mac,
            source: src_mac,
            ether_type: etherparse::EtherType::IPV4,
        };

        let mut out = Vec::new();
        eth.write(&mut out).unwrap();
        ip.write(&mut out).unwrap();
        tcp.write(&mut out).unwrap();
        out.extend_from_slice(payload);
        out
    }

    /// Build an Ethernet/IPv4/UDP frame.
    pub fn ipv4_udp(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        use etherparse::{Ethernet2Header, IpNumber, Ipv4Header, UdpHeader};

        let udp = UdpHeader::without_ipv4_checksum(src_port, dst_port, payload.len()).unwrap();
        let ip = Ipv4Header::new(
            (udp.header_len_u16() as usize + payload.len()) as u16,
            64,
            IpNumber::UDP,
            src_ip,
            dst_ip,
        )
        .unwrap();
        let eth = Ethernet2Header {
            destination: [0; 6],
            source: [0; 6],
            ether_type: etherparse::EtherType::IPV4,
        };

        let mut out = Vec::new();
        eth.write(&mut out).unwrap();
        ip.write(&mut out).unwrap();
        udp.write(&mut out).unwrap();
        out.extend_from_slice(payload);
        out
    }

    /// Build an Ethernet/IPv6/TCP frame.
    pub fn ipv6_tcp(
        src_ip: [u8; 16],
        dst_ip: [u8; 16],
        src_port: u16,
        dst_port: u16,
        seq: u32,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        use etherparse::{Ethernet2Header, IpNumber, Ipv6Header, TcpHeader};

        let mut tcp = TcpHeader::new(src_port, dst_port, seq, 8192);
        tcp.syn = flags & 0x02 != 0;
        tcp.ack = flags & 0x10 != 0;

        let ip = Ipv6Header {
            traffic_class: 0,
            flow_label: 0u32.try_into().unwrap(),
            payload_length: (tcp.header_len() + payload.len()) as u16,
            next_header: IpNumber::TCP,
            hop_limit: 64,
            source: src_ip,
            destination: dst_ip,
        };
        let eth = Ethernet2Header {
            destination: [0; 6],
            source: [0; 6],
            ether_type: etherparse::EtherType::IPV6,
        };

        let mut out = Vec::new();
        eth.write(&mut out).unwrap();
        ip.write(&mut out).unwrap();
        tcp.write(&mut out).unwrap();
        out.extend_from_slice(payload);
        out
    }

    /// Insert 802.1Q / 802.1ad tags, outermost first, into an Ethernet II
    /// `frame` after its MAC addresses. Each tag is `(tpid, tci)`.
    pub fn with_vlan_tags(frame: &[u8], tags: &[(u16, u16)]) -> Vec<u8> {
        let mut out = frame[..12].to_vec();
        for &(tpid, tci) in tags {
            out.extend_from_slice(&tpid.to_be_bytes());
            out.extend_from_slice(&tci.to_be_bytes());
        }
        out.extend_from_slice(&frame[12..]);
        out
    }
}

#[cfg(test)]
mod tests {
    use test_frames::*;

    use super::*;

    #[test]
    fn parse_ipv4_tcp_basic() {
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
        let parsed = parse_eth(&f).expect("parse");
        let ip = parsed.ip.unwrap();
        match ip.src {
            std::net::IpAddr::V4(a) => assert_eq!(a.octets(), [10, 0, 0, 1]),
            _ => panic!("expected ipv4"),
        }
        match parsed.l4.unwrap() {
            ParsedL4::Tcp(t) => {
                assert_eq!(t.src_port, 1234);
                assert_eq!(t.dst_port, 80);
                assert!(t.flags.contains(TcpFlags::SYN));
                assert_eq!(t.seq, 1000);
                assert_eq!(t.payload_len, 0);
            }
            _ => panic!("expected tcp"),
        }
    }

    #[test]
    fn parse_ipv4_tcp_payload_offset_correct() {
        let payload = b"hello";
        let f = ipv4_tcp(
            [0; 6],
            [0; 6],
            [1, 2, 3, 4],
            [5, 6, 7, 8],
            10,
            20,
            0,
            0,
            0x10,
            payload,
        );
        let parsed = parse_eth(&f).unwrap();
        let tcp = match parsed.l4.unwrap() {
            ParsedL4::Tcp(t) => t,
            _ => panic!(),
        };
        // Eth (14) + IP (20) + TCP (20) = 54
        assert_eq!(tcp.payload_offset, 54);
        assert_eq!(tcp.payload_len, payload.len());
        assert_eq!(
            &f[tcp.payload_offset..tcp.payload_offset + tcp.payload_len],
            payload
        );
    }

    #[test]
    fn parse_ipv4_udp_basic() {
        let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 5353, 53, b"hi");
        let parsed = parse_eth(&f).unwrap();
        match parsed.l4.unwrap() {
            ParsedL4::Udp(u) => {
                assert_eq!(u.src_port, 5353);
                assert_eq!(u.dst_port, 53);
                assert_eq!(u.payload_len, 2);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parse_ipv6_tcp_basic() {
        let f = ipv6_tcp(
            [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            12345,
            443,
            500,
            0x12, // SYN | ACK
            b"",
        );
        let parsed = parse_eth(&f).unwrap();
        let ip = parsed.ip.unwrap();
        match ip.src {
            std::net::IpAddr::V6(_) => {}
            _ => panic!(),
        }
        let tcp = match parsed.l4.unwrap() {
            ParsedL4::Tcp(t) => t,
            _ => panic!(),
        };
        assert!(tcp.flags.contains(TcpFlags::SYN));
        assert!(tcp.flags.contains(TcpFlags::ACK));
    }

    #[test]
    fn parse_arp_returns_none_ip() {
        // 64-byte minimum ARP frame: Eth(14) + ARP(28) + padding(22)
        let mut f = vec![0u8; 64];
        f[0..6].copy_from_slice(&[0xff; 6]); // dst MAC
        f[6..12].copy_from_slice(&[0; 6]);
        f[12..14].copy_from_slice(&0x0806u16.to_be_bytes()); // ARP ethertype
        // ARP header (HTYPE=1, PTYPE=0x0800, HLEN=6, PLEN=4, OPER=1)
        f[14..16].copy_from_slice(&1u16.to_be_bytes());
        f[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
        f[18] = 6;
        f[19] = 4;
        f[20..22].copy_from_slice(&1u16.to_be_bytes());
        let parsed = parse_eth(&f);
        // ARP doesn't yield an IP, parse should return None at the
        // net stage.
        assert!(parsed.is_none() || parsed.unwrap().ip.is_none());
    }

    #[test]
    fn parse_truncated_returns_none() {
        let f = [0u8; 5];
        assert!(parse_eth(&f).is_none());
    }

    // ── #212: lax parsing of frames a snap length cut ──────────

    fn tcp_frame(payload: &[u8]) -> Vec<u8> {
        ipv4_tcp(
            [0; 6],
            [0; 6],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            40000,
            80,
            1000,
            0,
            0x18,
            payload,
        )
    }

    #[test]
    fn lax_tcp_reports_wire_payload_len() {
        let mut f = tcp_frame(&[b'x'; 100]);
        // Ethernet (14) + IP (20) + TCP (20) + 10 payload bytes kept.
        f.truncate(64);
        let parsed = parse_eth(&f).expect("a cut segment is parsed");
        let ip = parsed.ip.unwrap();
        assert_eq!(ip.l3_len, 140, "IP total length from the header");
        assert_eq!(ip.l4_wire_len, 120);
        assert_eq!(ip.l4_payload.len(), 30, "captured L4 bytes");
        let ParsedL4::Tcp(t) = parsed.l4.unwrap() else {
            panic!("expected tcp")
        };
        assert_eq!((t.src_port, t.dst_port, t.seq), (40000, 80, 1000));
        assert_eq!((t.payload_offset, t.payload_len), (54, 10));
        assert_eq!(t.wire_payload_len, 100);
    }

    #[test]
    fn complete_tcp_has_equal_wire_and_captured_lengths() {
        let f = tcp_frame(&[b'x'; 100]);
        let parsed = parse_eth(&f).unwrap();
        assert_eq!(parsed.ip.as_ref().unwrap().l3_len, 140);
        let ParsedL4::Tcp(t) = parsed.l4.unwrap() else {
            panic!("expected tcp")
        };
        assert_eq!((t.payload_len, t.wire_payload_len), (100, 100));
    }

    #[test]
    fn lax_udp_reports_wire_payload_len() {
        let mut f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 5353, 53, &[7; 200]);
        f.truncate(14 + 20 + 8 + 20);
        let parsed = parse_eth(&f).expect("a cut datagram is parsed");
        assert_eq!(parsed.ip.as_ref().unwrap().l3_len, 228);
        let ParsedL4::Udp(u) = parsed.l4.unwrap() else {
            panic!("expected udp")
        };
        assert_eq!((u.payload_len, u.wire_payload_len), (20, 200));
    }

    #[test]
    fn tcp_header_cut_is_skipped() {
        let mut f = tcp_frame(&[b'x'; 100]);
        // Cut inside the TCP header: ports present, header incomplete.
        f.truncate(14 + 20 + 10);
        assert!(parse_eth(&f).is_none(), "no complete L4 header, no key");
        // Cut inside the IP header.
        f.truncate(14 + 10);
        assert!(parse_eth(&f).is_none());
    }

    #[test]
    fn malformed_igmp_content_still_skipped() {
        // A complete IPv4 packet carrying a 4-byte IGMP message (IGMP
        // needs 8): malformed, not cut — skipped as in 0.25.3.
        use etherparse::{Ethernet2Header, IpNumber, Ipv4Header};
        let ip = Ipv4Header::new(4, 1, IpNumber::IGMP, [10, 0, 0, 1], [224, 0, 0, 1]).unwrap();
        let mut f = Vec::new();
        Ethernet2Header {
            destination: [0; 6],
            source: [0; 6],
            ether_type: etherparse::EtherType::IPV4,
        }
        .write(&mut f)
        .unwrap();
        ip.write(&mut f).unwrap();
        f.extend_from_slice(&[0x11, 0, 0, 0]);
        assert!(parse_eth(&f).is_none());
        // A malformed TCP header (data offset beyond the segment) in a
        // complete packet: skipped too.
        let mut f = tcp_frame(b"");
        f[14 + 20 + 12] = 0xf0; // data offset 15 words = 60 bytes
        assert!(parse_eth(&f).is_none());
    }

    #[test]
    fn tso_zero_total_len_is_tracked() {
        // TCP segmentation offload hands the capture a super-segment
        // whose IPv4 total length is 0: the frame is the length.
        let mut f = tcp_frame(&[b'x'; 3000]);
        f[16] = 0;
        f[17] = 0;
        let parsed = parse_eth(&f).expect("TSO frame parsed");
        let ip = parsed.ip.unwrap();
        assert_eq!(ip.l3_len as usize, f.len() - 14, "captured IP length");
        let ParsedL4::Tcp(t) = parsed.l4.unwrap() else {
            panic!("expected tcp")
        };
        assert_eq!((t.payload_len, t.wire_payload_len), (3000, 3000));
    }

    #[test]
    fn ethernet_padding_is_not_payload() {
        // A minimum-size frame: 2 UDP payload bytes, then padding.
        let mut f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"hi");
        f.resize(60, 0);
        let parsed = parse_eth(&f).unwrap();
        assert_eq!(parsed.ip.as_ref().unwrap().l3_len, 30);
        let ParsedL4::Udp(u) = parsed.l4.unwrap() else {
            panic!("expected udp")
        };
        assert_eq!((u.payload_len, u.wire_payload_len), (2, 2));
    }

    #[test]
    fn udp_surplus_area_is_not_a_truncation() {
        // UDP length 38 (30-byte payload) inside a 48-byte IP payload:
        // 10 bytes after the datagram (UDP options / trailing data).
        let mut f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 5353, 53, &[1; 40]);
        f[14 + 20 + 4..14 + 20 + 6].copy_from_slice(&38u16.to_be_bytes());
        let parsed = parse_eth(&f).unwrap();
        let ParsedL4::Udp(u) = parsed.l4.unwrap() else {
            panic!("expected udp")
        };
        assert_eq!((u.payload_len, u.wire_payload_len), (30, 30));
        // Cut: the UDP length field gives the datagram's wire size.
        f.truncate(14 + 20 + 8 + 5);
        let ParsedL4::Udp(u) = parse_eth(&f).unwrap().l4.unwrap() else {
            panic!("expected udp")
        };
        assert_eq!((u.payload_len, u.wire_payload_len), (5, 30));
    }

    #[test]
    fn lax_ipv6_tcp_reports_wire_payload_len() {
        let mut f = ipv6_tcp([1; 16], [2; 16], 1234, 443, 7, 0x10, &[b'y'; 500]);
        f.truncate(14 + 40 + 20 + 30);
        let parsed = parse_eth(&f).expect("a cut IPv6 segment is parsed");
        assert_eq!(parsed.ip.as_ref().unwrap().l3_len, 40 + 20 + 500);
        let ParsedL4::Tcp(t) = parsed.l4.unwrap() else {
            panic!("expected tcp")
        };
        assert_eq!((t.payload_len, t.wire_payload_len), (30, 500));
    }

    #[test]
    fn byte_offset_basic() {
        let outer = [0u8, 1, 2, 3, 4, 5];
        let inner = &outer[2..4];
        assert_eq!(byte_offset(&outer, inner), Some(2));
    }

    #[test]
    fn byte_offset_disjoint_returns_none() {
        let outer = [0u8; 4];
        let other = [0u8; 4];
        assert_eq!(byte_offset(&outer, &other[..]), None);
    }
}

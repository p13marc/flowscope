//! 0.14.1 regression: `datagram_broadcast(IcmpParser::new())` must
//! actually deliver `IcmpMessage`s when ICMP frames are tracked.
//!
//! Before 0.14.1 the datagram driver's payload extractor handled only
//! UDP (`TransportSlice::Udp`), so the ICMP parser was never fed and
//! the slot drained nothing — silently breaking ICMP-error correlation.

#![cfg(all(feature = "icmp", feature = "extractors", feature = "tracker"))]

use flowscope::{PacketView, Timestamp, driver::Driver, extract::FiveTuple, icmp::IcmpParser};

/// Build an Ethernet/IPv4/ICMPv4 Port-Unreachable frame carrying an
/// inner IPv4+TCP header (the original 5-tuple).
fn icmpv4_dest_unreach_frame() -> Vec<u8> {
    use etherparse::{Ethernet2Header, IpNumber, Ipv4Header};

    let mut inner = Vec::new();
    inner.extend_from_slice(&[0x45, 0, 0x00, 0x28, 0, 0, 0, 0, 64, 6, 0, 0]);
    inner.extend_from_slice(&[10, 0, 0, 1]);
    inner.extend_from_slice(&[10, 0, 0, 2]);
    inner.extend_from_slice(&12345u16.to_be_bytes());
    inner.extend_from_slice(&80u16.to_be_bytes());
    inner.extend_from_slice(&[0, 0, 0, 1]);

    let mut icmp = vec![3u8, 3, 0, 0, 0, 0, 0, 0]; // type=3 code=3 (Port)
    icmp.extend_from_slice(&inner);

    let ip = Ipv4Header::new(
        icmp.len() as u16,
        64,
        IpNumber::ICMP,
        [192, 0, 2, 1],
        [192, 0, 2, 2],
    )
    .unwrap();
    let eth = Ethernet2Header {
        destination: [2u8; 6],
        source: [1u8; 6],
        ether_type: etherparse::EtherType::IPV4,
    };
    let mut frame = Vec::new();
    eth.write(&mut frame).unwrap();
    ip.write(&mut frame).unwrap();
    frame.extend_from_slice(&icmp);
    frame
}

#[test]
fn datagram_broadcast_delivers_icmp_messages() {
    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut handle = builder.datagram_broadcast(IcmpParser::new());
    let mut driver = builder.build();

    let frame = icmpv4_dest_unreach_frame();
    let mut events = Vec::new();
    driver.track_into(PacketView::new(&frame, Timestamp::new(1, 0)), &mut events);

    let mut msgs = Vec::new();
    let n = handle.drain(&mut msgs);
    assert_eq!(n, 1, "ICMP message delivered through the datagram slot");

    // The message classifies as an error carrying the inner 5-tuple.
    assert!(msgs[0].message.is_error());
    let (_, inner) = msgs[0].message.error_inner().expect("has inner");
    assert_eq!(inner.proto, flowscope::extractor::L4Proto::Tcp);
    assert_eq!(inner.dst_port, Some(80));
}

/// Build an Ethernet/IPv4/UDP frame to port 53 with a DNS-looking
/// payload whose first byte (3) is also a valid ICMP type.
fn udp_dns_frame() -> Vec<u8> {
    use etherparse::{Ethernet2Header, IpNumber, Ipv4Header, UdpHeader};
    let payload = [
        3u8, 3, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, b'w', b'w', b'w', 0, 0, 1, 0, 1,
    ];
    let udp = UdpHeader::without_ipv4_checksum(40000, 53, payload.len()).unwrap();
    let ip = Ipv4Header::new(
        (8 + payload.len()) as u16,
        64,
        IpNumber::UDP,
        [192, 0, 2, 1],
        [192, 0, 2, 53],
    )
    .unwrap();
    let mut frame = Vec::new();
    Ethernet2Header {
        destination: [2u8; 6],
        source: [1u8; 6],
        ether_type: etherparse::EtherType::IPV4,
    }
    .write(&mut frame)
    .unwrap();
    ip.write(&mut frame).unwrap();
    udp.write(&mut frame).unwrap();
    frame.extend_from_slice(&payload);
    frame
}

/// Issue #186: an ICMP parser registered with `datagram_broadcast`
/// used to parse every UDP payload (DNS bytes became fake ICMP
/// messages). It reads ICMP only.
#[test]
fn icmp_parser_ignores_udp() {
    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut handle = builder.datagram_broadcast(IcmpParser::new());
    let mut driver = builder.build();
    let mut events = Vec::new();
    let frame = udp_dns_frame();
    driver.track_into(PacketView::new(&frame, Timestamp::new(1, 0)), &mut events);
    driver.finish_into(&mut events);
    let mut msgs = Vec::new();
    assert_eq!(
        handle.drain(&mut msgs),
        0,
        "no ICMP message from a UDP payload"
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, flowscope::driver::Event::ParserClosed { .. })),
        "no ICMP parser was ever created for the UDP flow"
    );
}

/// Issue #186: a UDP parser (default transports) never receives an
/// ICMP message.
#[test]
fn udp_broadcast_ignores_icmp() {
    #[derive(Default, Clone)]
    struct AnyBytes;
    impl flowscope::DatagramParser for AnyBytes {
        type Message = usize;
        fn parse(&mut self, p: &[u8], _: flowscope::FlowSide, _: Timestamp, out: &mut Vec<usize>) {
            out.push(p.len());
        }
    }
    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut handle = builder.datagram_broadcast(AnyBytes);
    let mut driver = builder.build();
    let mut events = Vec::new();
    let icmp = icmpv4_dest_unreach_frame();
    let udp = udp_dns_frame();
    driver.track_into(PacketView::new(&icmp, Timestamp::new(1, 0)), &mut events);
    driver.track_into(PacketView::new(&udp, Timestamp::new(1, 0)), &mut events);
    let mut msgs = Vec::new();
    assert_eq!(handle.drain(&mut msgs), 1, "only the UDP datagram");
    assert_eq!(msgs[0].message, 21);
}

/// A parser that opts into every transport sees ICMP and UDP.
#[test]
fn transports_opt_in_admits_icmp() {
    #[derive(Default, Clone)]
    struct Both;
    impl flowscope::DatagramParser for Both {
        type Message = ();
        fn parse(&mut self, _: &[u8], _: flowscope::FlowSide, _: Timestamp, out: &mut Vec<()>) {
            out.push(());
        }
        fn transports(&self) -> flowscope::Transports {
            flowscope::Transports::UDP | flowscope::Transports::ICMP_ANY
        }
    }
    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut handle = builder.datagram_broadcast(Both);
    let mut driver = builder.build();
    let mut events = Vec::new();
    let icmp = icmpv4_dest_unreach_frame();
    let udp = udp_dns_frame();
    driver.track_into(PacketView::new(&icmp, Timestamp::new(1, 0)), &mut events);
    driver.track_into(PacketView::new(&udp, Timestamp::new(1, 0)), &mut events);
    let mut msgs = Vec::new();
    assert_eq!(handle.drain(&mut msgs), 2);
}

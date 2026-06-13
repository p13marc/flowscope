//! 0.14.1 regression: `datagram_broadcast(IcmpParser::new())` must
//! actually deliver `IcmpMessage`s when ICMP frames are tracked.
//!
//! Before 0.14.1 the datagram driver's payload extractor handled only
//! UDP (`TransportSlice::Udp`), so the ICMP parser was never fed and
//! the slot drained nothing — silently breaking ICMP-error correlation.

#![cfg(all(feature = "icmp", feature = "extractors", feature = "tracker"))]

use flowscope::driver::Driver;
use flowscope::extract::FiveTuple;
use flowscope::icmp::IcmpParser;
use flowscope::{PacketView, Timestamp};

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

    let ip = Ipv4Header::new(icmp.len() as u16, 64, IpNumber::ICMP, [192, 0, 2, 1], [192, 0, 2, 2])
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

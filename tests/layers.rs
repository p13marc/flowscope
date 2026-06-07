//! Plan 94 Tier 3 — public `flowscope::layers` per-packet view.

#![cfg(all(feature = "extractors", feature = "test-helpers"))]

use flowscope::extract::parse::test_frames::{ipv4_tcp, ipv4_udp, ipv6_tcp};
use flowscope::layers::{Layer, LayerKind, Layers};
use flowscope::{PacketView, Timestamp};

#[test]
fn pv_layers_accessor() {
    let f = ipv4_tcp(
        [0; 6],
        [0; 6],
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        12345,
        80,
        1000,
        0,
        0x02,
        b"",
    );
    let pv = PacketView::new(&f, Timestamp::default());
    let layers = pv.layers().expect("parse");
    assert!(layers.tcp().is_some());
    assert_eq!(layers.tcp().unwrap().src_port(), 12345);
}

#[test]
fn dynamic_walk_outer_to_inner() {
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
    let kinds: Vec<_> = layers.iter().map(|l| l.kind()).collect();
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
fn find_returns_first_by_kind() {
    let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 5353, 53, b"hi");
    let layers = Layers::parse_ethernet(&f).unwrap();
    let ip = layers.find(LayerKind::Ipv4).unwrap();
    assert!(matches!(ip, Layer::Ipv4(_)));
    let udp = layers.find(LayerKind::Udp).unwrap();
    assert!(matches!(udp, Layer::Udp(_)));
}

#[test]
fn l_group_helpers_pick_outermost() {
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
fn ipv6_flow_label_exposed() {
    // ipv6_tcp helper sets flow_label = 0 — verify accessor at least works.
    let f = ipv6_tcp(
        [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
        [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
        12345,
        443,
        500,
        0x02,
        b"",
    );
    let layers = Layers::parse_ethernet(&f).unwrap();
    let ip6 = layers.ipv6().unwrap();
    assert_eq!(ip6.flow_label(), 0);
    assert_eq!(ip6.next_header(), 6); // TCP
}

#[test]
fn tcp_options_default_frame_is_empty() {
    // ipv4_tcp does not insert TCP options.
    let f = ipv4_tcp(
        [0; 6],
        [0; 6],
        [1, 2, 3, 4],
        [5, 6, 7, 8],
        10,
        20,
        0,
        0,
        0x02,
        b"",
    );
    let layers = Layers::parse_ethernet(&f).unwrap();
    let tcp = layers.tcp().unwrap();
    let opts: Vec<_> = tcp.options().collect();
    assert!(opts.is_empty());
    assert_eq!(tcp.data_offset(), 5); // 20-byte header
}

#[test]
fn truncated_frame_errors_with_layers_module() {
    use flowscope::{ErrorCode, Module};
    let err = Layers::parse_ethernet(&[0u8; 4]).err().unwrap();
    assert_eq!(err.module(), Module::Layers);
    assert_eq!(err.code(), ErrorCode::Parse);
}

#[test]
fn payload_is_what_l4_left() {
    let payload = b"hello, layers!";
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

#[test]
fn depth_counts_real_layers_not_payload() {
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
    // Eth + IPv4 + TCP = 3 real layers (Payload doesn't count).
    assert_eq!(layers.depth(), 3);
}

#[test]
fn parse_ip_raw_datagram() {
    // Manually build an IPv4 + UDP packet (no Ethernet prefix).
    use etherparse::{IpNumber, Ipv4Header, UdpHeader};
    let payload = b"ip-raw";
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

    let layers = Layers::parse_ip(&buf).unwrap();
    assert!(layers.ipv4().is_some());
    assert!(layers.udp().is_some());
    assert_eq!(layers.udp().unwrap().payload(), payload);
}

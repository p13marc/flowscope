//! Encapsulated TCP: the reassembled bytes are the *inner* TCP
//! payload (issue #190 — before 0.25 the inner payload offset was
//! applied to the outer frame), and the session engine's port
//! selectors / datagram payloads come from the inner packet.

use etherparse::{Ethernet2Header, IpNumber, Ipv4Header, TcpHeader, UdpHeader};
use flowscope::extract::{FiveTuple, InnerGre, InnerGtpU, InnerVxlan, StripMpls};
use flowscope::{
    BufferedReassemblerFactory, Extracted, FlowDriver, FlowExtractor, FlowSide, PacketView,
    SessionParser, StreamChunks, Timestamp,
};

const INNER_PAYLOAD: &[u8] = b"inner application bytes";

fn inner_ipv4_tcp(seq: u32, flags_syn: bool, payload: &[u8]) -> Vec<u8> {
    let mut tcp = TcpHeader::new(40_000, 80, seq, 8192);
    tcp.syn = flags_syn;
    tcp.ack = !flags_syn;
    tcp.psh = !payload.is_empty();
    let ip = Ipv4Header::new(
        (tcp.header_len() + payload.len()) as u16,
        64,
        IpNumber::TCP,
        [192, 168, 1, 1],
        [192, 168, 1, 2],
    )
    .unwrap();
    let mut out = Vec::new();
    ip.write(&mut out).unwrap();
    tcp.write(&mut out).unwrap();
    out.extend_from_slice(payload);
    out
}

fn eth(ethertype: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    Ethernet2Header {
        destination: [2; 6],
        source: [4; 6],
        ether_type: ethertype.into(),
    }
    .write(&mut out)
    .unwrap();
    out.extend_from_slice(body);
    out
}

fn outer_ipv4(proto: IpNumber, body: &[u8]) -> Vec<u8> {
    let ip = Ipv4Header::new(body.len() as u16, 64, proto, [10, 0, 0, 1], [10, 0, 0, 2]).unwrap();
    let mut out = Vec::new();
    ip.write(&mut out).unwrap();
    out.extend_from_slice(body);
    eth(0x0800, &out)
}

fn outer_udp(port: u16, body: &[u8]) -> Vec<u8> {
    let udp = UdpHeader::without_ipv4_checksum(5555, port, body.len()).unwrap();
    let mut out = Vec::new();
    udp.write(&mut out).unwrap();
    out.extend_from_slice(body);
    outer_ipv4(IpNumber::UDP, &out)
}

fn vxlan(inner_ip: &[u8]) -> Vec<u8> {
    let mut body = vec![0x08, 0, 0, 0, 0, 0, 42, 0];
    body.extend_from_slice(&eth(0x0800, inner_ip));
    outer_udp(4789, &body)
}

fn gtpu(inner_ip: &[u8]) -> Vec<u8> {
    let mut body = vec![0x30, 0xff];
    body.extend_from_slice(&(inner_ip.len() as u16).to_be_bytes());
    body.extend_from_slice(&7u32.to_be_bytes());
    body.extend_from_slice(inner_ip);
    outer_udp(2152, &body)
}

fn gre(inner_ip: &[u8]) -> Vec<u8> {
    let mut body = vec![0, 0, 0x08, 0x00];
    body.extend_from_slice(inner_ip);
    outer_ipv4(IpNumber::GRE, &body)
}

fn mpls(inner_ip: &[u8]) -> Vec<u8> {
    // Two labels, bottom-of-stack on the second.
    let mut body = vec![0x00, 0x01, 0x00, 0x40, 0x00, 0x02, 0x01, 0x40];
    body.extend_from_slice(inner_ip);
    eth(0x8847, &body)
}

fn reassembled<E: FlowExtractor>(ext: E, wrap: fn(&[u8]) -> Vec<u8>) -> Vec<u8> {
    let mut d = FlowDriver::new(ext, BufferedReassemblerFactory::default());
    let ts = Timestamp::new(1, 0);
    let syn = wrap(&inner_ipv4_tcp(999, true, b""));
    d.track(PacketView::new(&syn, ts));
    let data = wrap(&inner_ipv4_tcp(1000, false, INNER_PAYLOAD));
    let _ = d.track_pending(PacketView::new(&data, ts));
    let key = d.last_packet().expect("tracked").key.clone();
    let mut out = StreamChunks::new();
    assert!(d.drain_stream(&key, FlowSide::Initiator, &mut out));
    out.data().to_vec()
}

#[test]
fn vxlan_tcp_payload_is_inner_bytes() {
    assert_eq!(
        reassembled(InnerVxlan::new(FiveTuple::bidirectional()), vxlan),
        INNER_PAYLOAD
    );
}

#[test]
fn gtpu_tcp_payload_is_inner_bytes() {
    assert_eq!(
        reassembled(InnerGtpU::new(FiveTuple::bidirectional()), gtpu),
        INNER_PAYLOAD
    );
}

#[test]
fn gre_tcp_payload_is_inner_bytes() {
    assert_eq!(
        reassembled(InnerGre::new(FiveTuple::bidirectional()), gre),
        INNER_PAYLOAD
    );
}

#[test]
fn mpls_tcp_payload_is_inner_bytes() {
    assert_eq!(
        reassembled(StripMpls(FiveTuple::bidirectional()), mpls),
        INNER_PAYLOAD
    );
}

#[test]
fn extracted_l4_meta_points_into_the_outer_frame() {
    let frame = vxlan(&inner_ipv4_tcp(1000, false, INNER_PAYLOAD));
    let e = InnerVxlan::new(FiveTuple::bidirectional())
        .extract(PacketView::new(&frame, Timestamp::default()))
        .unwrap();
    let meta = e.l4_meta.expect("built-in extractors report L4 meta");
    assert_eq!(meta.ports, Some((40_000, 80)));
    assert_eq!(meta.payload(&frame), INNER_PAYLOAD);
}

/// A port-selected session parser sees the inner flow's port (80),
/// not the tunnel's (4789).
#[test]
fn session_port_selector_uses_inner_ports() {
    #[derive(Default, Clone)]
    struct Collect;
    impl SessionParser for Collect {
        type Message = Vec<u8>;
        fn feed_initiator(&mut self, b: &[u8], _: Timestamp, out: &mut Vec<Vec<u8>>) {
            out.push(b.to_vec());
        }
        fn feed_responder(&mut self, _: &[u8], _: Timestamp, _: &mut Vec<Vec<u8>>) {}
    }
    let mut b = flowscope::driver::Driver::builder(InnerVxlan::new(FiveTuple::bidirectional()));
    let mut slot = b.session_on_ports(Collect, [80]);
    let mut d = b.build();
    let ts = Timestamp::new(1, 0);
    let syn = vxlan(&inner_ipv4_tcp(999, true, b""));
    let data = vxlan(&inner_ipv4_tcp(1000, false, INNER_PAYLOAD));
    let _ = d.track(PacketView::new(&syn, ts));
    let _ = d.track(PacketView::new(&data, ts));
    let mut msgs = Vec::new();
    slot.drain(&mut msgs);
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].message, INNER_PAYLOAD);
}

/// Custom extractors that report no `L4Meta` keep working: the
/// engine falls back to parsing the frame.
#[test]
fn custom_extractor_without_l4_meta_falls_back() {
    #[derive(Clone)]
    struct NoMeta(FiveTuple);
    impl FlowExtractor for NoMeta {
        type Key = <FiveTuple as FlowExtractor>::Key;
        fn extract(&self, v: PacketView<'_>) -> Option<Extracted<Self::Key>> {
            let e = self.0.extract(v)?;
            Some(Extracted::new(e.key, e.orientation, e.l4, e.tcp))
        }
    }
    #[derive(Default, Clone)]
    struct Count;
    impl SessionParser for Count {
        type Message = usize;
        fn feed_initiator(&mut self, b: &[u8], _: Timestamp, out: &mut Vec<usize>) {
            out.push(b.len());
        }
        fn feed_responder(&mut self, _: &[u8], _: Timestamp, _: &mut Vec<usize>) {}
    }
    let mut b = flowscope::driver::Driver::builder(NoMeta(FiveTuple::bidirectional()));
    let mut slot = b.session_on_ports(Count, [80]);
    let mut d = b.build();
    let ts = Timestamp::new(1, 0);
    let syn = eth(0x0800, &inner_ipv4_tcp(999, true, b""));
    let data = eth(0x0800, &inner_ipv4_tcp(1000, false, INNER_PAYLOAD));
    let _ = d.track(PacketView::new(&syn, ts));
    let _ = d.track(PacketView::new(&data, ts));
    let mut msgs = Vec::new();
    slot.drain(&mut msgs);
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].message, INNER_PAYLOAD.len());
}

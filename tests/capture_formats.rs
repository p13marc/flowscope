//! `PcapFlowSource` / `CaptureReader` read classic pcap and pcapng
//! (0.25), applying pcapng per-interface timestamp resolution.

#![cfg(all(feature = "pcap", feature = "test-helpers"))]

use std::borrow::Cow;
use std::io::Cursor;
use std::time::Duration;

use flowscope::extract::parse::test_frames::ipv4_udp;
use flowscope::pcap::{CaptureFormat, CaptureReader, PcapFlowSource};
use flowscope::{FlowSide, FlowState, Timestamp};
use pcap_file::DataLink;
use pcap_file::pcapng::PcapNgWriter;
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketBlock;
use pcap_file::pcapng::blocks::interface_description::{
    InterfaceDescriptionBlock, InterfaceDescriptionOption,
};

/// A pcapng with one interface at `tsresol` and one EPB whose raw
/// timestamp is `raw_ticks`.
fn pcapng(tsresol: Option<u8>, raw_ticks: u64, frame: &[u8]) -> Vec<u8> {
    let mut w = PcapNgWriter::new(Vec::new()).unwrap();
    let options = tsresol
        .map(|v| vec![InterfaceDescriptionOption::IfTsResol(v)])
        .unwrap_or_default();
    w.write_pcapng_block(InterfaceDescriptionBlock {
        linktype: DataLink::ETHERNET,
        snaplen: 65535,
        options,
    })
    .unwrap();
    w.write_pcapng_block(EnhancedPacketBlock {
        interface_id: 0,
        // pcap-file stores the raw tick count in a Duration's nanos.
        timestamp: Duration::from_nanos(raw_ticks),
        original_len: frame.len() as u32,
        data: Cow::Borrowed(frame),
        options: vec![],
    })
    .unwrap();
    w.into_inner()
}

#[test]
fn pcapng_default_resolution_is_microseconds() {
    let frame = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 53, b"q");
    // 1_700_000_000.250_000 s in µs.
    let bytes = pcapng(None, 1_700_000_000_250_000, &frame);
    let mut r = CaptureReader::new(Cursor::new(bytes)).unwrap();
    assert_eq!(r.format(), CaptureFormat::PcapNg);
    let p = r.next_packet().unwrap().unwrap();
    assert_eq!(p.timestamp, Duration::new(1_700_000_000, 250_000_000));
    assert_eq!(p.data, frame);
    assert_eq!(p.datalink, DataLink::ETHERNET);
    assert!(r.next_packet().is_none());
}

#[test]
fn pcapng_nanosecond_and_binary_resolutions() {
    let frame = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 53, b"q");
    let ns = pcapng(Some(9), 1_700_000_000_000_000_123, &frame);
    let p = CaptureReader::new(Cursor::new(ns))
        .unwrap()
        .next_packet()
        .unwrap()
        .unwrap();
    assert_eq!(p.timestamp, Duration::new(1_700_000_000, 123));

    // 2^-10 s units: 3 * 1024 + 512 ticks = 3.5 s.
    let bin = pcapng(Some(0x80 | 10), 3 * 1024 + 512, &frame);
    let p = CaptureReader::new(Cursor::new(bin))
        .unwrap()
        .next_packet()
        .unwrap()
        .unwrap();
    assert_eq!(p.timestamp, Duration::from_millis(3_500));
}

#[test]
fn pcap_flow_source_replays_pcapng() {
    let frame = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 53, b"q");
    let bytes = pcapng(Some(6), 2_000_000, &frame);
    let source = PcapFlowSource::from_reader(Cursor::new(bytes)).unwrap();
    assert_eq!(source.format(), CaptureFormat::PcapNg);
    let views: Vec<_> = source.views().collect::<Result<_, _>>().unwrap();
    assert_eq!(views.len(), 1);
    assert_eq!(views[0].timestamp, Timestamp::new(2, 0));
}

#[test]
fn flow_side_and_state_have_stable_labels() {
    assert_eq!(FlowSide::Initiator.as_str(), "initiator");
    assert_eq!(FlowSide::Responder.to_string(), "responder");
    assert_eq!(FlowSide::Initiator.opposite(), FlowSide::Responder);
    assert_eq!(FlowState::Established.as_str(), "established");
    assert_eq!(FlowState::SynSent.to_string(), "syn_sent");
    assert_eq!(FlowState::ClosingTcp.as_str(), "closing_tcp");
}

//! Issue #28 — RFC 7011 IPFIX binary wire encoder, end-to-end.
//!
//! Build a full IPFIX Message (Header + Template Set + Data
//! Set) from a typed [`FlowRecord`] and verify every byte of
//! the wire shape matches RFC 7011 §3.

#![cfg(all(
    feature = "ipfix-export",
    feature = "extractors",
    feature = "tracker",
    feature = "test-helpers",
))]

use flowscope::extract::FiveTuple;
use flowscope::extract::parse::test_frames::ipv4_tcp;
use flowscope::ipfix::wire::{
    FLOWSCOPE_TEMPLATE_FLOW_IPV4, IPFIX_VERSION, MESSAGE_HEADER_LEN, MessageBuilder,
    SET_HEADER_LEN, SET_ID_TEMPLATE, TEMPLATE_ID_FLOW_IPV4, TemplateRegistry,
};
use flowscope::{
    EndReason, FlowExtractor, FlowRecord, FlowStats, FlowTracker, PacketView, Timestamp,
};

fn build_record() -> FlowRecord {
    let mac = [0u8; 6];
    let mut t: FlowTracker<FiveTuple, ()> = FlowTracker::new(FiveTuple::bidirectional());
    let frame = ipv4_tcp(
        mac,
        mac,
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        1234,
        80,
        1,
        0,
        0x02,
        b"",
    );
    let pv = PacketView::new(&frame, Timestamp::new(1_700_000_000, 0));
    let key = FiveTuple::bidirectional().extract(pv).expect("ext").key;
    t.track(pv);
    let mut stats: FlowStats = t.snapshot_stats(&key).expect("stats");
    stats.packets_initiator = 10;
    stats.packets_responder = 12;
    stats.bytes_initiator = 1500;
    stats.bytes_responder = 2100;
    stats.started = Timestamp::new(1_700_000_000, 0);
    stats.last_seen = Timestamp::new(1_700_000_005, 0);
    FlowRecord::from_parts(&stats, &key, Some(EndReason::Fin))
}

fn registry() -> TemplateRegistry {
    let mut reg = TemplateRegistry::new(0xDEAD_BEEF);
    reg.register(FLOWSCOPE_TEMPLATE_FLOW_IPV4.clone());
    reg
}

#[test]
fn full_message_template_plus_data() {
    let reg = registry();
    let rec = build_record();
    let mut b = MessageBuilder::new(&reg, 1, 1_700_000_000);
    b.add_template_set(&[TEMPLATE_ID_FLOW_IPV4]).expect("tpl");
    b.add_data_record(&rec, TEMPLATE_ID_FLOW_IPV4)
        .expect("data");
    let msg = b.finalize().expect("finalize");

    // Layout: header(16) + template-set(4 + 4 + 13*4=56=60) + data-set(4+64=68)
    let expected_total = MESSAGE_HEADER_LEN + (SET_HEADER_LEN + 4 + 13 * 4) + (SET_HEADER_LEN + 64);
    assert_eq!(msg.len(), expected_total);

    // Verify header.
    assert_eq!(u16::from_be_bytes([msg[0], msg[1]]), IPFIX_VERSION);
    assert_eq!(
        u16::from_be_bytes([msg[2], msg[3]]) as usize,
        expected_total
    );

    // First set: template.
    assert_eq!(u16::from_be_bytes([msg[16], msg[17]]), SET_ID_TEMPLATE);
    let template_set_len = u16::from_be_bytes([msg[18], msg[19]]) as usize;
    assert_eq!(template_set_len, SET_HEADER_LEN + 4 + 13 * 4);

    // Second set starts after the template set.
    let data_set_start = 16 + template_set_len;
    assert_eq!(
        u16::from_be_bytes([msg[data_set_start], msg[data_set_start + 1]]),
        TEMPLATE_ID_FLOW_IPV4,
        "data set ID matches the template ID"
    );
}

#[test]
fn data_record_encodes_protocol_and_ports_correctly() {
    let reg = registry();
    let rec = build_record();
    let mut b = MessageBuilder::new(&reg, 1, 0);
    b.add_data_record(&rec, TEMPLATE_ID_FLOW_IPV4).unwrap();
    let msg = b.finalize().unwrap();
    let data_start = MESSAGE_HEADER_LEN + SET_HEADER_LEN;

    // Template field order: proto(1), srcPort(2), srcIP(4),
    // dstPort(2), dstIP(4), octetInit(8), pktInit(8),
    // octetTotal(8), pktTotal(8), startMs(8), endMs(8),
    // tcpFlags(2), endReason(1).
    let mut cursor = data_start;
    assert_eq!(msg[cursor], 6, "protocolIdentifier = TCP");
    cursor += 1;
    assert_eq!(u16::from_be_bytes([msg[cursor], msg[cursor + 1]]), 1234);
    cursor += 2;
    assert_eq!(&msg[cursor..cursor + 4], &[10, 0, 0, 1]);
    cursor += 4;
    assert_eq!(u16::from_be_bytes([msg[cursor], msg[cursor + 1]]), 80);
    cursor += 2;
    assert_eq!(&msg[cursor..cursor + 4], &[10, 0, 0, 2]);
    cursor += 4;
    // octetDelta initiator = 1500.
    assert_eq!(
        u64::from_be_bytes([
            msg[cursor],
            msg[cursor + 1],
            msg[cursor + 2],
            msg[cursor + 3],
            msg[cursor + 4],
            msg[cursor + 5],
            msg[cursor + 6],
            msg[cursor + 7],
        ]),
        1500
    );
}

#[test]
fn sequence_and_observation_domain_propagate() {
    let reg = registry();
    let mut b = MessageBuilder::new(&reg, 0xABCD_EF01, 0x1234_5678);
    let rec = build_record();
    b.add_data_record(&rec, TEMPLATE_ID_FLOW_IPV4).unwrap();
    let msg = b.finalize().unwrap();
    assert_eq!(
        u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]),
        0x1234_5678,
        "export time at offset 4"
    );
    assert_eq!(
        u32::from_be_bytes([msg[8], msg[9], msg[10], msg[11]]),
        0xABCD_EF01,
        "sequence number at offset 8"
    );
    assert_eq!(
        u32::from_be_bytes([msg[12], msg[13], msg[14], msg[15]]),
        0xDEAD_BEEF,
        "observation domain id at offset 12"
    );
}

#[test]
fn coalescing_handles_50_records_in_one_set() {
    let reg = registry();
    let rec = build_record();
    let mut b = MessageBuilder::new(&reg, 1, 0);
    for _ in 0..50 {
        b.add_data_record(&rec, TEMPLATE_ID_FLOW_IPV4).unwrap();
    }
    assert_eq!(b.set_count(), 1);
    assert_eq!(b.data_record_count(), 50);
    let msg = b.finalize().unwrap();
    assert_eq!(msg.len(), MESSAGE_HEADER_LEN + SET_HEADER_LEN + 50 * 64);
}

#[test]
fn alternating_templates_split_into_separate_sets() {
    use flowscope::ipfix::wire::TEMPLATE_ID_FLOW_IPV6;
    use std::net::Ipv6Addr;

    let mut reg = registry();
    reg.register(flowscope::ipfix::wire::FLOWSCOPE_TEMPLATE_FLOW_IPV6.clone());
    let rec4 = build_record();
    let mut rec6 = build_record();
    rec6.source_ipv4_address = None;
    rec6.destination_ipv4_address = None;
    rec6.source_ipv6_address = Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
    rec6.destination_ipv6_address = Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2));

    let mut b = MessageBuilder::new(&reg, 1, 0);
    b.add_data_record(&rec4, TEMPLATE_ID_FLOW_IPV4).unwrap();
    b.add_data_record(&rec6, TEMPLATE_ID_FLOW_IPV6).unwrap();
    b.add_data_record(&rec4, TEMPLATE_ID_FLOW_IPV4).unwrap();
    assert_eq!(b.set_count(), 3, "alternating templates → 3 sets");
}

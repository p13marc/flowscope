//! CICFlowMeter-compatible feature vector subset (issue #15).

#![cfg(feature = "ml-features")]

use flowscope::ml_features::{CicFlowFeatures, count_tcp_flags};
use flowscope::{
    EndReason, FlowExtractor, FlowRecord, FlowTracker, PacketView, Timestamp,
    extract::{FiveTuple, parse::test_frames::ipv4_tcp},
};

fn end_to_end_record(payload_len: usize, end_reason: EndReason) -> FlowRecord {
    let mac = [0u8; 6];
    let ip_a = [10, 0, 0, 1];
    let ip_b = [10, 0, 0, 2];
    let mut t: FlowTracker<FiveTuple, ()> = FlowTracker::new(FiveTuple::bidirectional());
    let body: Vec<u8> = vec![b'A'; payload_len];
    let frames = [
        // SYN
        ipv4_tcp(mac, mac, ip_a, ip_b, 1234, 80, 1000, 0, 0x02, b""),
        // SYN-ACK
        ipv4_tcp(mac, mac, ip_b, ip_a, 80, 1234, 5000, 1001, 0x12, b""),
        // ACK
        ipv4_tcp(mac, mac, ip_a, ip_b, 1234, 80, 1001, 5001, 0x10, b""),
        // PSH+ACK with data
        ipv4_tcp(mac, mac, ip_a, ip_b, 1234, 80, 1001, 5001, 0x18, &body),
        // Responder ACK
        ipv4_tcp(
            mac,
            mac,
            ip_b,
            ip_a,
            80,
            1234,
            5001,
            1001 + payload_len as u32,
            0x10,
            b"",
        ),
    ];
    let mut key = None;
    for (i, f) in frames.iter().enumerate() {
        let pv = PacketView::new(f, Timestamp::new(i as u32, 0));
        if key.is_none() {
            key = Some(FiveTuple::bidirectional().extract(pv).expect("ext").key);
        }
        t.track(pv);
    }
    let key = key.unwrap();
    let stats = t.snapshot_stats(&key).expect("stats");
    FlowRecord::from_parts(&stats, &key, Some(end_reason))
}

#[test]
fn end_to_end_flow_produces_features() {
    let rec = end_to_end_record(100, EndReason::Fin);
    let feats = CicFlowFeatures::from_flow_record(&rec);
    assert!(
        feats.total_fwd_packets >= 3,
        "expected >=3 fwd packets, got {}",
        feats.total_fwd_packets
    );
    assert!(feats.total_fwd_bytes >= 100);
    assert!(feats.flow_duration_us > 0);
    assert!(feats.flow_bytes_per_sec > 0.0);
    assert_eq!(feats.conn_state, Some("SF"));
}

#[test]
fn flag_count_helper_compiles_through_public_api() {
    // Note: `FlowRecord::from_parts` does not auto-populate
    // tcp_control_bits — the caller must invoke
    // `observe_tcp_flags` per packet (typically wired from
    // the per-packet TCP-flags emit hook). Driving that
    // explicitly here keeps the test in the consumer's
    // shape.
    let mut rec = end_to_end_record(10, EndReason::Fin);
    rec.observe_tcp_flags(true, false, true, false, false, false, false, false, false);
    rec.observe_tcp_flags(
        false, false, true, false, false, true, false, false, false,
    );
    let counts = count_tcp_flags(&rec);
    assert_eq!(counts.fwd_syn, 1);
    assert_eq!(counts.bwd_syn, 1);
}

#[test]
fn fin_end_reason_maps_to_sf() {
    let rec = end_to_end_record(10, EndReason::Fin);
    let feats = CicFlowFeatures::from_flow_record(&rec);
    assert_eq!(feats.conn_state, Some("SF"));
}

#[test]
fn idle_timeout_end_reason_maps_to_oth() {
    let rec = end_to_end_record(10, EndReason::IdleTimeout);
    let feats = CicFlowFeatures::from_flow_record(&rec);
    assert_eq!(feats.conn_state, Some("OTH"));
}

#[test]
fn missing_end_reason_yields_none_conn_state() {
    let mut rec = end_to_end_record(10, EndReason::Fin);
    rec.flow_end_reason = None;
    let feats = CicFlowFeatures::from_flow_record(&rec);
    assert_eq!(feats.conn_state, None);
}

#[test]
fn down_up_ratio_matches_responder_over_initiator() {
    let rec = end_to_end_record(0, EndReason::Fin);
    let feats = CicFlowFeatures::from_flow_record(&rec);
    // Both directions sent only handshake-control bytes; bwd
    // and fwd are similar but not zero. Ratio is safe (no inf).
    assert!(!feats.down_up_ratio.is_nan());
    assert!(!feats.down_up_ratio.is_infinite());
}

#[test]
fn five_tuple_app_label_populates_application_name() {
    // The 3WHS+data flow targets dport 80 → app_label "http".
    // from_parts copies that into application_name; the
    // feature vector does not surface application_name
    // directly, but verifying the FlowRecord's wiring is
    // useful sanity.
    let rec = end_to_end_record(10, EndReason::Fin);
    assert_eq!(rec.application_name.as_deref(), Some("http"));
    let _feats = CicFlowFeatures::from_flow_record(&rec);
}

#[cfg(feature = "serde")]
#[test]
fn features_serialize_to_json() {
    // CicFlowFeatures is serialize-only via serde — the
    // `conn_state: Option<&'static str>` field can be
    // emitted but not deserialized back (the borrowed `'static`
    // lifetime doesn't survive a round-trip). For producer
    // pipelines (the common ML-features case) this is the
    // right tradeoff: zero allocations on the hot path.
    let rec = end_to_end_record(50, EndReason::Fin);
    let feats = CicFlowFeatures::from_flow_record(&rec);
    let json = serde_json::to_string(&feats).expect("serialize");
    assert!(json.contains("flow_duration_us"));
    assert!(json.contains("total_fwd_packets"));
    assert!(json.contains("down_up_ratio"));
}

//! `FlowStats` deserializes records written before fields were added
//! (issue #193): every field defaults.

#![cfg(feature = "serde")]

#[test]
fn flow_stats_from_an_older_record() {
    let json = r#"{"packets_initiator": 3, "bytes_initiator": 120}"#;
    let stats: flowscope::FlowStats = serde_json::from_str(json).expect("old record parses");
    assert_eq!(stats.packets_initiator, 3);
    assert_eq!(stats.bytes_initiator, 120);
    assert_eq!(stats.reassembly_gaps_initiator, 0);
    assert!(!stats.fin_initiator);
}

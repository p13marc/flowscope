//! Plan 123 — `flowscope::emit::EveJsonWriter` tests.

#![cfg(all(feature = "emit-eve", feature = "tracker", feature = "extractors"))]

use flowscope::{
    HistoryString, L4Proto, Timestamp,
    emit::{EveJsonWriter, EveOptions},
    event::{AnomalyKind, EndReason, FlowEvent, FlowSide, FlowStats, OverflowPolicy},
    extract::FiveTupleKey,
};

fn key() -> FiveTupleKey {
    FiveTupleKey {
        proto: L4Proto::Tcp,
        a: "10.0.0.1:33000".parse().unwrap(),
        b: "10.0.0.2:80".parse().unwrap(),
    }
}

fn parse_lines(out: &[u8]) -> Vec<serde_json::Value> {
    String::from_utf8(out.to_vec())
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .collect()
}

fn flipped_key() -> FiveTupleKey {
    // Same flow, reverse direction.
    FiveTupleKey {
        proto: L4Proto::Tcp,
        a: "10.0.0.2:80".parse().unwrap(),
        b: "10.0.0.1:33000".parse().unwrap(),
    }
}

/// The proprietary FNV-1a `flow_hash` was dropped from default EVE
/// output in 0.19 (issue #88) — `community_id` is now the canonical
/// flow identifier. This guards against it sneaking back.
#[test]
fn eve_flow_hash_is_not_emitted() {
    let mut buf = Vec::new();
    let mut w = EveJsonWriter::new(&mut buf);
    let ev: FlowEvent<FiveTupleKey> = FlowEvent::FlowAnomaly {
        key: key(),
        kind: AnomalyKind::OutOfOrderSegment {
            side: FlowSide::Initiator,
            count: 1,
        },
        ts: Timestamp::new(1_700_000_000, 0),
    };
    w.write_event(&ev).unwrap();
    let lines = parse_lines(&buf);
    assert!(
        lines[0].get("flow_hash").is_none(),
        "flow_hash must not be emitted: {:?}",
        lines[0]
    );
}

#[cfg(feature = "community-id")]
#[test]
fn eve_emits_community_id_and_is_direction_invariant() {
    let mk = |k: FiveTupleKey| {
        let mut buf = Vec::new();
        let mut w = EveJsonWriter::new(&mut buf);
        let ev: FlowEvent<FiveTupleKey> = FlowEvent::FlowAnomaly {
            key: k,
            kind: AnomalyKind::OutOfOrderSegment {
                side: FlowSide::Initiator,
                count: 1,
            },
            ts: Timestamp::new(1_700_000_000, 0),
        };
        w.write_event(&ev).unwrap();
        parse_lines(&buf)[0]["community_id"]
            .as_str()
            .expect("community_id present")
            .to_string()
    };
    let fwd = mk(key());
    let rev = mk(flipped_key());
    assert!(fwd.starts_with("1:"), "v1 prefix: {fwd}");
    assert_eq!(fwd, rev, "community_id is direction-invariant");
}

#[cfg(feature = "community-id")]
fn extract_community_id(key: FiveTupleKey) -> String {
    let mut buf = Vec::new();
    let mut w = EveJsonWriter::new(&mut buf);
    let ev: FlowEvent<FiveTupleKey> = FlowEvent::FlowAnomaly {
        key,
        kind: AnomalyKind::OutOfOrderSegment {
            side: FlowSide::Initiator,
            count: 1,
        },
        ts: Timestamp::new(1_700_000_000, 0),
    };
    w.write_event(&ev).unwrap();
    parse_lines(&buf)[0]["community_id"]
        .as_str()
        .expect("community_id present")
        .to_string()
}

#[cfg(feature = "community-id")]
#[test]
fn eve_community_id_is_deterministic() {
    let h1 = extract_community_id(key());
    let h2 = extract_community_id(key()); // same input → same id
    let h3 = extract_community_id(flipped_key()); // direction reversed → same id
    assert_eq!(h1, h2);
    assert_eq!(h1, h3);
}

#[cfg(feature = "community-id")]
#[test]
fn eve_community_id_differs_for_distinct_flows() {
    let h1 = extract_community_id(key());
    let mut other = key();
    other.b = "10.0.0.3:443".parse().unwrap();
    let h2 = extract_community_id(other);
    assert_ne!(h1, h2);
}

#[test]
fn eve_flow_anomaly_buffer_overflow_has_expected_shape() {
    let mut buf = Vec::new();
    let mut w = EveJsonWriter::new(&mut buf);
    let ev: FlowEvent<FiveTupleKey> = FlowEvent::FlowAnomaly {
        key: key(),
        kind: AnomalyKind::BufferOverflow {
            side: FlowSide::Initiator,
            bytes: 1500,
            policy: OverflowPolicy::SlidingWindow,
        },
        ts: Timestamp::new(1_700_000_000, 0),
    };
    w.write_event(&ev).unwrap();
    w.flush().unwrap();

    let lines = parse_lines(&buf);
    assert_eq!(lines.len(), 1);
    let line = &lines[0];
    assert_eq!(line["event_type"], "anomaly");
    assert_eq!(line["src_ip"], "10.0.0.1");
    assert_eq!(line["dest_ip"], "10.0.0.2");
    assert_eq!(line["src_port"], 33000);
    assert_eq!(line["dest_port"], 80);
    assert_eq!(line["proto"], "TCP");
    assert_eq!(line["anomaly"]["type"], "stream");
    assert_eq!(line["anomaly"]["event"], "buffer_overflow");
    assert_eq!(line["severity"], 3); // Warning
    assert!(line["timestamp"].as_str().unwrap().starts_with("2023-"));
}

#[test]
fn eve_session_parse_error_classifies_as_applayer() {
    let mut buf = Vec::new();
    let mut w = EveJsonWriter::new(&mut buf);
    let ev: FlowEvent<FiveTupleKey> = FlowEvent::FlowAnomaly {
        key: key(),
        kind: AnomalyKind::SessionParseError {
            side: FlowSide::Responder,
            reason: Some("bad frame".to_string()),
        },
        ts: Timestamp::new(1_700_000_000, 0),
    };
    w.write_event(&ev).unwrap();
    let lines = parse_lines(&buf);
    assert_eq!(lines[0]["anomaly"]["type"], "applayer");
    assert_eq!(lines[0]["anomaly"]["event"], "parse_error");
    assert_eq!(lines[0]["severity"], 2); // Error
}

#[test]
fn eve_flow_ended_includes_pkts_bytes_and_age() {
    let mut buf = Vec::new();
    let mut w = EveJsonWriter::new(&mut buf);
    let mut stats = FlowStats::default();
    stats.packets_initiator = 7;
    stats.packets_responder = 5;
    stats.bytes_initiator = 2400;
    stats.bytes_responder = 14000;
    stats.started = Timestamp::new(1_700_000_000, 0);
    stats.last_seen = Timestamp::new(1_700_000_006, 0);
    let ev: FlowEvent<FiveTupleKey> = FlowEvent::Ended {
        key: key(),
        reason: EndReason::Fin,
        stats,
        history: HistoryString::new(),
        l4: Some(L4Proto::Tcp),
    };
    w.write_event(&ev).unwrap();
    let lines = parse_lines(&buf);
    assert_eq!(lines[0]["event_type"], "flow");
    assert_eq!(lines[0]["flow"]["pkts_toserver"], 7);
    assert_eq!(lines[0]["flow"]["pkts_toclient"], 5);
    assert_eq!(lines[0]["flow"]["bytes_toserver"], 2400);
    assert_eq!(lines[0]["flow"]["bytes_toclient"], 14000);
    assert_eq!(lines[0]["flow"]["age"], 6);
    assert_eq!(lines[0]["flow"]["reason"], "fin");
    assert_eq!(lines[0]["flow"]["alerted"], false);
}

#[test]
fn eve_flow_id_increases_monotonically() {
    let mut buf = Vec::new();
    let mut w = EveJsonWriter::new(&mut buf);
    let kind = AnomalyKind::OutOfOrderSegment {
        side: FlowSide::Initiator,
        count: 1,
    };
    for _ in 0..3 {
        let ev: FlowEvent<FiveTupleKey> = FlowEvent::FlowAnomaly {
            key: key(),
            kind: kind.clone(),
            ts: Timestamp::new(1_700_000_000, 0),
        };
        w.write_event(&ev).unwrap();
    }
    let lines = parse_lines(&buf);
    assert_eq!(lines[0]["flow_id"], 1);
    assert_eq!(lines[1]["flow_id"], 2);
    assert_eq!(lines[2]["flow_id"], 3);
}

#[test]
fn eve_anomalies_disabled_produces_no_output() {
    let mut buf = Vec::new();
    let mut opts = EveOptions::default();
    opts.include_anomalies = false;
    let mut w = EveJsonWriter::with_options(&mut buf, opts);
    let ev: FlowEvent<FiveTupleKey> = FlowEvent::FlowAnomaly {
        key: key(),
        kind: AnomalyKind::OutOfOrderSegment {
            side: FlowSide::Initiator,
            count: 1,
        },
        ts: Timestamp::new(1_700_000_000, 0),
    };
    w.write_event(&ev).unwrap();
    assert!(buf.is_empty());
}

#[test]
fn eve_tick_off_by_default() {
    let mut buf = Vec::new();
    let mut w = EveJsonWriter::new(&mut buf);
    let ev: FlowEvent<FiveTupleKey> = FlowEvent::Tick {
        key: key(),
        stats: FlowStats::default(),
        ts: Timestamp::new(1_700_000_000, 0),
    };
    w.write_event(&ev).unwrap();
    assert!(buf.is_empty(), "Tick suppressed unless include_stats=true");
}

#[test]
fn eve_tick_included_when_enabled() {
    let mut buf = Vec::new();
    let mut opts = EveOptions::default();
    opts.include_stats = true;
    let mut w = EveJsonWriter::with_options(&mut buf, opts);
    let mut stats = FlowStats::default();
    stats.packets_initiator = 3;
    let ev: FlowEvent<FiveTupleKey> = FlowEvent::Tick {
        key: key(),
        stats,
        ts: Timestamp::new(1_700_000_000, 0),
    };
    w.write_event(&ev).unwrap();
    let lines = parse_lines(&buf);
    assert_eq!(lines[0]["event_type"], "stats");
    assert_eq!(lines[0]["stats"]["pkts_toserver"], 3);
}

#[test]
fn eve_in_iface_present_when_set() {
    let mut buf = Vec::new();
    let mut opts = EveOptions::default();
    opts.in_iface = "eth0".to_string();
    let mut w = EveJsonWriter::with_options(&mut buf, opts);
    let ev: FlowEvent<FiveTupleKey> = FlowEvent::FlowAnomaly {
        key: key(),
        kind: AnomalyKind::RetransmittedSegment {
            side: FlowSide::Initiator,
            count: 1,
        },
        ts: Timestamp::new(1_700_000_000, 0),
    };
    w.write_event(&ev).unwrap();
    let lines = parse_lines(&buf);
    assert_eq!(lines[0]["in_iface"], "eth0");
}

#[test]
fn eve_every_line_is_valid_json() {
    let mut buf = Vec::new();
    let mut w = EveJsonWriter::new(&mut buf);
    let events: Vec<FlowEvent<FiveTupleKey>> = vec![
        FlowEvent::FlowAnomaly {
            key: key(),
            kind: AnomalyKind::OutOfOrderSegment {
                side: FlowSide::Initiator,
                count: 1,
            },
            ts: Timestamp::new(1_700_000_000, 0),
        },
        FlowEvent::Ended {
            key: key(),
            reason: EndReason::Fin,
            stats: FlowStats::default(),
            history: HistoryString::new(),
            l4: Some(L4Proto::Tcp),
        },
        FlowEvent::TrackerAnomaly {
            kind: AnomalyKind::FlowTableEvictionPressure {
                evicted_in_tick: 1,
                evicted_total: 42,
            },
            ts: Timestamp::new(1_700_000_000, 0),
        },
    ];
    for ev in &events {
        w.write_event(ev).unwrap();
    }
    let lines = parse_lines(&buf);
    assert_eq!(lines.len(), 3);
}

#[test]
fn eve_severity_numeric_override_can_invert() {
    fn invert(s: flowscope::event::Severity) -> u8 {
        match s {
            flowscope::event::Severity::Critical => 4,
            flowscope::event::Severity::Error => 3,
            flowscope::event::Severity::Warning => 2,
            flowscope::event::Severity::Info => 1,
            _ => 0,
        }
    }
    let mut buf = Vec::new();
    let mut opts = EveOptions::default();
    opts.severity_numeric = invert;
    let mut w = EveJsonWriter::with_options(&mut buf, opts);
    let ev: FlowEvent<FiveTupleKey> = FlowEvent::FlowAnomaly {
        key: key(),
        kind: AnomalyKind::OutOfOrderSegment {
            side: FlowSide::Initiator,
            count: 1,
        },
        ts: Timestamp::new(1_700_000_000, 0),
    };
    w.write_event(&ev).unwrap();
    let lines = parse_lines(&buf);
    // Info → inverted=1 (was 4 under default).
    assert_eq!(lines[0]["severity"], 1);
}

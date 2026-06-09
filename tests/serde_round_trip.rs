//! Plan 83 — serde Serialize + Deserialize round-trip tests.
//!
//! Coverage focuses on:
//! 1. Every top-level event type that consumers ship to log
//!    pipelines (FlowEvent, SessionEvent, all L7 messages, anomaly
//!    kinds).
//! 2. The wire format — snake_case + adjacent tagging — is what
//!    actually lands in serialized JSON. Renames here would break
//!    downstream dashboards.

#![cfg(feature = "serde")]

use flowscope::Timestamp;
use flowscope::event::{
    AnomalyKind, EndReason, FlowEvent, FlowSide, FlowState, FlowStats, OverflowPolicy, Severity,
};
use flowscope::extractor::L4Proto;

fn ts(sec: u32, nsec: u32) -> Timestamp {
    Timestamp::new(sec, nsec)
}

/// Round-trip helper: serialize to JSON, deserialize, assert the
/// two debug strings match (good enough for the events we cover —
/// they don't carry interior mutability or floats).
fn round_trip<T>(value: T) -> serde_json::Value
where
    T: serde::Serialize + serde::de::DeserializeOwned + std::fmt::Debug,
{
    let json = serde_json::to_value(&value).expect("serialize");
    let back: T = serde_json::from_value(json.clone()).expect("deserialize");
    assert_eq!(format!("{value:?}"), format!("{back:?}"));
    json
}

#[test]
fn timestamp_serializes_as_sec_nsec() {
    let json = round_trip(ts(1717610000, 123456789));
    assert_eq!(json["sec"], 1717610000);
    assert_eq!(json["nsec"], 123456789);
}

#[test]
fn flow_side_serializes_as_snake_case() {
    let json = round_trip(FlowSide::Initiator);
    assert_eq!(json, serde_json::json!("initiator"));
    let json = round_trip(FlowSide::Responder);
    assert_eq!(json, serde_json::json!("responder"));
}

#[test]
fn end_reason_every_variant_round_trips() {
    for r in [
        EndReason::Fin,
        EndReason::Rst,
        EndReason::IdleTimeout,
        EndReason::Evicted,
        EndReason::BufferOverflow,
        EndReason::ParseError,
        EndReason::ParserDone,
        EndReason::ForceClosed,
    ] {
        round_trip(r);
    }
    // Spot-check a specific name.
    assert_eq!(
        serde_json::to_value(EndReason::IdleTimeout).unwrap(),
        serde_json::json!("idle_timeout")
    );
    assert_eq!(
        serde_json::to_value(EndReason::ForceClosed).unwrap(),
        serde_json::json!("force_closed")
    );
}

#[test]
fn severity_every_variant_round_trips() {
    for s in [
        Severity::Info,
        Severity::Warning,
        Severity::Error,
        Severity::Critical,
    ] {
        round_trip(s);
    }
}

#[test]
fn overflow_policy_round_trips() {
    for p in [OverflowPolicy::SlidingWindow, OverflowPolicy::DropFlow] {
        round_trip(p);
    }
    assert_eq!(
        serde_json::to_value(OverflowPolicy::SlidingWindow).unwrap(),
        serde_json::json!("sliding_window")
    );
}

#[test]
fn flow_state_every_variant_round_trips() {
    for s in [
        FlowState::SynSent,
        FlowState::SynReceived,
        FlowState::Established,
        FlowState::FinWait,
        FlowState::ClosingTcp,
        FlowState::Active,
        FlowState::Closed,
        FlowState::Reset,
        FlowState::Aborted,
    ] {
        round_trip(s);
    }
}

#[test]
fn l4proto_adjacent_tagged() {
    let json = serde_json::to_value(L4Proto::Tcp).unwrap();
    assert_eq!(json, serde_json::json!({"kind": "tcp"}));
    let json = serde_json::to_value(L4Proto::Other(99)).unwrap();
    assert_eq!(json, serde_json::json!({"kind": "other", "value": 99}));
    round_trip(L4Proto::Udp);
    round_trip(L4Proto::Icmp);
    round_trip(L4Proto::IcmpV6);
    round_trip(L4Proto::Sctp);
    round_trip(L4Proto::Other(42));
}

#[test]
fn anomaly_kind_internal_tagged() {
    let kind = AnomalyKind::OutOfOrderSegment {
        side: FlowSide::Initiator,
        count: 5,
    };
    let json = serde_json::to_value(&kind).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "kind": "out_of_order_segment",
            "side": "initiator",
            "count": 5,
        })
    );
    round_trip(kind);

    let kind = AnomalyKind::ReassemblerHighWatermark {
        side: FlowSide::Responder,
        bytes: 800,
        cap: 1000,
        threshold_pct: 80,
    };
    let json = serde_json::to_value(&kind).unwrap();
    assert_eq!(json["kind"], "reassembler_high_watermark");
    assert_eq!(json["bytes"], 800);
    round_trip(kind);
}

#[test]
fn flow_event_started_round_trips() {
    let evt: FlowEvent<u32> = FlowEvent::Started {
        key: 7,
        side: FlowSide::Initiator,
        ts: ts(1234, 0),
        l4: Some(L4Proto::Tcp),
    };
    let json = serde_json::to_value(&evt).unwrap();
    assert_eq!(json["type"], "started");
    assert_eq!(json["key"], 7);
    assert_eq!(json["side"], "initiator");
    assert_eq!(json["l4"], serde_json::json!({"kind": "tcp"}));
    round_trip(evt);
}

#[test]
fn flow_event_ended_round_trips() {
    let evt: FlowEvent<u32> = FlowEvent::Ended {
        key: 7,
        reason: EndReason::Fin,
        stats: FlowStats::default(),
        history: flowscope::history::HistoryString::new(),
        l4: Some(L4Proto::Tcp),
    };
    let json = serde_json::to_value(&evt).unwrap();
    assert_eq!(json["type"], "ended");
    assert_eq!(json["reason"], "fin");
    round_trip(evt);
}

#[test]
fn flow_event_all_variants_round_trip() {
    let key: u32 = 42;
    let evts = vec![
        FlowEvent::Started {
            key,
            side: FlowSide::Initiator,
            ts: ts(1, 0),
            l4: Some(L4Proto::Tcp),
        },
        FlowEvent::Packet {
            key,
            side: FlowSide::Responder,
            len: 100,
            ts: ts(2, 0),
        },
        FlowEvent::Established {
            key,
            ts: ts(3, 0),
            l4: Some(L4Proto::Tcp),
        },
        FlowEvent::StateChange {
            key,
            from: FlowState::SynSent,
            to: FlowState::Established,
            ts: ts(4, 0),
        },
        FlowEvent::Ended {
            key,
            reason: EndReason::IdleTimeout,
            stats: FlowStats::default(),
            history: flowscope::history::HistoryString::new(),
            l4: Some(L4Proto::Tcp),
        },
        FlowEvent::FlowAnomaly {
            key,
            kind: AnomalyKind::OutOfOrderSegment {
                side: FlowSide::Initiator,
                count: 1,
            },
            ts: ts(5, 0),
        },
        FlowEvent::TrackerAnomaly {
            kind: AnomalyKind::FlowTableEvictionPressure {
                evicted_in_tick: 1,
                evicted_total: 42,
            },
            ts: ts(6, 0),
        },
        FlowEvent::Tick {
            key,
            stats: FlowStats::default(),
            ts: ts(7, 0),
        },
    ];
    for evt in evts {
        round_trip(evt);
    }
}

#[cfg(feature = "http")]
#[test]
fn http_message_round_trips() {
    use bytes::Bytes;
    use flowscope::http::{HttpMessage, HttpRequest, HttpResponse, HttpVersion};
    let req = HttpRequest {
        method: Bytes::from_static(b"GET"),
        path: Bytes::from_static(b"/"),
        version: HttpVersion::Http1_1,
        headers: vec![(
            Bytes::from_static(b"Host"),
            Bytes::from_static(b"example.com"),
        )],
        body: Bytes::new(),
    };
    let msg = HttpMessage::Request(req);
    let json = serde_json::to_value(&msg).unwrap();
    assert_eq!(json["type"], "request");
    round_trip(msg);

    let resp = HttpResponse {
        status: 200,
        reason: Bytes::from_static(b"OK"),
        version: HttpVersion::Http1_1,
        headers: vec![],
        body: Bytes::new(),
    };
    round_trip(HttpMessage::Response(resp));
}

#[cfg(feature = "dns")]
#[test]
fn dns_message_query_round_trips() {
    use flowscope::dns::{DnsFlags, DnsMessage, DnsQuery, DnsQuestion};
    let q = DnsQuery {
        transaction_id: 0x1234,
        flags: DnsFlags(0x0100),
        questions: vec![DnsQuestion {
            name: "example.com".to_string(),
            qtype: 1,
            qclass: 1,
        }],
        timestamp: ts(0, 0),
    };
    let msg = DnsMessage::Query(q);
    let json = serde_json::to_value(&msg).unwrap();
    assert_eq!(json["type"], "query");
    round_trip(msg);
}

#[cfg(feature = "icmp")]
#[test]
fn icmp_message_round_trips() {
    use flowscope::icmp::{IcmpFamily, IcmpMessage, IcmpType, Icmpv4Type};
    let msg = IcmpMessage {
        family: IcmpFamily::V4,
        ty: IcmpType::V4(Icmpv4Type::EchoRequest {
            id: 0x1234,
            seq: 0x5678,
        }),
    };
    let json = serde_json::to_value(&msg).unwrap();
    assert_eq!(json["family"], "v4");
    round_trip(msg);
}

#[test]
fn unknown_variant_fails_to_deserialize() {
    // Locks the forward-compat contract: an unknown enum tag MUST
    // surface as a serde error rather than silently default.
    let json = serde_json::json!({"kind": "future_variant_not_yet_defined"});
    let result: Result<L4Proto, _> = serde_json::from_value(json);
    assert!(result.is_err());
}

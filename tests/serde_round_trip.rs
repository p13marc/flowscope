//! Plan 83 — serde Serialize + Deserialize round-trip tests.
//!
//! Coverage focuses on:
//! 1. Every top-level event type that consumers ship to log
//!    pipelines (FlowEvent, all L7 messages, anomaly kinds).
//! 2. The wire format — snake_case + adjacent tagging — is what
//!    actually lands in serialized JSON. Renames here would break
//!    downstream dashboards.

#![cfg(feature = "serde")]

use flowscope::{
    Timestamp,
    event::{
        AnomalyKind, EndReason, FlowEvent, FlowSide, FlowState, FlowStats, OverflowPolicy, Severity,
    },
    extractor::{L4Proto, Orientation},
};

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
        orientation: Orientation::Forward,
        ts: ts(1234, 0),
        l4: Some(L4Proto::Tcp),
    };
    let json = serde_json::to_value(&evt).unwrap();
    assert_eq!(json["type"], "started");
    assert_eq!(json["key"], 7);
    assert_eq!(json["side"], "initiator");
    // Issue #118: the canonical orientation axis rides alongside `side`.
    assert_eq!(json["orientation"], "forward");
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
            orientation: Orientation::Forward,
            ts: ts(1, 0),
            l4: Some(L4Proto::Tcp),
        },
        // Packet is a #[non_exhaustive] variant (0.21, #121) —
        // synthetic construction goes through test_helpers.
        flowscope::test_helpers::events::packet_side(key, FlowSide::Responder, 100, ts(2, 0)),
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
    let req = HttpRequest::new(
        Bytes::from_static(b"GET"),
        Bytes::from_static(b"/"),
        HttpVersion::Http1_1,
        vec![(
            Bytes::from_static(b"Host"),
            Bytes::from_static(b"example.com"),
        )],
        Bytes::new(),
    );
    let msg = HttpMessage::Request(req);
    let json = serde_json::to_value(&msg).unwrap();
    assert_eq!(json["type"], "request");
    round_trip(msg);

    let resp = HttpResponse::new(
        200,
        Bytes::from_static(b"OK"),
        HttpVersion::Http1_1,
        vec![],
        Bytes::new(),
    );
    round_trip(HttpMessage::Response(resp));
}

#[cfg(feature = "dns")]
#[test]
fn dns_message_query_round_trips() {
    use flowscope::dns::{DnsFlags, DnsMessage, DnsQuery, DnsQuestion};
    let q = DnsQuery::new(
        0x1234,
        DnsFlags(0x0100),
        vec![DnsQuestion::new("example.com", 1, 1)],
        ts(0, 0),
    );
    let msg = DnsMessage::Query(q);
    let json = serde_json::to_value(&msg).unwrap();
    assert_eq!(json["type"], "query");
    round_trip(msg);
}

#[cfg(feature = "icmp")]
#[test]
fn icmp_message_round_trips() {
    use flowscope::icmp::{IcmpFamily, IcmpMessage, IcmpType, Icmpv4Type};
    let msg = IcmpMessage::new(
        IcmpFamily::V4,
        IcmpType::V4(Icmpv4Type::EchoRequest {
            id: 0x1234,
            seq: 0x5678,
        }),
    );
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

// ── 0.23: the inline-proxy and HTTP/2 surface ─────────────────────
//
// These types cross a wire (EVE records, stored access logs), so
// their serde shape is part of the contract. The `rename_all` and
// `tag` attributes in particular are easy to change by accident;
// pinning the emitted JSON is what makes that a test failure rather
// than a downstream surprise.

#[cfg(feature = "http")]
#[test]
fn body_framing_uses_snake_case_slugs() {
    use flowscope::http::BodyFraming;
    assert_eq!(round_trip(BodyFraming::None), serde_json::json!("none"));
    assert_eq!(
        round_trip(BodyFraming::ContentLength(42)),
        serde_json::json!({ "content_length": 42 })
    );
    assert_eq!(
        round_trip(BodyFraming::Chunked),
        serde_json::json!("chunked")
    );
    assert_eq!(
        round_trip(BodyFraming::UntilClose),
        serde_json::json!("until_close")
    );
}

#[cfg(feature = "http")]
#[test]
fn http_poison_slugs_match_as_str() {
    use flowscope::http::HttpPoison;
    // The JSON form and the metric-label form must not drift apart:
    // an operator correlating a log line with a metric depends on
    // them being the same string.
    for p in [
        HttpPoison::HeadOverflow,
        HttpPoison::ContentLengthWithTransferEncoding,
        HttpPoison::ConflictingContentLength,
        HttpPoison::NonFinalChunked,
        HttpPoison::DuplicateHost,
        HttpPoison::UnexpectedResponse,
    ] {
        let json = round_trip(p);
        let as_str = p.as_str();
        assert_eq!(
            json.as_str().unwrap().replace('_', "-"),
            as_str,
            "serde slug and as_str() must agree for {p:?}"
        );
    }
}

#[cfg(feature = "http")]
#[test]
fn smuggling_policy_and_normalization_round_trip() {
    use flowscope::http::{Normalization, SmugglingPolicy};
    assert_eq!(
        round_trip(SmugglingPolicy::Strict),
        serde_json::json!("strict")
    );
    assert_eq!(
        round_trip(SmugglingPolicy::Normalize),
        serde_json::json!("normalize")
    );
    assert_eq!(
        round_trip(SmugglingPolicy::Observe),
        serde_json::json!("observe")
    );
    assert_eq!(
        round_trip(Normalization::StrippedContentLength),
        serde_json::json!("stripped_content_length")
    );
}

#[cfg(feature = "http")]
#[test]
fn access_outcome_is_internally_tagged_on_kind() {
    use flowscope::http::{HttpAccessOutcome, HttpPoison};
    assert_eq!(
        round_trip(HttpAccessOutcome::Completed),
        serde_json::json!({ "kind": "completed" })
    );
    assert_eq!(
        round_trip(HttpAccessOutcome::NoResponse),
        serde_json::json!({ "kind": "no_response" })
    );
    // The payload-carrying variant is the one most likely to break
    // silently if the tag attribute changes.
    assert_eq!(
        round_trip(HttpAccessOutcome::Refused {
            reason: HttpPoison::BareCr
        }),
        serde_json::json!({ "kind": "refused", "reason": "bare_cr" })
    );
}

#[cfg(feature = "http")]
#[test]
fn access_record_round_trips_from_the_consumer_side() {
    use flowscope::http::HttpAccessRecord;
    // The record is `#[non_exhaustive]` — a consumer receives it, it
    // does not build it. So the direction worth pinning is the one a
    // consumer actually uses: reading a stored record back.
    let stored = serde_json::json!({
        "method": [80, 79, 83, 84],
        "path": [47, 111],
        "authority": "api.example",
        "version": "http1_1",
        "status": 201,
        "request_body_bytes": 5,
        "response_body_bytes": 2,
        "outcome": { "kind": "completed" }
    });
    let rec: HttpAccessRecord =
        serde_json::from_value(stored.clone()).expect("a stored record must deserialize");
    assert_eq!(rec.method_str(), Some("POST"));
    assert_eq!(rec.status, Some(201));
    assert_eq!(rec.request_body_bytes, 5);
    // And back out unchanged.
    assert_eq!(serde_json::to_value(&rec).unwrap(), stored);
}

#[test]
fn wire_protocol_round_trips() {
    use flowscope::classify::WireProtocol;
    assert_eq!(round_trip(WireProtocol::Tls), serde_json::json!("tls"));
    assert_eq!(round_trip(WireProtocol::Http1), serde_json::json!("http1"));
    assert_eq!(
        round_trip(WireProtocol::Http2Preface),
        serde_json::json!("http2_preface")
    );
    assert_eq!(round_trip(WireProtocol::Raw), serde_json::json!("raw"));
}

#[cfg(feature = "http2")]
#[test]
fn http2_error_round_trips() {
    use flowscope::http2::Http2Error;
    assert_eq!(
        round_trip(Http2Error::BadPreface),
        serde_json::json!("bad_preface")
    );
    assert_eq!(
        round_trip(Http2Error::HpackInvalidIndex),
        serde_json::json!("hpack_invalid_index")
    );
}

#[cfg(feature = "http2")]
#[test]
fn grpc_status_round_trips_from_the_consumer_side() {
    use flowscope::http2::GrpcStatus;
    let stored = serde_json::json!({ "code": 5, "message": [110, 111] });
    let s: GrpcStatus = serde_json::from_value(stored.clone()).expect("deserialize");
    assert_eq!(s.code, 5);
    assert_eq!(s.name(), Some("NOT_FOUND"));
    assert!(!s.is_ok());
    assert_eq!(serde_json::to_value(&s).unwrap(), stored);
}

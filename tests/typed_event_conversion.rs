//! Issue #97 — `Event<K>` emit-readiness.
//!
//! Covers the lossless `From<FlowEvent>` conversion, the reverse
//! `to_flow_event` projection (incl. `ParserClosed -> None`), serde
//! round-trips, and `emit` `write_lifecycle` parity with `write_event`.

#![cfg(all(feature = "extractors", feature = "reassembler", feature = "session"))]

use std::net::SocketAddr;

use flowscope::{
    AnomalyKind, EndReason, FlowEvent, FlowSide, FlowState, FlowStats, Timestamp, driver::Event,
    extract::FiveTupleKey, extractor::L4Proto, history::HistoryString,
};

fn key() -> FiveTupleKey {
    let a: SocketAddr = "10.0.0.1:1234".parse().unwrap();
    let b: SocketAddr = "10.0.0.2:80".parse().unwrap();
    let (a, b) = if a < b { (a, b) } else { (b, a) };
    FiveTupleKey::new(L4Proto::Tcp, a, b)
}

fn stats() -> FlowStats {
    let mut s = FlowStats::default();
    s.started = Timestamp::new(1_700_000_000, 0);
    s.last_seen = Timestamp::new(1_700_000_005, 0);
    s.packets_initiator = 4;
    s.bytes_initiator = 400;
    s
}

/// One of every `FlowEvent` variant for exhaustive conversion checks.
fn all_flow_events() -> Vec<FlowEvent<FiveTupleKey>> {
    let ts = Timestamp::new(1_700_000_001, 0);
    vec![
        FlowEvent::Started {
            key: key(),
            side: FlowSide::Initiator,
            ts,
            l4: Some(L4Proto::Tcp),
        },
        FlowEvent::Packet {
            key: key(),
            side: FlowSide::Responder,
            len: 100,
            ts,
        },
        FlowEvent::Established {
            key: key(),
            ts,
            l4: Some(L4Proto::Tcp),
        },
        FlowEvent::StateChange {
            key: key(),
            from: FlowState::Established,
            to: FlowState::FinWait,
            ts,
        },
        FlowEvent::Ended {
            key: key(),
            reason: EndReason::Fin,
            stats: stats(),
            history: HistoryString::new(),
            l4: Some(L4Proto::Tcp),
        },
        FlowEvent::FlowAnomaly {
            key: key(),
            kind: AnomalyKind::OutOfOrderSegment {
                side: FlowSide::Initiator,
                count: 3,
            },
            ts,
        },
        FlowEvent::TrackerAnomaly {
            kind: AnomalyKind::OutOfOrderSegment {
                side: FlowSide::Responder,
                count: 1,
            },
            ts,
        },
        FlowEvent::Tick {
            key: key(),
            stats: stats(),
            ts,
        },
    ]
}

#[test]
fn from_flow_event_is_total_and_round_trips() {
    for fe in all_flow_events() {
        let dbg_before = format!("{fe:?}");
        // Total: every FlowEvent variant has an Event counterpart.
        let ev: Event<FiveTupleKey> = Event::from(fe);
        // Lossless: reverse reproduces the original.
        let back = ev
            .to_flow_event()
            .expect("non-ParserClosed always projects back");
        assert_eq!(
            dbg_before,
            format!("{back:?}"),
            "FlowEvent -> Event -> FlowEvent must be identity"
        );
    }
}

#[test]
fn state_change_maps_to_flow_state_change() {
    let ev = Event::from(FlowEvent::StateChange {
        key: key(),
        from: FlowState::Established,
        to: FlowState::FinWait,
        ts: Timestamp::new(1, 0),
    });
    assert!(matches!(
        ev,
        Event::FlowStateChange {
            from: FlowState::Established,
            to: FlowState::FinWait,
            ..
        }
    ));
}

#[test]
fn parser_closed_has_no_flow_event_projection() {
    let ev: Event<FiveTupleKey> = Event::ParserClosed {
        key: key(),
        parser_kind: "http",
        reason: EndReason::ParserDone,
        ts: Timestamp::new(1, 0),
    };
    assert!(ev.to_flow_event().is_none());
}

#[test]
fn from_flow_packet_defaults_tcp_to_none() {
    let ev = Event::from(FlowEvent::Packet {
        key: key(),
        side: FlowSide::Initiator,
        len: 40,
        ts: Timestamp::new(1, 0),
    });
    assert!(ev.tcp().is_none());
}

#[cfg(feature = "serde")]
#[test]
fn event_serializes_with_type_tag() {
    // Event is Serialize-only (ParserClosed's `&'static str` precludes
    // a general Deserialize) — verify the tagged, snake_case shape.
    for fe in all_flow_events() {
        let ev = Event::from(fe);
        let json = serde_json::to_value(&ev).expect("serialize");
        assert!(json.get("type").is_some(), "tag = \"type\" shape: {json}");
    }
    // Spot-check a couple of variant tags are snake_case.
    let started = Event::from(FlowEvent::Started {
        key: key(),
        side: FlowSide::Initiator,
        ts: Timestamp::new(1, 0),
        l4: Some(L4Proto::Tcp),
    });
    assert_eq!(
        serde_json::to_value(&started).unwrap()["type"],
        serde_json::json!("flow_started")
    );
    let pc: Event<FiveTupleKey> = Event::ParserClosed {
        key: key(),
        parser_kind: "http",
        reason: EndReason::ParserDone,
        ts: Timestamp::new(1, 0),
    };
    let pc_json = serde_json::to_value(&pc).unwrap();
    assert_eq!(pc_json["type"], serde_json::json!("parser_closed"));
    assert_eq!(pc_json["parser_kind"], serde_json::json!("http"));
}

#[cfg(feature = "emit")]
#[test]
fn write_lifecycle_matches_write_event_for_ended() {
    use flowscope::emit::FlowEventCsvWriter;

    let fe = FlowEvent::Ended {
        key: key(),
        reason: EndReason::Fin,
        stats: stats(),
        history: HistoryString::new(),
        l4: Some(L4Proto::Tcp),
    };
    let ev = Event::from(fe.clone());

    let mut via_event = Vec::new();
    FlowEventCsvWriter::new(&mut via_event)
        .unwrap()
        .write_lifecycle(&ev)
        .unwrap();

    let mut via_flow = Vec::new();
    FlowEventCsvWriter::new(&mut via_flow)
        .unwrap()
        .write_event(&fe)
        .unwrap();

    assert_eq!(
        via_event, via_flow,
        "Event and FlowEvent must emit identical CSV"
    );
    assert!(!via_event.is_empty());
}

#[cfg(feature = "emit")]
#[test]
fn write_lifecycle_skips_parser_closed() {
    use flowscope::emit::FlowEventCsvWriter;

    let ev: Event<FiveTupleKey> = Event::ParserClosed {
        key: key(),
        parser_kind: "http",
        reason: EndReason::ParserDone,
        ts: Timestamp::new(1, 0),
    };

    let mut got = Vec::new();
    {
        let mut w = FlowEventCsvWriter::new(&mut got).unwrap();
        w.write_lifecycle(&ev).unwrap();
    }
    // A writer that received no event at all (header only) must match —
    // ParserClosed contributes no row.
    let mut none = Vec::new();
    {
        let _ = FlowEventCsvWriter::new(&mut none).unwrap();
    }
    assert_eq!(got, none, "ParserClosed contributes no CSV row");
}

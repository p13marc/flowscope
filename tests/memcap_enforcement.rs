//! Cross-flow reassembly memcap enforcement (issue #26).
//!
//! Verifies the `FlowDriver` enforcement layer that consumes
//! [`FlowTrackerConfig::reassembly_memcap`] +
//! [`FlowTrackerConfig::reassembly_memcap_policy`]. The
//! declarative API + `Reassembler::current_bytes` hook
//! shipped in #17; this test suite drives the policy paths.

#![cfg(all(feature = "tracker", feature = "extractors", feature = "reassembler"))]

use flowscope::{
    AnomalyKind, BufferedReassemblerFactory, EndReason, FlowDriver, FlowEvent, FlowSide,
    FlowTrackerConfig, MemcapPolicy, PacketView, Timestamp,
    extract::{FiveTuple, parse::test_frames::ipv4_tcp},
};

const MAC: [u8; 6] = [0u8; 6];

fn view(frame: &[u8], sec: u32) -> PacketView<'_> {
    PacketView::new(frame, Timestamp::new(sec, 0))
}

/// Build a 3WHS + initiator data segment of `n` bytes for the
/// flow A→B keyed by (ip_a, ip_b, sport, dport). Returns the
/// four packets.
fn handshake_plus_data(
    ip_a: [u8; 4],
    ip_b: [u8; 4],
    sport: u16,
    dport: u16,
    seq_init: u32,
    seq_resp: u32,
    payload: &[u8],
) -> [Vec<u8>; 4] {
    [
        // SYN
        ipv4_tcp(MAC, MAC, ip_a, ip_b, sport, dport, seq_init, 0, 0x02, b""),
        // SYN-ACK
        ipv4_tcp(
            MAC,
            MAC,
            ip_b,
            ip_a,
            dport,
            sport,
            seq_resp,
            seq_init + 1,
            0x12,
            b"",
        ),
        // ACK
        ipv4_tcp(
            MAC,
            MAC,
            ip_a,
            ip_b,
            sport,
            dport,
            seq_init + 1,
            seq_resp + 1,
            0x10,
            b"",
        ),
        // PSH+ACK with data
        ipv4_tcp(
            MAC,
            MAC,
            ip_a,
            ip_b,
            sport,
            dport,
            seq_init + 1,
            seq_resp + 1,
            0x18,
            payload,
        ),
    ]
}

fn driver_with_memcap(
    cap_bytes: u64,
    policy: MemcapPolicy,
) -> FlowDriver<FiveTuple, BufferedReassemblerFactory> {
    let mut cfg = FlowTrackerConfig::default();
    cfg.reassembly_memcap = Some(cap_bytes);
    cfg.reassembly_memcap_policy = policy;
    FlowDriver::with_config(
        FiveTuple::bidirectional(),
        BufferedReassemblerFactory::default(),
        cfg,
    )
    .with_emit_anomalies(true)
}

// ─── Accounting + inspector ────────────────────────────────

#[test]
fn reassembly_memcap_bytes_starts_at_zero() {
    let d = driver_with_memcap(1024, MemcapPolicy::Ignore);
    assert_eq!(d.reassembly_memcap_bytes(), 0);
}

#[test]
fn reassembly_memcap_bytes_tracks_per_segment_growth() {
    let mut d = driver_with_memcap(1_000_000, MemcapPolicy::Ignore);
    let frames = handshake_plus_data(
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        1234,
        80,
        1000,
        5000,
        b"hello world",
    );
    for f in &frames {
        d.track(view(f, 0));
    }
    // Buffered: 11 bytes of "hello world".
    assert_eq!(d.reassembly_memcap_bytes(), 11);
}

#[test]
fn reassembly_memcap_bytes_decrements_on_flow_end() {
    let mut d = driver_with_memcap(1_000_000, MemcapPolicy::Ignore);
    let frames = handshake_plus_data([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1000, 5000, b"hi");
    for f in &frames {
        d.track(view(f, 0));
    }
    assert_eq!(d.reassembly_memcap_bytes(), 2);
    // RST tears down the flow → finalize drops both reassemblers.
    let rst = ipv4_tcp(
        MAC,
        MAC,
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        1234,
        80,
        1003,
        5001,
        0x04,
        b"",
    );
    d.track(view(&rst, 1));
    assert_eq!(
        d.reassembly_memcap_bytes(),
        0,
        "flow-end should refund every byte to the pool"
    );
}

#[test]
fn reassembly_memcap_bytes_aggregates_across_flows() {
    let mut d = driver_with_memcap(1_000_000, MemcapPolicy::Ignore);
    let body = vec![b'X'; 50];
    let flow_a = handshake_plus_data([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1000, 5000, &body);
    let flow_b = handshake_plus_data([10, 0, 0, 3], [10, 0, 0, 4], 4444, 80, 2000, 6000, &body);
    for f in &flow_a {
        d.track(view(f, 0));
    }
    for f in &flow_b {
        d.track(view(f, 1));
    }
    assert_eq!(d.reassembly_memcap_bytes(), 100);
}

// ─── Ignore policy ──────────────────────────────────────────

#[test]
fn ignore_policy_emits_anomaly_but_keeps_flow_alive() {
    let mut d = driver_with_memcap(50, MemcapPolicy::Ignore);
    let payload = vec![b'A'; 200];
    let frames = handshake_plus_data([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1000, 5000, &payload);
    let mut all_events: Vec<FlowEvent<_>> = Vec::new();
    for f in &frames {
        all_events.extend(d.track(view(f, 0)));
    }
    let memcap_hits: Vec<_> = all_events
        .iter()
        .filter_map(|e| match e {
            FlowEvent::TrackerAnomaly {
                kind:
                    kind @ AnomalyKind::GlobalMemcapHit {
                        policy: MemcapPolicy::Ignore,
                        ..
                    },
                ..
            } => Some(kind.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(
        memcap_hits.len(),
        1,
        "Ignore policy emits exactly one GlobalMemcapHit per tick"
    );
    let bufoverflow_ends: Vec<_> = all_events
        .iter()
        .filter(|e| {
            matches!(
                e,
                FlowEvent::Ended {
                    reason: EndReason::BufferOverflow,
                    ..
                }
            )
        })
        .collect();
    assert!(
        bufoverflow_ends.is_empty(),
        "Ignore policy must not synthesize BufferOverflow ends"
    );
}

// ─── DropFlow policy ────────────────────────────────────────

#[test]
fn drop_flow_policy_emits_anomaly_and_ends_flow() {
    let mut d = driver_with_memcap(50, MemcapPolicy::DropFlow);
    let payload = vec![b'A'; 200];
    let frames = handshake_plus_data([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1000, 5000, &payload);
    let mut all_events: Vec<FlowEvent<_>> = Vec::new();
    for f in &frames {
        all_events.extend(d.track(view(f, 0)));
    }
    let memcap_hits: Vec<_> = all_events
        .iter()
        .filter_map(|e| match e {
            FlowEvent::TrackerAnomaly {
                kind:
                    AnomalyKind::GlobalMemcapHit {
                        policy: MemcapPolicy::DropFlow,
                        bytes_in_flight,
                        cap,
                    },
                ..
            } => Some((*bytes_in_flight, *cap)),
            _ => None,
        })
        .collect();
    assert_eq!(memcap_hits.len(), 1, "one anomaly per tick");
    let (bytes, cap) = memcap_hits[0];
    assert!(bytes > cap, "trip happened above cap: {bytes} > {cap}");
    let bufoverflow_ends: Vec<_> = all_events
        .iter()
        .filter(|e| {
            matches!(
                e,
                FlowEvent::Ended {
                    reason: EndReason::BufferOverflow,
                    ..
                }
            )
        })
        .collect();
    assert_eq!(
        bufoverflow_ends.len(),
        1,
        "DropFlow synthesizes exactly one BufferOverflow end"
    );
    assert_eq!(
        d.reassembly_memcap_bytes(),
        0,
        "DropFlow refund leaves pool empty"
    );
}

// ─── PassThrough policy ─────────────────────────────────────

#[test]
fn pass_through_policy_kills_flow_like_dropflow_for_memcap() {
    // PassThrough is documented as "poison the reassembler but
    // keep the flow alive in the tracker". The driver-side
    // memcap implementation treats both PassThrough and DropFlow
    // the same: poison + synthesize Ended. (The distinction
    // is meaningful for per-flow overflow, not for global
    // memcap — once we're over the global pool, *the
    // reassembler* must release bytes either way.)
    let mut d = driver_with_memcap(50, MemcapPolicy::PassThrough);
    let payload = vec![b'A'; 200];
    let frames = handshake_plus_data([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1000, 5000, &payload);
    let mut all_events: Vec<FlowEvent<_>> = Vec::new();
    for f in &frames {
        all_events.extend(d.track(view(f, 0)));
    }
    let hits = all_events
        .iter()
        .filter(|e| {
            matches!(
                e,
                FlowEvent::TrackerAnomaly {
                    kind: AnomalyKind::GlobalMemcapHit {
                        policy: MemcapPolicy::PassThrough,
                        ..
                    },
                    ..
                }
            )
        })
        .count();
    assert_eq!(hits, 1);
}

// ─── DropPacket policy ──────────────────────────────────────

#[test]
fn drop_packet_policy_emits_anomaly_but_keeps_flow_alive() {
    let mut d = driver_with_memcap(50, MemcapPolicy::DropPacket);
    let payload = vec![b'A'; 200];
    let frames = handshake_plus_data([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1000, 5000, &payload);
    let mut all_events: Vec<FlowEvent<_>> = Vec::new();
    for f in &frames {
        all_events.extend(d.track(view(f, 0)));
    }
    let bufoverflow_ends: Vec<_> = all_events
        .iter()
        .filter(|e| {
            matches!(
                e,
                FlowEvent::Ended {
                    reason: EndReason::BufferOverflow,
                    ..
                }
            )
        })
        .collect();
    assert!(
        bufoverflow_ends.is_empty(),
        "DropPacket must not synthesize BufferOverflow ends"
    );
    let hits = all_events
        .iter()
        .filter(|e| {
            matches!(
                e,
                FlowEvent::TrackerAnomaly {
                    kind: AnomalyKind::GlobalMemcapHit {
                        policy: MemcapPolicy::DropPacket,
                        ..
                    },
                    ..
                }
            )
        })
        .count();
    assert_eq!(hits, 1);
}

// ─── Coalescing ─────────────────────────────────────────────

#[test]
fn memcap_anomaly_is_one_per_tick_not_per_segment() {
    let mut d = driver_with_memcap(50, MemcapPolicy::Ignore);
    let payload = vec![b'A'; 200];
    // Send the 3WHS first so the flow is established.
    let init = handshake_plus_data([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1000, 5000, b"");
    for f in &init[..3] {
        d.track(view(f, 0));
    }
    // Now hammer the flow with multiple data segments in a
    // single tick. (Each `d.track(...)` is its own tick from
    // the driver's perspective — coalescing is per-call. We
    // verify that one call → at most one anomaly even when
    // the buffer holds multiple segments' worth of payload.)
    let psh_ack_1 = ipv4_tcp(
        MAC,
        MAC,
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        1234,
        80,
        1001,
        5001,
        0x18,
        &payload,
    );
    let events = d.track(view(&psh_ack_1, 0));
    let hits = events
        .iter()
        .filter(|e| {
            matches!(
                e,
                FlowEvent::TrackerAnomaly {
                    kind: AnomalyKind::GlobalMemcapHit { .. },
                    ..
                }
            )
        })
        .count();
    assert_eq!(hits, 1, "exactly one anomaly per tick");
}

// ─── No-memcap config: no enforcement ───────────────────────

#[test]
fn memcap_disabled_emits_no_anomaly() {
    let mut d = FlowDriver::<_, _>::new(
        FiveTuple::bidirectional(),
        BufferedReassemblerFactory::default(),
    )
    .with_emit_anomalies(true);
    // Send a big flow — would trip any reasonable cap.
    let payload = vec![b'A'; 10_000];
    let frames = handshake_plus_data([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1000, 5000, &payload);
    let mut all_events: Vec<FlowEvent<_>> = Vec::new();
    for f in &frames {
        all_events.extend(d.track(view(f, 0)));
    }
    let hits = all_events
        .iter()
        .filter(|e| {
            matches!(
                e,
                FlowEvent::TrackerAnomaly {
                    kind: AnomalyKind::GlobalMemcapHit { .. },
                    ..
                }
            )
        })
        .count();
    assert_eq!(hits, 0, "no memcap configured → no memcap anomalies");
    // But bytes-in-flight is still tracked.
    assert_eq!(d.reassembly_memcap_bytes(), 10_000);
}

// ─── force_close refunds bytes ──────────────────────────────

#[test]
fn force_close_refunds_bytes_to_pool() {
    use flowscope::FlowExtractor;
    let mut d = driver_with_memcap(1_000_000, MemcapPolicy::Ignore);
    let payload = vec![b'A'; 100];
    let frames = handshake_plus_data([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1000, 5000, &payload);
    for f in &frames {
        d.track(view(f, 0));
    }
    assert_eq!(d.reassembly_memcap_bytes(), 100);
    let pv = view(&frames[0], 0);
    let key = FiveTuple::bidirectional().extract(pv).expect("extract").key;
    let _ = d.force_close(&key, Timestamp::new(2, 0));
    assert_eq!(d.reassembly_memcap_bytes(), 0, "force_close refunds bytes");
}

// ─── Enforcement, not just reporting (#186) ─────────────────
//
// The policies used to differ only in whether they ended the flow;
// none of them actually kept the pool under the cap. These pin the
// behaviour each variant now documents.

#[test]
fn drop_packet_actually_keeps_the_pool_under_the_cap() {
    // The whole point of a cap. Previously `DropPacket` shared an
    // empty match arm with `Ignore`: it emitted an anomaly and let
    // the pool grow to 200 bytes against a 50-byte cap.
    let mut d = driver_with_memcap(50, MemcapPolicy::DropPacket);
    let payload = vec![b'A'; 200];
    let frames = handshake_plus_data([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1000, 5000, &payload);
    for f in &frames {
        let _ = d.track(view(f, 0));
    }
    assert!(
        d.reassembly_memcap_bytes() <= 50,
        "pool must stay within the cap, saw {}",
        d.reassembly_memcap_bytes()
    );
}

#[test]
fn drop_packet_still_reports_the_violation_it_prevented() {
    // Refusing the segment must not make the trip invisible — the
    // anomaly is how an operator learns the cap is too small.
    let mut d = driver_with_memcap(50, MemcapPolicy::DropPacket);
    let payload = vec![b'A'; 200];
    let frames = handshake_plus_data([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1000, 5000, &payload);
    let mut all: Vec<FlowEvent<_>> = Vec::new();
    for f in &frames {
        all.extend(d.track(view(f, 0)));
    }
    let hits = all
        .iter()
        .filter(|e| {
            matches!(
                e,
                FlowEvent::TrackerAnomaly {
                    kind: AnomalyKind::GlobalMemcapHit { .. },
                    ..
                }
            )
        })
        .count();
    assert_eq!(hits, 1, "the refusal must still be reported");
}

#[test]
fn ignore_is_a_reporting_mode_and_says_so() {
    // `Ignore` deliberately does NOT enforce — it mirrors Suricata's
    // `memcap-policy: ignore`. Pinning that keeps it distinguishable
    // from `DropPacket` rather than the two silently coinciding.
    let mut d = driver_with_memcap(50, MemcapPolicy::Ignore);
    let payload = vec![b'A'; 200];
    let frames = handshake_plus_data([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1000, 5000, &payload);
    for f in &frames {
        let _ = d.track(view(f, 0));
    }
    assert!(
        d.reassembly_memcap_bytes() > 50,
        "Ignore reports without enforcing, by design"
    );
}

#[test]
fn pass_through_frees_the_bytes_and_keeps_the_flow() {
    // Documented behaviour that the code did not implement: stop
    // reassembling, but leave the flow tracked so accounting
    // continues. It previously ended the flow like DropFlow.
    let mut d = driver_with_memcap(50, MemcapPolicy::PassThrough);
    let payload = vec![b'A'; 200];
    let frames = handshake_plus_data([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1000, 5000, &payload);
    let mut all: Vec<FlowEvent<_>> = Vec::new();
    for f in &frames {
        all.extend(d.track(view(f, 0)));
    }

    let ended: Vec<_> = all
        .iter()
        .filter(|e| {
            matches!(
                e,
                FlowEvent::Ended {
                    reason: EndReason::BufferOverflow,
                    ..
                }
            )
        })
        .collect();
    assert!(
        ended.is_empty(),
        "PassThrough keeps the flow alive; DropFlow is the variant that ends it"
    );
    assert_eq!(
        d.reassembly_memcap_bytes(),
        0,
        "releasing the reassembler must return its bytes to the pool"
    );
    assert_eq!(d.tracker().flow_count(), 1, "the flow itself stays tracked");
}

#[test]
fn drained_bytes_are_returned_to_the_pool() {
    // A parser that consumes its buffer between segments used to
    // leave the pool over-reporting until flow end, so the memcap
    // tripped on bytes nobody was holding.
    let mut d = driver_with_memcap(1_000_000, MemcapPolicy::Ignore);
    let payload = vec![b'A'; 500];
    let frames = handshake_plus_data([10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1000, 5000, &payload);
    for f in &frames {
        let _ = d.track(view(f, 0));
    }
    assert_eq!(d.reassembly_memcap_bytes(), 500);

    // Drain the initiator side the way a parser would.
    let key = d
        .snapshot_flow_stats()
        .map(|(k, _)| k)
        .next()
        .expect("one flow");
    if let Some(r) = d.reassembler(&key, FlowSide::Initiator) {
        let _ = r.take();
    }

    // The pool still reflects the stale figure until the next
    // segment re-syncs it — which is what the fix does.
    let more = ipv4_tcp(
        [0; 6],
        [0; 6],
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        1234,
        80,
        1500,
        5000,
        0x18,
        b"xy",
    );
    let _ = d.track(view(&more, 0));
    assert!(
        d.reassembly_memcap_bytes() <= 2,
        "the drained 500 bytes must not still be counted, pool is {}",
        d.reassembly_memcap_bytes()
    );
}

//! Plan 110 sub-B — quick-win helper sweep.
//!
//! Coverage for the additive helpers added in 0.10:
//! - `Timestamp::to_unix_f64` / `from_unix_f64` / `relative_to` /
//!   `from_system_time`
//! - `FlowStats::total_bytes` / `total_packets` /
//!   `total_retransmits` / `retransmit_rate` / `duration` /
//!   `duration_secs`
//! - `EndReason::as_str` + `Display`
//! - `LayerKind::is_l2` / `is_l3` / `is_l4` / `is_tunnel`
//! - `Layer<'_>::Display`
//! - `LayerStack::depth` / `iter_kinds`
//! - `KeyIndexed::peek`

use flowscope::{EndReason, FlowStats, Timestamp};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// ── Timestamp ──────────────────────────────────────────────────────

#[test]
fn timestamp_to_unix_f64_roundtrip() {
    let ts = Timestamp::new(1_700_000_000, 250_000_000);
    let f = ts.to_unix_f64();
    assert!((f - 1_700_000_000.25).abs() < 1e-3);
    let back = Timestamp::from_unix_f64(f);
    // Within a microsecond due to f64 mantissa near 2^31.
    assert_eq!(back.sec, ts.sec);
    assert!(back.nsec.abs_diff(ts.nsec) < 1_000);
}

#[test]
fn timestamp_from_unix_f64_clamps_negative_and_nan() {
    assert_eq!(Timestamp::from_unix_f64(-1.0), Timestamp::default());
    assert_eq!(Timestamp::from_unix_f64(f64::NAN), Timestamp::default());
    assert_eq!(
        Timestamp::from_unix_f64(f64::INFINITY),
        Timestamp::default()
    );
}

#[test]
fn timestamp_relative_to_signed_delta() {
    let a = Timestamp::new(100, 0);
    let b = Timestamp::new(110, 500_000_000);
    assert!((b.relative_to(a) - 10.5).abs() < 1e-9);
    assert!((a.relative_to(b) + 10.5).abs() < 1e-9);
    assert_eq!(a.relative_to(a), 0.0);
}

#[test]
fn timestamp_from_system_time() {
    let st = UNIX_EPOCH + Duration::new(1_234_567_890, 123_456_789);
    let ts = Timestamp::from_system_time(st);
    assert_eq!(ts.sec, 1_234_567_890);
    assert_eq!(ts.nsec, 123_456_789);
}

#[test]
fn timestamp_from_system_time_pre_epoch_clamps_to_zero() {
    // SystemTime::UNIX_EPOCH - 1 second should clamp to default.
    let st = SystemTime::UNIX_EPOCH
        .checked_sub(Duration::from_secs(1))
        .expect("checked_sub from epoch");
    let ts = Timestamp::from_system_time(st);
    assert_eq!(ts, Timestamp::default());
}

#[test]
fn timestamp_display_already_zeek_compatible() {
    let ts = Timestamp::new(1234, 1);
    assert_eq!(ts.to_string(), "1234.000000001");
}

// ── FlowStats ──────────────────────────────────────────────────────

fn stats_with(
    pkts_i: u64,
    pkts_r: u64,
    bytes_i: u64,
    bytes_r: u64,
    rtx_i: u64,
    rtx_r: u64,
) -> FlowStats {
    let mut s = FlowStats::default();
    s.packets_initiator = pkts_i;
    s.packets_responder = pkts_r;
    s.bytes_initiator = bytes_i;
    s.bytes_responder = bytes_r;
    s.retransmits_initiator = rtx_i;
    s.retransmits_responder = rtx_r;
    s.started = Timestamp::new(100, 0);
    s.last_seen = Timestamp::new(105, 500_000_000);
    s
}

#[test]
fn flow_stats_total_helpers() {
    let s = stats_with(10, 20, 1_000, 2_000, 1, 2);
    assert_eq!(s.total_packets(), 30);
    assert_eq!(s.total_bytes(), 3_000);
    assert_eq!(s.total_retransmits(), 3);
}

#[test]
fn flow_stats_retransmit_rate() {
    let s = stats_with(10, 10, 0, 0, 1, 1);
    assert!((s.retransmit_rate() - 0.1).abs() < 1e-9);
}

#[test]
fn flow_stats_retransmit_rate_zero_packets_is_zero() {
    let s = FlowStats::default();
    assert_eq!(s.retransmit_rate(), 0.0);
}

#[test]
fn flow_stats_duration_and_secs() {
    let s = stats_with(0, 0, 0, 0, 0, 0);
    assert_eq!(s.duration(), Duration::new(5, 500_000_000));
    assert!((s.duration_secs() - 5.5).abs() < 1e-9);
}

#[test]
fn flow_stats_duration_saturates_when_last_before_started() {
    let mut s = FlowStats::default();
    s.started = Timestamp::new(200, 0);
    s.last_seen = Timestamp::new(100, 0);
    assert_eq!(s.duration(), Duration::ZERO);
    assert_eq!(s.duration_secs(), 0.0);
}

// ── EndReason ──────────────────────────────────────────────────────

#[test]
fn end_reason_as_str_vocabulary() {
    assert_eq!(EndReason::Fin.as_str(), "fin");
    assert_eq!(EndReason::Rst.as_str(), "rst");
    assert_eq!(EndReason::IdleTimeout.as_str(), "idle");
    assert_eq!(EndReason::Evicted.as_str(), "evicted");
    assert_eq!(EndReason::BufferOverflow.as_str(), "buffer_overflow");
    assert_eq!(EndReason::ParseError.as_str(), "parse_error");
    assert_eq!(EndReason::ParserDone.as_str(), "parser_done");
    assert_eq!(EndReason::ForceClosed.as_str(), "force_closed");
}

#[test]
fn end_reason_display_matches_as_str() {
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
        assert_eq!(r.to_string(), r.as_str());
    }
}

// ── LayerKind predicates ──────────────────────────────────────────

#[test]
fn layer_kind_groups() {
    use flowscope::layers::LayerKind;

    for k in [LayerKind::Ethernet, LayerKind::Vlan, LayerKind::Mpls] {
        assert!(k.is_l2(), "{k:?} expected L2");
        assert!(!k.is_l3());
        assert!(!k.is_l4());
        assert!(!k.is_tunnel());
    }
    for k in [LayerKind::Ipv4, LayerKind::Ipv6, LayerKind::Arp] {
        assert!(!k.is_l2());
        assert!(k.is_l3(), "{k:?} expected L3");
        assert!(!k.is_l4());
        assert!(!k.is_tunnel());
    }
    for k in [
        LayerKind::Tcp,
        LayerKind::Udp,
        LayerKind::Icmpv4,
        LayerKind::Icmpv6,
    ] {
        assert!(!k.is_l2());
        assert!(!k.is_l3());
        assert!(k.is_l4(), "{k:?} expected L4");
        assert!(!k.is_tunnel());
    }
    for k in [LayerKind::Gre, LayerKind::Vxlan, LayerKind::GtpU] {
        assert!(!k.is_l2());
        assert!(!k.is_l3());
        assert!(!k.is_l4());
        assert!(k.is_tunnel(), "{k:?} expected tunnel");
    }
    // Payload is in none of the groups.
    assert!(!LayerKind::Payload.is_l2());
    assert!(!LayerKind::Payload.is_l3());
    assert!(!LayerKind::Payload.is_l4());
    assert!(!LayerKind::Payload.is_tunnel());
}

// ── KeyIndexed::peek ──────────────────────────────────────────────

#[test]
fn key_indexed_peek_does_not_bump_lru() {
    use flowscope::correlate::KeyIndexed;

    let mut q: KeyIndexed<u16, String> = KeyIndexed::new(Duration::from_secs(60), 2);
    q.insert(1, "a".into(), Timestamp::new(0, 0));
    q.insert(2, "b".into(), Timestamp::new(0, 0));
    // Peek at 1 — must NOT bump it ahead of 2 in LRU order.
    assert_eq!(
        q.peek(&1, Timestamp::new(1, 0)).map(String::as_str),
        Some("a")
    );
    // Insert a third entry; with capacity 2, the LRU (still 1)
    // should be evicted because peek didn't touch recency.
    q.insert(3, "c".into(), Timestamp::new(2, 0));
    // If peek had bumped 1, 2 would be evicted instead.
    assert!(
        q.peek(&1, Timestamp::new(3, 0)).is_none(),
        "1 should have been LRU-evicted"
    );
    assert!(q.peek(&2, Timestamp::new(3, 0)).is_some());
    assert!(q.peek(&3, Timestamp::new(3, 0)).is_some());
}

#[test]
fn key_indexed_peek_respects_ttl() {
    use flowscope::correlate::KeyIndexed;

    let q: KeyIndexed<u16, String> = {
        let mut q = KeyIndexed::new(Duration::from_secs(5), 16);
        q.insert(42, "ok".into(), Timestamp::new(0, 0));
        q
    };
    assert_eq!(
        q.peek(&42, Timestamp::new(3, 0)).map(String::as_str),
        Some("ok")
    );
    assert!(q.peek(&42, Timestamp::new(10, 0)).is_none());
}

// ── Layer<'_> Display ──────────────────────────────────────────────

#[cfg(feature = "test-helpers")]
mod layers {
    use flowscope::layers::{LayerKind, LayerParser, LayerStack, Layers};

    fn ipv4_tcp_frame() -> Vec<u8> {
        // Use the same test helper as the layers tests do internally
        // via the test-helpers feature.
        flowscope::extract::parse::test_frames::ipv4_tcp(
            [0xaa; 6],
            [0xbb; 6],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            12345,
            80,
            1000,
            0,
            0x02, // SYN
            b"",
        )
    }

    #[test]
    fn layer_display_one_line_summary() {
        let frame = ipv4_tcp_frame();
        let layers = Layers::parse_ethernet(&frame).expect("parse");
        let lines: Vec<String> = layers.iter().map(|l| l.to_string()).collect();
        assert!(lines.iter().any(|s| s.starts_with("ethernet")));
        assert!(lines.iter().any(|s| s.starts_with("ipv4 src=10.0.0.1")));
        assert!(
            lines
                .iter()
                .any(|s| s.starts_with("tcp src_port=12345 dst_port=80")),
        );
        assert!(lines.iter().any(|s| s.contains("flags=[S]")));
    }

    #[test]
    fn layer_stack_depth_and_iter_kinds() {
        let frame = ipv4_tcp_frame();
        let parser = LayerParser::new();
        let mut stack = LayerStack::new();
        parser.parse_ethernet(&frame, &mut stack).expect("parse");

        assert_eq!(stack.depth(), 3);
        let kinds: Vec<LayerKind> = stack.iter_kinds().collect();
        assert_eq!(
            kinds,
            vec![LayerKind::Ethernet, LayerKind::Ipv4, LayerKind::Tcp]
        );
    }
}

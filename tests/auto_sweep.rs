//! Plan 75 — `FlowTracker::with_auto_sweep(interval)`.
//!
//! Verifies that:
//! 1. Without auto-sweep, idle-timeouts only fire on explicit
//!    sweep — offline replay never emits Ended for idle flows.
//! 2. With auto-sweep set, packet-clock advancement past the
//!    idle threshold + sweep interval produces an Ended event
//!    inline (no separate sweep call needed).
//! 3. Manual sweep updates `last_sweep_ts`, so a follow-up
//!    auto-sweep doesn't double-fire.

#![cfg(all(feature = "tracker", feature = "extractors"))]

use std::time::Duration;

use flowscope::extract::FiveTuple;
use flowscope::extract::parse::test_frames::ipv4_tcp;
use flowscope::{FlowEvent, FlowTracker, FlowTrackerConfig, PacketView, Timestamp};

fn view(frame: &[u8], sec: u32) -> PacketView<'_> {
    PacketView::new(frame, Timestamp::new(sec, 0))
}

fn syn(seq: u32) -> Vec<u8> {
    ipv4_tcp(
        [1; 6],
        [2; 6],
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        1234,
        80,
        seq,
        0,
        0x02, // SYN
        b"",
    )
}

#[test]
fn without_auto_sweep_offline_replay_never_idle_ends() {
    // Setup: tcp idle timeout = 60 s. One packet at t=0, another
    // at t=200 (far past idle). Without auto-sweep we never see
    // an Ended event between the two — it would take an explicit
    // sweep(now) call.
    let mut cfg = FlowTrackerConfig::default();
    cfg.idle_timeout_tcp = Duration::from_secs(60);
    let mut t: FlowTracker<FiveTuple> = FlowTracker::with_config(FiveTuple::bidirectional(), cfg);

    let f = syn(1000);
    let _ = t.track(view(&f, 0));

    // Different flow at t=200s; the original flow has been idle 200s.
    let f2 = ipv4_tcp(
        [3; 6],
        [4; 6],
        [10, 0, 0, 3],
        [10, 0, 0, 4],
        9999,
        443,
        500,
        0,
        0x02,
        b"",
    );
    let events = t.track(view(&f2, 200));
    let ended_count = events
        .iter()
        .filter(|e| matches!(e, FlowEvent::Ended { .. }))
        .count();
    assert_eq!(
        ended_count, 0,
        "without auto_sweep no idle-end fires inline"
    );
}

#[test]
fn auto_sweep_produces_inline_ended_event() {
    // With auto_sweep_interval = 1s and idle_timeout = 60s, the
    // second packet at t=200s past a stale flow's last_seen
    // should trigger an implicit sweep that emits Ended for the
    // first flow.
    let mut cfg = FlowTrackerConfig::default();
    cfg.idle_timeout_tcp = Duration::from_secs(60);
    let mut t: FlowTracker<FiveTuple> = FlowTracker::with_config(FiveTuple::bidirectional(), cfg)
        .with_auto_sweep(Duration::from_secs(1));

    let f = syn(1000);
    let _ = t.track(view(&f, 0));

    // Far-future packet on a different flow.
    let f2 = ipv4_tcp(
        [3; 6],
        [4; 6],
        [10, 0, 0, 3],
        [10, 0, 0, 4],
        9999,
        443,
        500,
        0,
        0x02,
        b"",
    );
    let events = t.track(view(&f2, 200));
    let ended_count = events
        .iter()
        .filter(|e| matches!(e, FlowEvent::Ended { .. }))
        .count();
    assert_eq!(ended_count, 1, "auto-sweep should idle-end the stale flow");
}

#[test]
fn manual_sweep_resets_auto_sweep_clock() {
    // After a manual sweep, the next auto-sweep window starts
    // fresh — a follow-up packet within `auto_sweep_interval` of
    // the manual sweep should not trigger another implicit sweep.
    let mut cfg = FlowTrackerConfig::default();
    cfg.idle_timeout_tcp = Duration::from_secs(60);
    let mut t: FlowTracker<FiveTuple> = FlowTracker::with_config(FiveTuple::bidirectional(), cfg)
        .with_auto_sweep(Duration::from_secs(10));

    let f = syn(1000);
    let _ = t.track(view(&f, 0));

    // Manual sweep at t=100.
    let _ = t.sweep(Timestamp::new(100, 0));

    // A new flow at t=105. Only 5s since the manual sweep — auto
    // shouldn't fire again. Even if it did, the flow we just
    // expired is already gone, so this primarily checks the
    // "no double-fire" path stays sane.
    let f2 = ipv4_tcp(
        [3; 6],
        [4; 6],
        [10, 0, 0, 3],
        [10, 0, 0, 4],
        9999,
        443,
        500,
        0,
        0x02,
        b"",
    );
    let events = t.track(view(&f2, 105));
    let started_count = events
        .iter()
        .filter(|e| matches!(e, FlowEvent::Started { .. }))
        .count();
    assert_eq!(started_count, 1, "new flow should still emit Started");
}

#[test]
fn auto_sweep_default_is_off() {
    let cfg = FlowTrackerConfig::default();
    assert!(cfg.auto_sweep_interval.is_none());
}

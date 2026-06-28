//! Issue #118 — the canonical [`Orientation`] axis on flow events is
//! deterministic, while [`FlowSide`] is arrival-order-relative.
//!
//! This is the regression test for the #71 tap-merge problem: when two
//! capture legs feed one tracker and a scheduling race delivers the
//! *response* packet first, `FlowSide::Initiator` binds to the server
//! on some flows and the client on others. The deterministic,
//! address-sorted `Orientation` does **not** move — a given wire
//! direction always carries the same `Orientation` regardless of which
//! packet of the flow was observed first.
//!
//! Issue #120 — the physical capture leg (`RxMetadata::source_idx`) is
//! folded to a per-canonical-orientation binding on `FlowStats`, so a
//! merged bidirectional flow still reports which NIC each direction
//! arrived on (IPFIX biflow-merge model) without splitting into two
//! flows.

#![cfg(all(feature = "extractors", feature = "tracker"))]

use flowscope::{
    FlowEvent, FlowSide, FlowStats, FlowTracker, Orientation, PacketView, Timestamp,
    extract::{FiveTuple, parse::test_frames},
};

// Two endpoints. As `SocketAddr`, A < B, so the bidirectional
// extractor canonicalizes the key to `a = A`, `b = B`. A packet whose
// src→dst is A→B is therefore `Orientation::Forward`; B→A is `Reverse`.
const A_IP: [u8; 4] = [10, 0, 0, 1];
const B_IP: [u8; 4] = [10, 0, 0, 2];
const A_PORT: u16 = 40000;
const B_PORT: u16 = 53;

fn a_to_b(payload: &[u8]) -> Vec<u8> {
    test_frames::ipv4_udp(A_IP, B_IP, A_PORT, B_PORT, payload)
}

fn b_to_a(payload: &[u8]) -> Vec<u8> {
    test_frames::ipv4_udp(B_IP, A_IP, B_PORT, A_PORT, payload)
}

/// Drive a tracker over the given frames in order, returning the
/// `(side, orientation)` of every `Started`/`Packet` event, plus the
/// `initiator_orientation` recorded on the flow's stats.
fn run(frames: &[Vec<u8>]) -> (Vec<(FlowSide, Orientation)>, Orientation) {
    let mut tracker: FlowTracker<_, ()> = FlowTracker::new(FiveTuple::bidirectional());
    let mut seen = Vec::new();
    let mut init_orientation = None;
    for (t, frame) in frames.iter().enumerate() {
        let evts = tracker.track(PacketView::new(frame, Timestamp::new(t as u32, 0)));
        for evt in evts {
            match evt {
                FlowEvent::Started {
                    side, orientation, ..
                } => {
                    seen.push((side, orientation));
                }
                FlowEvent::Packet {
                    side, orientation, ..
                } => {
                    seen.push((side, orientation));
                }
                _ => {}
            }
        }
        // Capture initiator_orientation off a live snapshot.
        if init_orientation.is_none() {
            for (_k, entry) in tracker.flows() {
                init_orientation = Some(entry.initiator_orientation());
            }
        }
    }
    (seen, init_orientation.expect("flow was created"))
}

#[test]
fn orientation_is_stable_across_arrival_order_while_side_flips() {
    // Run A — the client's A→B packet is seen first (the normal case).
    let (a_events, a_init) = run(&[a_to_b(b"q1"), b_to_a(b"r1"), a_to_b(b"q2")]);
    // Run B — the server's B→A packet is seen first (tap-merge race).
    let (b_events, b_init) = run(&[b_to_a(b"r1"), a_to_b(b"q1"), b_to_a(b"r2")]);

    assert!(!a_events.is_empty() && !b_events.is_empty());

    // ── The headline invariant: orientation is a pure function of the
    // wire direction, independent of arrival order. ─────────────────
    // A→B is always Forward and B→A is always Reverse, in both runs.
    // In run A the first event (Started) is the A→B packet → Forward.
    assert_eq!(
        a_events[0].1,
        Orientation::Forward,
        "run A: first packet A→B must be Forward"
    );
    // In run B the first event (Started) is the B→A packet → Reverse.
    assert_eq!(
        b_events[0].1,
        Orientation::Reverse,
        "run B: first packet B→A must be Reverse"
    );

    // ── side flips between runs for the SAME wire direction. ────────
    // Run A: the A→B packet is the initiator (seen first).
    assert_eq!(a_events[0].0, FlowSide::Initiator);
    // Run B: the A→B packet now arrives second, so it is the responder.
    // Find the A→B (Forward) event in run B — it must be Responder.
    let ab_in_run_b = b_events
        .iter()
        .find(|(_s, o)| *o == Orientation::Forward)
        .expect("run B sees at least one A→B packet");
    assert_eq!(
        ab_in_run_b.0,
        FlowSide::Responder,
        "run B: the A→B direction is the RESPONDER because the B→A \
         packet was seen first — this is exactly the side fragility \
         that Orientation fixes"
    );

    // ── initiator_orientation records which canonical direction the
    // first-seen packet had — and it differs between the two runs. ──
    assert_eq!(a_init, Orientation::Forward, "run A initiator was A→B");
    assert_eq!(b_init, Orientation::Reverse, "run B initiator was B→A");
    assert_ne!(
        a_init, b_init,
        "the two runs disagree on who the initiator is — but agree on \
         every packet's Orientation"
    );
}

#[test]
fn flow_stats_translate_between_axes() {
    use flowscope::FlowStats;

    // A flow whose initiator went A→B (Forward).
    let mut stats = FlowStats::default();
    stats.initiator_orientation = Orientation::Forward;
    // Forward orientation == initiator side; Reverse == responder.
    assert_eq!(stats.side_for(Orientation::Forward), FlowSide::Initiator);
    assert_eq!(stats.side_for(Orientation::Reverse), FlowSide::Responder);
    // And the inverse mapping round-trips.
    assert_eq!(
        stats.orientation_for(FlowSide::Initiator),
        Orientation::Forward
    );
    assert_eq!(
        stats.orientation_for(FlowSide::Responder),
        Orientation::Reverse
    );

    // A flow whose initiator went B→A (Reverse) — the tap-merge case.
    let mut flipped = FlowStats::default();
    flipped.initiator_orientation = Orientation::Reverse;
    assert_eq!(flipped.side_for(Orientation::Reverse), FlowSide::Initiator);
    assert_eq!(flipped.side_for(Orientation::Forward), FlowSide::Responder);
}

/// Feed `(frame, source_idx)` pairs through one merged bidirectional
/// flow and return the single flow's live `FlowStats`.
fn drive_with_legs(frames: &[(Vec<u8>, u32)]) -> FlowStats {
    let mut tracker: FlowTracker<_, ()> = FlowTracker::new(FiveTuple::bidirectional());
    for (t, (frame, src)) in frames.iter().enumerate() {
        let view = PacketView::new(frame, Timestamp::new(t as u32, 0)).with_source_idx(*src);
        let _ = tracker.track(view);
    }
    let mut stats = None;
    for (_k, entry) in tracker.flows() {
        assert!(stats.is_none(), "expected exactly one merged flow");
        stats = Some(entry.stats.clone());
    }
    stats.expect("flow was created")
}

#[test]
fn capture_leg_binds_per_orientation_on_merged_flow() {
    // A→B (Forward) arrives on NIC 1; B→A (Reverse) on NIC 2. Both
    // legs of the SAME flow — they must merge into one flow while each
    // direction remembers its leg.
    let stats = drive_with_legs(&[
        (a_to_b(b"q1"), 1),
        (b_to_a(b"r1"), 2),
        (a_to_b(b"q2"), 1),
        (b_to_a(b"r2"), 2),
    ]);

    assert_eq!(stats.source_idx_for(Orientation::Forward), Some(1));
    assert_eq!(stats.source_idx_for(Orientation::Reverse), Some(2));
    assert_eq!(stats.source_idx_forward, Some(1));
    assert_eq!(stats.source_idx_reverse, Some(2));
    assert!(
        !stats.capture_leg_inconsistent,
        "one leg per direction — consistent"
    );
    // Still a single bidirectional flow.
    assert_eq!(stats.total_packets(), 4);
}

#[test]
fn inconsistent_leg_flips_the_ioc() {
    // The A→B direction shows up on TWO different NICs (1 then 3) —
    // tap miswire / asymmetric routing. The first binding is kept, the
    // IOC flips.
    let stats = drive_with_legs(&[
        (a_to_b(b"q1"), 1),
        (b_to_a(b"r1"), 2),
        (a_to_b(b"q2"), 3), // same orientation, different leg
    ]);

    assert_eq!(
        stats.source_idx_for(Orientation::Forward),
        Some(1),
        "original binding is kept, not overwritten"
    );
    assert_eq!(stats.source_idx_for(Orientation::Reverse), Some(2));
    assert!(
        stats.capture_leg_inconsistent,
        "a second, different leg on the Forward direction is the IOC"
    );
}

#[test]
fn no_source_idx_leaves_legs_unbound() {
    // pcap / synthetic: source_idx stays at the `0` "unused" sentinel,
    // so the per-direction bindings stay None and the IOC stays clear.
    let stats = drive_with_legs(&[(a_to_b(b"q1"), 0), (b_to_a(b"r1"), 0)]);
    assert_eq!(stats.source_idx_for(Orientation::Forward), None);
    assert_eq!(stats.source_idx_for(Orientation::Reverse), None);
    assert!(!stats.capture_leg_inconsistent);
}

#[test]
fn orientation_helpers_round_trip() {
    assert_eq!(Orientation::Forward.flipped(), Orientation::Reverse);
    assert_eq!(Orientation::Reverse.flipped(), Orientation::Forward);
    assert_eq!(
        Orientation::Forward.flipped().flipped(),
        Orientation::Forward
    );
    assert_eq!(Orientation::Forward.as_str(), "forward");
    assert_eq!(Orientation::Reverse.as_str(), "reverse");
    assert_eq!(Orientation::default(), Orientation::Forward);
}

//! Tap-merge direction model — the three orthogonal direction axes
//! (flowscope 0.20, issues #118 / #119 / #120 / #122).
//!
//! When two capture legs (e.g. a tap's TX and RX NICs, or two RSS
//! queues) feed ONE tracker, the two directions of a flow race. This
//! example shows the three direction axes flowscope keeps distinct, and
//! why you usually want the *deterministic* one:
//!
//!   1. **Logical role** — `FlowSide` (Initiator/Responder), decided by
//!      arrival order. Flips under a tap-merge race.
//!   2. **Canonical orientation** — `Orientation` (Forward/Reverse),
//!      address-sorted. Deterministic regardless of arrival order.
//!   3. **Physical capture leg** — `RxMetadata::source_idx` (which NIC),
//!      folded per-direction onto the merged flow.
//!
//! Run with:
//!   cargo run --features tracker,extractors,test-helpers \
//!     --example tap_merge_orientation
//!
//! (`test-helpers` only supplies the synthetic frame builders used
//! below — the orientation/leg APIs themselves are always-on.)

use flowscope::{
    FlowEvent, FlowTracker, FlowTrackerConfig, Orientation, PacketView, Timestamp,
    extract::{FiveTuple, parse::test_frames},
};

// Two endpoints. As SocketAddr, A < B, so the bidirectional extractor
// canonicalizes the key to a=A, b=B: an A→B packet is `Forward`, a B→A
// packet is `Reverse` — no matter which is seen first.
const A_IP: [u8; 4] = [10, 0, 0, 10]; // client
const B_IP: [u8; 4] = [10, 0, 0, 20]; // server
const A_PORT: u16 = 50000;
const B_PORT: u16 = 443;

fn udp_a_to_b(p: &[u8]) -> Vec<u8> {
    test_frames::ipv4_udp(A_IP, B_IP, A_PORT, B_PORT, p)
}
fn udp_b_to_a(p: &[u8]) -> Vec<u8> {
    test_frames::ipv4_udp(B_IP, A_IP, B_PORT, A_PORT, p)
}

fn main() {
    axis_1_and_2_orientation_vs_side();
    axis_3_capture_leg_binding();
    syn_based_initiator();
}

/// Axes 1 + 2 — feed the SAME flow two ways and watch `FlowSide` flip
/// while `Orientation` stays put.
fn axis_1_and_2_orientation_vs_side() {
    println!("== Axes 1+2: FlowSide (arrival order) vs Orientation (deterministic) ==");

    for (label, frames) in [
        (
            "client first (A→B seen first)",
            vec![udp_a_to_b(b"req"), udp_b_to_a(b"resp")],
        ),
        // Tap-merge race: the server's response is delivered first.
        (
            "server first (B→A seen first)",
            vec![udp_b_to_a(b"resp"), udp_a_to_b(b"req")],
        ),
    ] {
        let mut tracker: FlowTracker<_, ()> = FlowTracker::new(FiveTuple::bidirectional());
        println!("  {label}:");
        for (t, frame) in frames.iter().enumerate() {
            for ev in tracker.track(PacketView::new(frame, Timestamp::new(t as u32, 0))) {
                if let FlowEvent::Packet {
                    side, orientation, ..
                }
                | FlowEvent::Started {
                    side, orientation, ..
                } = ev
                {
                    // A→B is the request direction. Note how `side` for
                    // it depends on the run, but `orientation` does not.
                    println!("    packet  side={side:?}  orientation={orientation:?}");
                }
            }
        }
    }
    println!(
        "  → `orientation` is identical across both runs; `side` is not. \
         Key on orientation for Community ID / biflow / cross-sensor dedup.\n"
    );
}

/// Axis 3 — a merged flow remembers which NIC each direction arrived on
/// without splitting into two flows (the IPFIX biflow-merge model).
fn axis_3_capture_leg_binding() {
    println!("== Axis 3: per-direction capture leg on a merged flow ==");

    let mut tracker: FlowTracker<_, ()> = FlowTracker::new(FiveTuple::bidirectional());
    // The request leg arrives on NIC 1, the response leg on NIC 2.
    let frames = [
        (udp_a_to_b(b"req1"), 1u32),
        (udp_b_to_a(b"resp1"), 2),
        (udp_a_to_b(b"req2"), 1),
        (udp_b_to_a(b"resp2"), 2),
    ];
    for (t, (frame, nic)) in frames.iter().enumerate() {
        let view = PacketView::new(frame, Timestamp::new(t as u32, 0)).with_source_idx(*nic);
        let _ = tracker.track(view);
    }

    for (_key, entry) in tracker.flows() {
        let s = &entry.stats;
        println!(
            "  Forward leg = NIC {:?}, Reverse leg = NIC {:?}, packets={} (single merged flow)",
            s.source_idx_for(Orientation::Forward),
            s.source_idx_for(Orientation::Reverse),
            s.total_packets(),
        );
        println!(
            "  capture_leg_inconsistent = {}  (would flip on a tap miswire / asymmetric routing)\n",
            s.capture_leg_inconsistent
        );
    }
}

/// Axis 1, made race-robust — opt-in SYN-based initiator inference so
/// `FlowSide` survives the same race that flips it above.
fn syn_based_initiator() {
    println!("== SYN-based initiator inference (opt-in) ==");
    const SYN: u8 = 0x02;
    const SYN_ACK: u8 = 0x12;
    let syn = test_frames::ipv4_tcp([0; 6], [0; 6], A_IP, B_IP, A_PORT, B_PORT, 0, 0, SYN, b"");
    let syn_ack = test_frames::ipv4_tcp(
        [0; 6], [0; 6], B_IP, A_IP, B_PORT, A_PORT, 0, 0, SYN_ACK, b"",
    );

    for infer in [false, true] {
        let mut cfg = FlowTrackerConfig::default();
        cfg.infer_tcp_initiator = infer;
        let mut tracker: FlowTracker<_, ()> =
            FlowTracker::with_config(FiveTuple::bidirectional(), cfg);
        // Race: the SYN+ACK (server) is delivered before the SYN (client).
        for (t, frame) in [&syn_ack, &syn].into_iter().enumerate() {
            let _ = tracker.track(PacketView::new(frame, Timestamp::new(t as u32, 0)));
        }
        for (_key, entry) in tracker.flows() {
            let s = &entry.stats;
            // The SYN sender is A→B = Forward. With inference on, it is
            // correctly the initiator despite arriving second.
            println!(
                "  infer_tcp_initiator={infer:5}: initiator_orientation={:?}  \
                 SYN sender is {:?}  direction_flipped={}",
                s.initiator_orientation,
                s.side_for(Orientation::Forward),
                s.direction_flipped,
            );
        }
    }
    println!(
        "  → with inference on, the SYN sender stays Initiator even though \
         the response raced ahead."
    );
}

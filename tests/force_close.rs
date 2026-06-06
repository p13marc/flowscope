//! Plan 89 — programmatic flow termination via `force_close` on
//! tracker + driver mirrors. New `EndReason::ForceClosed` variant.

#![cfg(all(feature = "tracker", feature = "extractors"))]

use flowscope::extract::FiveTuple;
use flowscope::extract::parse::test_frames::ipv4_udp;
use flowscope::{EndReason, FlowEvent, FlowTracker, L4Proto, PacketView, Timestamp};

fn view(frame: &[u8], sec: u32) -> PacketView<'_> {
    PacketView::new(frame, Timestamp::new(sec, 0))
}

// ── Tracker level ────────────────────────────────────────────────

#[test]
fn tracker_force_close_unknown_key_returns_none() {
    use flowscope::FlowExtractor;
    let mut t: FlowTracker<FiveTuple, ()> = FlowTracker::new(FiveTuple::bidirectional());
    // Construct an arbitrary key by tracking a flow then forgetting it.
    let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"x");
    let pv = view(&f, 0);
    let key = FiveTuple::bidirectional().extract(pv).expect("extract").key;
    assert!(t.force_close(&key, Timestamp::default()).is_none());
}

#[test]
fn tracker_force_close_active_key_emits_ended() {
    use flowscope::FlowExtractor;
    let mut t = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
    let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1234, 53, b"hi");
    let pv = view(&f, 0);
    let key = FiveTuple::bidirectional().extract(pv).expect("extract").key;
    t.track(view(&f, 0));
    let ended = t
        .force_close(&key, Timestamp::default())
        .expect("active flow returns Some");
    match ended {
        FlowEvent::Ended { reason, l4, .. } => {
            assert_eq!(reason, EndReason::ForceClosed);
            assert_eq!(l4, Some(L4Proto::Udp));
        }
        _ => panic!("expected Ended variant"),
    }
    // Subsequent force_close on the same key returns None.
    assert!(t.force_close(&key, Timestamp::default()).is_none());
}

#[test]
fn tracker_force_close_clears_hot_cache() {
    use flowscope::FlowExtractor;
    let mut t = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
    let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"x");
    let pv = view(&f, 0);
    let key = FiveTuple::bidirectional().extract(pv).expect("extract").key;
    t.track(view(&f, 0));
    let _ = t.force_close(&key, Timestamp::default());
    // Re-tracking the same flow should treat it as fresh (no
    // half-state from the hot cache).
    let events = t.track(view(&f, 1));
    assert!(
        events
            .iter()
            .any(|e| matches!(e, FlowEvent::Started { .. }))
    );
}

// ── Driver level ─────────────────────────────────────────────────

#[cfg(all(feature = "reassembler", feature = "extractors"))]
mod driver_level {
    use super::*;
    use flowscope::reassembler::BufferedReassemblerFactory;
    use flowscope::{FlowDriver, FlowExtractor};

    #[test]
    fn driver_force_close_returns_ended_with_force_closed_reason() {
        let mut d = FlowDriver::new(
            FiveTuple::bidirectional(),
            BufferedReassemblerFactory::default(),
        );
        let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"x");
        let pv = view(&f, 0);
        let key = FiveTuple::bidirectional().extract(pv).expect("extract").key;
        let _ = d.track(view(&f, 0));
        let events = d.force_close(&key, Timestamp::default());
        let ended = events
            .iter()
            .find(|e| {
                matches!(
                    e,
                    FlowEvent::Ended {
                        reason: EndReason::ForceClosed,
                        ..
                    }
                )
            })
            .expect("force-closed Ended event");
        assert!(matches!(
            ended,
            FlowEvent::Ended {
                reason: EndReason::ForceClosed,
                ..
            }
        ));
    }

    #[test]
    fn driver_force_close_unknown_key_returns_empty_vec() {
        let mut d = FlowDriver::new(
            FiveTuple::bidirectional(),
            BufferedReassemblerFactory::default(),
        );
        // Synthesise a never-tracked key.
        let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"x");
        let pv = view(&f, 0);
        let key = FiveTuple::bidirectional().extract(pv).expect("extract").key;
        let events = d.force_close(&key, Timestamp::default());
        assert!(events.is_empty());
    }
}

#[cfg(all(feature = "session", feature = "reassembler", feature = "test-helpers"))]
mod session_driver_level {
    use super::*;
    use flowscope::extract::parse::test_frames::ipv4_tcp;
    use flowscope::test_helpers::EchoSessionParser;
    use flowscope::{FlowSessionDriver, SessionEvent};

    fn build_3whs() -> Vec<Vec<u8>> {
        let mac = [0u8; 6];
        vec![
            ipv4_tcp(
                mac,
                mac,
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                1234,
                80,
                1000,
                0,
                0x02,
                &[],
            ),
            ipv4_tcp(
                mac,
                mac,
                [10, 0, 0, 2],
                [10, 0, 0, 1],
                80,
                1234,
                5000,
                1001,
                0x12,
                &[],
            ),
            ipv4_tcp(
                mac,
                mac,
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                1234,
                80,
                1001,
                5001,
                0x10,
                &[],
            ),
        ]
    }

    #[test]
    fn session_driver_force_close_emits_closed_with_force_closed_reason() {
        let mut d = FlowSessionDriver::new(FiveTuple::bidirectional(), EchoSessionParser);
        let mut events: Vec<SessionEvent<_, _>> = Vec::new();
        for f in build_3whs() {
            events.extend(d.track(view(&f, 0)));
        }
        // Grab the key from the Started event.
        let key = events
            .iter()
            .find_map(|e| match e {
                SessionEvent::Started { key, .. } => Some(*key),
                _ => None,
            })
            .expect("Started event");
        let close_events = d.force_close(&key, Timestamp::default());
        let reason = close_events
            .iter()
            .find_map(|e| match e {
                SessionEvent::Closed { reason, .. } => Some(*reason),
                _ => None,
            })
            .expect("Closed event");
        assert_eq!(reason, EndReason::ForceClosed);
    }
}

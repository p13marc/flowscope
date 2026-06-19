//! Plan 89 — programmatic flow termination via `force_close` on
//! tracker + driver mirrors. New `EndReason::ForceClosed` variant.

#![cfg(all(feature = "tracker", feature = "extractors"))]

use flowscope::{
    extract::{parse::test_frames::ipv4_udp, FiveTuple},
    EndReason, FlowEvent, FlowTracker, L4Proto, PacketView, Timestamp,
};

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
    assert!(events
        .iter()
        .any(|e| matches!(e, FlowEvent::Started { .. })));
}

// ── Driver level ─────────────────────────────────────────────────

#[cfg(all(feature = "reassembler", feature = "extractors"))]
mod driver_level {
    use flowscope::{reassembler::BufferedReassemblerFactory, FlowDriver, FlowExtractor};

    use super::*;

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

// NOTE: The legacy `FlowSessionDriver::force_close` test that lived
// here was removed during plan 121's migration to the typed
// `Driver<E>` shape. The typed driver does not yet expose a
// `force_close` method; it will return as a feature of the new
// shape in a future cycle. The tracker-level and `FlowDriver`-level
// force_close behaviour above remains covered.

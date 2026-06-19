//! Plan 90 — `FlowTracker::iter_active()` snapshot iterator.

#![cfg(all(feature = "tracker", feature = "extractors"))]

use flowscope::{
    extract::{
        parse::test_frames::{ipv4_tcp, ipv4_udp},
        FiveTuple,
    },
    FlowState, FlowTracker, L4Proto, PacketView, Timestamp,
};

fn view(frame: &[u8], sec: u32) -> PacketView<'_> {
    PacketView::new(frame, Timestamp::new(sec, 0))
}

#[test]
fn empty_tracker_yields_no_entries() {
    let t: FlowTracker<FiveTuple, ()> = FlowTracker::new(FiveTuple::bidirectional());
    assert_eq!(t.iter_active().count(), 0);
}

#[test]
fn yields_each_active_flow_once() {
    let mut t = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
    for (a, b) in [(1, 2), (3, 4), (5, 6)] {
        let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], a, b, b"x");
        t.track(view(&f, 0));
    }
    assert_eq!(t.iter_active().count(), 3);
}

#[test]
fn surfaces_l4_per_flow() {
    let mut t = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
    // UDP flow
    let udp = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1234, 53, b"hi");
    t.track(view(&udp, 0));
    // TCP SYN
    let mac = [0u8; 6];
    let syn = ipv4_tcp(
        mac,
        mac,
        [10, 0, 0, 3],
        [10, 0, 0, 4],
        2222,
        80,
        1000,
        0,
        0x02,
        &[],
    );
    t.track(view(&syn, 0));
    let l4s: Vec<_> = t.iter_active().filter_map(|af| af.l4).collect();
    assert!(l4s.contains(&L4Proto::Udp));
    assert!(l4s.contains(&L4Proto::Tcp));
    assert_eq!(l4s.len(), 2);
}

#[test]
fn surfaces_tcp_state_established() {
    let mut t = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
    let mac = [0u8; 6];
    let syn = ipv4_tcp(
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
    );
    let synack = ipv4_tcp(
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
    );
    let ack = ipv4_tcp(
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
    );
    t.track(view(&syn, 0));
    t.track(view(&synack, 0));
    t.track(view(&ack, 0));
    let states: Vec<_> = t.iter_active().map(|af| af.state).collect();
    assert!(states.contains(&FlowState::Established));
}

#[test]
fn surfaces_user_state() {
    let mut next: u32 = 100;
    let mut t: FlowTracker<FiveTuple, u32> =
        FlowTracker::with_state(FiveTuple::bidirectional(), move |_| {
            let v = next;
            next += 1;
            v
        });
    let f1 = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"a");
    let f2 = ipv4_udp([10, 0, 0, 3], [10, 0, 0, 4], 3, 4, b"b");
    t.track(view(&f1, 0));
    t.track(view(&f2, 0));
    let mut users: Vec<u32> = t.iter_active().map(|af| *af.user).collect();
    users.sort();
    assert_eq!(users, vec![100, 101]);
}

#[test]
fn composes_with_filter() {
    let mut t = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
    let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"x");
    t.track(view(&f, 0));
    let terminal_count = t.iter_active().filter(|af| af.state.is_terminal()).count();
    assert_eq!(terminal_count, 0); // live flow is not terminal
}

#[test]
fn debug_format_does_not_panic() {
    let mut t = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
    let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"x");
    t.track(view(&f, 0));
    for af in t.iter_active() {
        let _ = format!("{af:?}");
    }
}

//! "Strictly better than 0.24.1" gates. Run in release:
//! `cargo test --release` from `compat/`.

use flowscope_compat::{Outcome, Scenario, alloc::Counting, run_new, run_old, traffic};

#[global_allocator]
static A: Counting = Counting;

/// Out-of-order budget per side (flowscope default) + one segment +
/// the allowed slack: the most the driver may hold at rest.
const S8_BUDGET: u64 = 256 * 1024 + 1500 + 64 * 1024;
/// Transient peak (a buffer reallocating while its data is copied).
const S8_PEAK: u64 = 2 * 256 * 1024 + 64 * 1024;

fn superset(s: Scenario, new: &Outcome, old: &Outcome) {
    assert!(new.lines_initiator >= old.lines_initiator, "{}: initiator lines {new:?} < {old:?}", s.name());
    assert!(new.lines_responder >= old.lines_responder, "{}: responder lines {new:?} < {old:?}", s.name());
    // A side the parser stopped reading after a gap is reported
    // (`ParserSideStopped`) instead of getting a `fin_*` — the parser
    // is told the stream is incomplete rather than that it ended.
    assert!(
        new.fins + new.side_stopped >= old.fins,
        "{}: fin markers {new:?} < {old:?}",
        s.name()
    );
    assert!(new.datagrams >= old.datagrams, "{}: datagrams {new:?} < {old:?}", s.name());
    assert_eq!(new.ended, old.ended, "{}: flows ended", s.name());
}

fn check(s: Scenario, cap: &traffic::Capture) {
    let (on, cn) = run_new::run(s, cap);
    let (oo, co) = run_old::run(s, cap);
    superset(s, &on, &oo);
    if s != Scenario::S7Lossy && s != Scenario::S8ReverseOoo {
        assert!(cn.blocks < co.blocks, "{}: allocations {} >= {}", s.name(), cn.blocks, co.blocks);
    }
}

#[test]
fn s1_one_port_slot() {
    check(Scenario::S1OnePortSlot, &Scenario::S1OnePortSlot.traffic());
}

#[test]
fn s2_eight_port_slots() {
    check(Scenario::S2EightPortSlots, &Scenario::S2EightPortSlots.traffic());
}

#[test]
fn s3_thirty_two_port_slots() {
    check(Scenario::S3ThirtyTwoPortSlots, &Scenario::S3ThirtyTwoPortSlots.traffic());
}

#[test]
fn s4_heuristic() {
    check(Scenario::S4Heuristic, &Scenario::S4Heuristic.traffic());
}

#[test]
fn s5_datagram() {
    check(Scenario::S5Datagram, &Scenario::S5Datagram.traffic());
}

/// 0.24.1 is quadratic in open flows here, so the gate uses 20k.
#[test]
fn s6_retained_bytes_per_idle_flow() {
    let n = 20_000u64;
    let cap = traffic::many_open_flows(n as u32);
    let (on, cn) = run_new::run(Scenario::S6ManyFlows, &cap);
    let (oo, co) = run_old::run(Scenario::S6ManyFlows, &cap);
    superset(Scenario::S6ManyFlows, &on, &oo);
    assert!(cn.blocks < co.blocks, "allocations {} >= {}", cn.blocks, co.blocks);
    let (pn, po) = (cn.retained_bytes / n, co.retained_bytes / n);
    eprintln!("retained per idle flow: new {pn} B, old {po} B");
    assert!(pn < po, "retained per idle flow {pn} >= {po}");
}

/// One lost initiator segment per flow: every message 0.24.1 produced,
/// including both sides' fin markers, must still be produced.
#[test]
fn s7_lossy_output_superset() {
    check(Scenario::S7Lossy, &Scenario::S7Lossy.traffic());
}

/// Adversarial 1-byte reverse out-of-order data stays within the
/// out-of-order budget and finishes in reasonable time.
#[test]
fn s8_reverse_ooo_bounded() {
    s8(traffic::reverse_ooo(300_000));
}

/// Same, ascending order (the worst case for a forward overlap scan).
#[test]
fn s8_ascending_ooo_bounded() {
    s8(traffic::ascending_ooo(300_000));
}

fn s8(cap: traffic::Capture) {
    let base = run_new::run(Scenario::S8ReverseOoo, &traffic::reverse_ooo(1)).1;
    let (on, cn) = run_new::run(Scenario::S8ReverseOoo, &cap);
    let (oo, _) = run_old::run(Scenario::S8ReverseOoo, &cap);
    let resident = cn.resident_bytes.saturating_sub(base.resident_bytes);
    let peak = cn.peak_bytes.saturating_sub(base.peak_bytes);
    eprintln!("S8 resident growth {resident} B, peak growth {peak} B, time {:?}", cn.time);
    assert!(resident <= S8_BUDGET, "S8 resident growth {resident} > {S8_BUDGET}");
    assert!(peak <= S8_PEAK, "S8 peak growth {peak} > {S8_PEAK}");
    superset(Scenario::S8ReverseOoo, &on, &oo);
    assert!(cn.time.as_secs() < 5, "S8 took {:?}", cn.time);
}

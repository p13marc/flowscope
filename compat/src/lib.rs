//! Comparison harness: the same traffic through this tree's flowscope
//! (`new`) and the released 0.24.1 (`old`), via the typed `Driver`
//! both versions share.
//!
//! Each scenario reports what the parsers produced, how many heap
//! blocks the run allocated, peak / retained live heap, and wall time.
//! `tests/gates.rs` turns the comparison into pass/fail gates;
//! `src/bin/compat-bench.rs` prints the table and applies the
//! throughput gate.

pub mod alloc;
pub mod traffic;

use std::time::Duration;

/// What one scenario run produced and cost.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Outcome {
    /// Line messages from the initiator side.
    pub lines_initiator: u64,
    /// Line messages from the responder side.
    pub lines_responder: u64,
    /// `fin_*` markers (one per side whose stream ended cleanly).
    pub fins: u64,
    /// Datagram messages.
    pub datagrams: u64,
    /// `Event::Ended` count.
    pub ended: u64,
    /// `Event::ParserClosed` count.
    pub parser_closed: u64,
    /// `Event::ParserSideStopped` count (0.25+): a side the parser
    /// stopped reading after a gap — reported instead of a `fin_*`.
    pub side_stopped: u64,
}

/// Cost of one scenario run.
#[derive(Debug, Default, Clone, Copy)]
pub struct Cost {
    /// Heap blocks allocated during the run.
    pub blocks: u64,
    /// Peak live heap during the run, relative to its start
    /// (includes transient reallocation copies).
    pub peak_bytes: u64,
    /// Highest live heap observed *between* packets — what the
    /// driver holds at rest.
    pub resident_bytes: u64,
    /// Live heap at the scenario's measuring point (see `Scenario`),
    /// relative to the run's start.
    pub retained_bytes: u64,
    /// Wall time.
    pub time: Duration,
}

/// Scenarios S1–S8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scenario {
    /// One port slot, sequential HTTP-like line flows.
    S1OnePortSlot,
    /// Eight port slots (only one matches the traffic).
    S2EightPortSlots,
    /// Thirty-two port slots (only one matches).
    S3ThirtyTwoPortSlots,
    /// A heuristic slot only; half the flows match its signature.
    S4Heuristic,
    /// A datagram slot on port 53, query/response pairs.
    S5Datagram,
    /// 100k concurrent flows; retained bytes measured while every
    /// flow is open and idle.
    S6ManyFlows,
    /// Lossy flows: one initiator segment in 50 never arrives.
    S7Lossy,
    /// Adversarial out-of-order: 1-byte segments in reverse order
    /// above a hole that never fills.
    S8ReverseOoo,
}

impl Scenario {
    /// Every scenario, in order.
    pub const ALL: [Scenario; 8] = [
        Scenario::S1OnePortSlot,
        Scenario::S2EightPortSlots,
        Scenario::S3ThirtyTwoPortSlots,
        Scenario::S4Heuristic,
        Scenario::S5Datagram,
        Scenario::S6ManyFlows,
        Scenario::S7Lossy,
        Scenario::S8ReverseOoo,
    ];

    /// Short label.
    pub fn name(self) -> &'static str {
        match self {
            Scenario::S1OnePortSlot => "S1 1 port slot",
            Scenario::S2EightPortSlots => "S2 8 port slots",
            Scenario::S3ThirtyTwoPortSlots => "S3 32 port slots",
            Scenario::S4Heuristic => "S4 heuristic",
            Scenario::S5Datagram => "S5 datagram",
            Scenario::S6ManyFlows => "S6 100k flows",
            Scenario::S7Lossy => "S7 lossy",
            Scenario::S8ReverseOoo => "S8 reverse OOO",
        }
    }

    /// Captured traffic for this scenario.
    pub fn traffic(self) -> traffic::Capture {
        use traffic::*;
        match self {
            Scenario::S1OnePortSlot | Scenario::S2EightPortSlots | Scenario::S3ThirtyTwoPortSlots => {
                line_flows(2_000, 10, 80, None)
            }
            Scenario::S4Heuristic => heuristic_flows(2_000, 10),
            Scenario::S5Datagram => dns_pairs(20_000),
            Scenario::S6ManyFlows => many_open_flows(100_000),
            Scenario::S7Lossy => line_flows(500, 50, 80, Some(25)),
            Scenario::S8ReverseOoo => reverse_ooo(s8_bytes()),
        }
    }
}

/// S8 size (bytes above the hole), `COMPAT_S8_BYTES` overrides.
pub fn s8_bytes() -> usize {
    std::env::var("COMPAT_S8_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300_000)
}

/// Generates `run_new` / `run_old`: identical code against each crate.
macro_rules! runner {
    ($modname:ident, $fs:ident, $is_side_stop:expr) => {
        pub mod $modname {
            use super::{Cost, Outcome, Scenario, alloc, traffic::Capture};
            use $fs::driver::{Driver, Event, SlotHandle, SlotMessage};
            use $fs::extract::{FiveTuple, FiveTupleKey};
            use $fs::{DatagramParser, FlowSide, PacketView, SessionParser, Timestamp};

            /// Messages the harness parsers emit.
            #[derive(Debug, Clone, Copy, PartialEq, Eq)]
            pub enum Msg {
                Line(bool),
                Fin(bool),
                Datagram,
            }

            /// Emits one `Line` per `\n`, a `Fin` marker per clean side end.
            #[derive(Default, Clone)]
            pub struct LineParser {
                partial: [usize; 2],
            }

            impl LineParser {
                fn feed(&mut self, side: usize, b: &[u8], out: &mut Vec<Msg>) {
                    for &c in b {
                        if c == b'\n' {
                            out.push(Msg::Line(side == 0));
                            self.partial[side] = 0;
                        } else {
                            self.partial[side] += 1;
                        }
                    }
                }
            }

            impl SessionParser for LineParser {
                type Message = Msg;
                fn feed_initiator(&mut self, b: &[u8], _: Timestamp, out: &mut Vec<Msg>) {
                    self.feed(0, b, out)
                }
                fn feed_responder(&mut self, b: &[u8], _: Timestamp, out: &mut Vec<Msg>) {
                    self.feed(1, b, out)
                }
                fn fin_initiator(&mut self, out: &mut Vec<Msg>) {
                    out.push(Msg::Fin(true))
                }
                fn fin_responder(&mut self, out: &mut Vec<Msg>) {
                    out.push(Msg::Fin(false))
                }
            }

            /// One message per datagram.
            #[derive(Default, Clone)]
            pub struct DnsLike;

            impl DatagramParser for DnsLike {
                type Message = Msg;
                fn parse(&mut self, p: &[u8], _: FlowSide, _: Timestamp, out: &mut Vec<Msg>) {
                    if !p.is_empty() {
                        out.push(Msg::Datagram);
                    }
                }
            }

            fn sig_get(b: &[u8]) -> $fs::detect::signatures::SignatureMatch {
                use $fs::detect::signatures::SignatureMatch as M;
                if b.len() < 3 {
                    M::NeedMoreData
                } else if b.starts_with(b"GET") {
                    M::Match
                } else {
                    M::NoMatch
                }
            }

            fn count(m: &Msg, o: &mut Outcome) {
                match *m {
                    Msg::Line(true) => o.lines_initiator += 1,
                    Msg::Line(false) => o.lines_responder += 1,
                    Msg::Fin(_) => o.fins += 1,
                    Msg::Datagram => o.datagrams += 1,
                }
            }

            fn build(s: Scenario) -> (Driver<FiveTuple>, Vec<SlotHandle<Msg, FiveTupleKey>>) {
                let mut b = Driver::builder(FiveTuple::bidirectional());
                let mut handles = Vec::new();
                match s {
                    Scenario::S1OnePortSlot | Scenario::S6ManyFlows | Scenario::S7Lossy | Scenario::S8ReverseOoo => {
                        handles.push(b.session_on_ports(LineParser::default(), [80]));
                    }
                    Scenario::S2EightPortSlots | Scenario::S3ThirtyTwoPortSlots => {
                        let n = if s == Scenario::S2EightPortSlots { 8 } else { 32 };
                        // The matching slot is registered last: every
                        // other slot is visited first.
                        for i in 1..n {
                            handles.push(b.session_on_ports(LineParser::default(), [8000 + i as u16]));
                        }
                        handles.push(b.session_on_ports(LineParser::default(), [80]));
                    }
                    Scenario::S4Heuristic => {
                        handles.push(b.session_heuristic(LineParser::default(), sig_get));
                    }
                    Scenario::S5Datagram => {
                        handles.push(b.datagram_on_ports(DnsLike, [53]));
                    }
                }
                (b.build(), handles)
            }

            /// Run `s` over `cap`, measuring allocations while it runs.
            pub fn run(s: Scenario, cap: &Capture) -> (Outcome, Cost) {
                let mut out = Outcome::default();
                let mut events: Vec<Event<FiveTupleKey>> = Vec::with_capacity(1024);
                let mut msgs: Vec<SlotMessage<Msg, FiveTupleKey>> = Vec::with_capacity(1024);
                let guard = alloc::Tracking::start();
                let t0 = std::time::Instant::now();
                let (mut d, mut handles) = build(s);
                let mut retained = None;
                let mut resident = 0u64;
                for (i, p) in cap.packets.iter().enumerate() {
                    if Some(i) == cap.measure_at {
                        retained = Some(alloc::live_delta());
                    }
                    let ts = Timestamp::new(p.sec, p.nsec);
                    d.track_into(PacketView::new(&p.frame, ts), &mut events);
                    resident = resident.max(alloc::live_delta());
                    if i % 64 == 63 {
                        for e in events.drain(..) {
                            match e {
                                Event::Ended { .. } => out.ended += 1,
                                Event::ParserClosed { .. } => out.parser_closed += 1,
                                ref e if ($is_side_stop)(e) => out.side_stopped += 1,
                                _ => {}
                            }
                        }
                        for h in handles.iter_mut() {
                            h.drain(&mut msgs);
                            for m in msgs.drain(..) {
                                count(&m.message, &mut out);
                            }
                        }
                    }
                }
                d.finish_into(&mut events);
                for e in events.drain(..) {
                    match e {
                        Event::Ended { .. } => out.ended += 1,
                        Event::ParserClosed { .. } => out.parser_closed += 1,
                        ref e if ($is_side_stop)(e) => out.side_stopped += 1,
                        _ => {}
                    }
                }
                for h in handles.iter_mut() {
                    h.drain(&mut msgs);
                    for m in msgs.drain(..) {
                        count(&m.message, &mut out);
                    }
                }
                drop(d);
                drop(handles);
                let time = t0.elapsed();
                let stats = guard.finish();
                (
                    out,
                    Cost {
                        blocks: stats.blocks,
                        peak_bytes: stats.peak,
                        resident_bytes: resident,
                        retained_bytes: retained.unwrap_or(0),
                        time,
                    },
                )
            }
        }
    };
}

runner!(
    run_new,
    new,
    |e: &Event<FiveTupleKey>| matches!(e, Event::ParserSideStopped { .. })
);
runner!(run_old, old, |_: &Event<FiveTupleKey>| false);

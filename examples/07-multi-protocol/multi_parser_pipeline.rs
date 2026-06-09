//! Demonstrates running multiple session parsers over a single
//! pcap pass on the plan-121 typed [`Driver`].
//!
//! With the typed driver, "multi-parser" is the natural shape:
//! register each parser with its own builder call; each returns
//! its own typed slot handle. No closed-`M` sum type required.
//!
//! ```bash
//! cargo run --features pcap,extractors,reassembler,session \
//!     --example multi_parser_pipeline -- trace.pcap
//! ```
//!
//! Falls back to `tests/fixtures/length_prefixed/sample.pcap`
//! if no path is provided.

use flowscope::driver::SlotMessage;
use flowscope::driver::{Driver, Event};
use flowscope::extract::{FiveTuple, FiveTupleKey};
use flowscope::pcap::PcapFlowSource;
use flowscope::{FlowSide, SessionParser, Timestamp};

/// Synthetic "parser A" — first byte → message.
#[derive(Default, Clone)]
struct ParserA;

impl SessionParser for ParserA {
    type Message = u8;
    fn feed_initiator(&mut self, b: &[u8], _ts: Timestamp, out: &mut Vec<u8>) {
        if let Some(&first) = b.first() {
            out.push(first);
        }
    }
    fn feed_responder(&mut self, b: &[u8], _ts: Timestamp, out: &mut Vec<u8>) {
        if let Some(&first) = b.first() {
            out.push(first);
        }
    }
}

/// Synthetic "parser B" — byte count.
#[derive(Default, Clone)]
struct ParserB;

impl SessionParser for ParserB {
    type Message = usize;
    fn feed_initiator(&mut self, b: &[u8], _ts: Timestamp, out: &mut Vec<usize>) {
        if !b.is_empty() {
            out.push(b.len());
        }
    }
    fn feed_responder(&mut self, b: &[u8], _ts: Timestamp, out: &mut Vec<usize>) {
        if !b.is_empty() {
            out.push(b.len());
        }
    }
}

fn main() -> flowscope::Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/fixtures/length_prefixed/sample.pcap".to_string());

    let mut builder = Driver::builder(FiveTuple::bidirectional());
    // Parser A: port-routed (HTTP ports).
    let mut a_slot = builder.session_on_ports(ParserA, [80, 8080]);
    // Parser B: broadcast over every flow.
    let mut b_slot = builder.session_broadcast(ParserB);
    let mut driver = builder.build();

    let mut events: Vec<Event<FiveTupleKey>> = Vec::new();
    let mut a_msgs: Vec<SlotMessage<u8, FiveTupleKey>> = Vec::new();
    let mut b_msgs: Vec<SlotMessage<usize, FiveTupleKey>> = Vec::new();

    let mut a_count = 0usize;
    let mut b_count = 0usize;

    for view in PcapFlowSource::open(&path)?.views() {
        let view = view?;
        events.clear();
        driver.track_into(&view, &mut events);
        a_msgs.clear();
        a_slot.drain(&mut a_msgs);
        b_msgs.clear();
        b_slot.drain(&mut b_msgs);

        for m in &a_msgs {
            a_count += 1;
            let side_str = match m.side {
                FlowSide::Initiator => "i",
                FlowSide::Responder => "r",
            };
            println!("A:{side_str} 0x{:02x}", m.message);
        }
        for m in &b_msgs {
            b_count += 1;
            println!("B: {} bytes", m.message);
        }
    }

    // End-of-input flush.
    events.clear();
    driver.finish_into(&mut events);
    a_msgs.clear();
    a_slot.drain(&mut a_msgs);
    b_msgs.clear();
    b_slot.drain(&mut b_msgs);
    for m in &a_msgs {
        a_count += 1;
        println!("A (flush): 0x{:02x}", m.message);
    }
    for m in &b_msgs {
        b_count += 1;
        println!("B (flush): {} bytes", m.message);
    }

    println!("---");
    println!("totals: A={a_count}, B={b_count}");
    Ok(())
}

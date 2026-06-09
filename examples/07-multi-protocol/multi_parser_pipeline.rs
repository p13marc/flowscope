//! Demonstrates [`flowscope::FlowMultiSessionDriver`] —
//! running multiple session parsers over a single pcap pass.
//!
//! ```bash
//! cargo run --features pcap,extractors,reassembler,session \
//!     --example multi_parser_pipeline -- trace.pcap
//! ```
//!
//! Falls back to `tests/fixtures/length_prefixed/sample.pcap`
//! if no path is provided.

use flowscope::extract::FiveTuple;
use flowscope::pcap::PcapFlowSource;
use flowscope::{FlowMultiSessionDriver, FlowSide, SessionEvent, SessionParser, Timestamp};

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

/// Composite event type — one variant per registered parser.
#[derive(Debug)]
enum L7 {
    A(u8),
    B(usize),
}

fn main() -> flowscope::Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/fixtures/length_prefixed/sample.pcap".to_string());

    let mut driver = FlowMultiSessionDriver::<_, L7>::new(FiveTuple::bidirectional())
        .with_parser_on_ports(ParserA, [80, 8080], L7::A)
        .with_parser_broadcast(ParserB, L7::B);

    let mut a_count = 0usize;
    let mut b_count = 0usize;

    for view in PcapFlowSource::open(&path)?.views() {
        let view = view?;
        for ev in driver.track(&view) {
            match ev {
                SessionEvent::Application {
                    message: L7::A(b),
                    side,
                    ..
                } => {
                    a_count += 1;
                    let side_str = match side {
                        FlowSide::Initiator => "i",
                        FlowSide::Responder => "r",
                    };
                    println!("A:{side_str} 0x{b:02x}");
                }
                SessionEvent::Application {
                    message: L7::B(n), ..
                } => {
                    b_count += 1;
                    println!("B: {n} bytes");
                }
                _ => {}
            }
        }
    }

    // End-of-input flush.
    for ev in driver.finish() {
        if let SessionEvent::Application { message, .. } = ev {
            match message {
                L7::A(b) => {
                    a_count += 1;
                    println!("A (flush): 0x{b:02x}");
                }
                L7::B(n) => {
                    b_count += 1;
                    println!("B (flush): {n} bytes");
                }
            }
        }
    }

    println!("---");
    println!("totals: A={a_count}, B={b_count}");
    Ok(())
}

//! `cargo run --example hello_pipeline --features pcap,extractors,reassembler,session`
//!
//! The shortest hello-world for the plan-121 typed [`Driver`].
//!
//! Reads a pcap, registers an echo `SessionParser` that returns
//! every payload chunk verbatim, and prints each event to stdout.

use flowscope::driver_unified::SlotMessage;
use flowscope::driver_unified::typed::{Driver, Event};
use flowscope::extract::{FiveTuple, FiveTupleKey};
use flowscope::pcap::PcapFlowSource;
use flowscope::{SessionParser, Timestamp};

#[derive(Default, Clone)]
struct EchoParser;

impl SessionParser for EchoParser {
    type Message = Vec<u8>;
    fn feed_initiator(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<Vec<u8>>) {
        if !bytes.is_empty() {
            out.push(bytes.to_vec());
        }
    }
    fn feed_responder(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<Vec<u8>>) {
        if !bytes.is_empty() {
            out.push(bytes.to_vec());
        }
    }
}

fn main() -> flowscope::Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/fixtures/length_prefixed/sample.pcap".to_string());

    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut echo_slot = builder.session_broadcast(EchoParser);
    let mut driver = builder.build();

    let mut events: Vec<Event<FiveTupleKey>> = Vec::new();
    let mut msgs: Vec<SlotMessage<Vec<u8>, FiveTupleKey>> = Vec::new();

    let mut event_count = 0usize;
    let mut app_count = 0usize;

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        events.clear();
        driver.track_into(&owned, &mut events);
        msgs.clear();
        echo_slot.drain(&mut msgs);

        event_count += events.len();
        for m in &msgs {
            app_count += 1;
            println!("application: {} bytes", m.message.len());
        }
    }

    events.clear();
    driver.finish_into(&mut events);
    event_count += events.len();
    msgs.clear();
    echo_slot.drain(&mut msgs);
    for m in &msgs {
        app_count += 1;
        println!("application: {} bytes", m.message.len());
    }

    println!("pipeline drained — {event_count} events, {app_count} application messages");
    Ok(())
}

//! `cargo run --example hello_pipeline --features pcap,extractors,reassembler,session`
//!
//! The shortest hello-world for `flowscope::Pipeline`.
//!
//! Reads a pcap, registers an echo `SessionParser` that returns
//! every payload chunk verbatim, and prints each `Event` to
//! stdout.

use flowscope::prelude::*;

#[derive(Default, Clone)]
struct EchoParser;

impl SessionParser for EchoParser {
    type Message = Vec<u8>;
    fn feed_initiator(&mut self, bytes: &[u8], _ts: Timestamp) -> Vec<Vec<u8>> {
        if bytes.is_empty() {
            Vec::new()
        } else {
            vec![bytes.to_vec()]
        }
    }
    fn feed_responder(&mut self, bytes: &[u8], _ts: Timestamp) -> Vec<Vec<u8>> {
        if bytes.is_empty() {
            Vec::new()
        } else {
            vec![bytes.to_vec()]
        }
    }
}

fn main() -> flowscope::Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/fixtures/length_prefixed/sample.pcap".to_string());

    let mut pipeline = Pipeline::builder(FiveTuple::bidirectional())
        .session(EchoParser)
        .build();

    let mut event_count = 0usize;
    let mut app_count = 0usize;
    for event in pipeline.run_pcap(&path)? {
        let event = event?;
        event_count += 1;
        if let Event::Tcp(SessionEvent::Application { message, .. }) = event {
            app_count += 1;
            println!("application: {} bytes", message.len());
        }
    }
    println!("pipeline drained — {event_count} events, {app_count} application messages");
    Ok(())
}

//! Read pcap bytes from stdin — the `tcpdump -w - | ...`
//! pipe-mode pattern every other capture tool supports.
//!
//! Wraps `std::io::stdin().lock()` in [`PcapFlowSource::from_reader`]
//! (which has been the shape since 0.3) and drives the bytes
//! through a typed [`Driver`] with an HTTP session slot — the
//! manual loop the path-based `session_messages` helper can't
//! cover, because stdin is a reader, not a file path. Output is
//! one line per HTTP request observed.
//!
//! ## Usage
//!
//! ```bash
//! # Live capture, pipe into flowscope:
//! sudo tcpdump -i any -w - 'tcp port 80' \
//!     | cargo run --release --features "pcap,http" --example from_stdin
//!
//! # Replay a file:
//! cat trace.pcap | cargo run --features "pcap,http" --example from_stdin
//! ```
//!
//! ## Back-pressure
//!
//! Reads bounded by the BufReader; if the consumer can't keep
//! up the kernel-side socket buffer fills and tcpdump's
//! libpcap will report packet drops — visible in the
//! `dropped by kernel` count tcpdump prints on SIGINT. Run on
//! `--release` and consider raising the capture buffer
//! (`tcpdump -B 4096`) for high-bandwidth links.
//!
//! Closes #61.

use std::io::{BufReader, stdin};

use flowscope::driver::{Driver, Event, SlotMessage};
use flowscope::extract::{FiveTuple, FiveTupleKey};
use flowscope::http::{HttpMessage, HttpParser};
use flowscope::pcap::PcapFlowSource;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let reader = BufReader::new(stdin().lock());
    let source = PcapFlowSource::from_reader(reader)?;

    // A reader source can't use the path-based `session_messages`
    // helper, so drive a typed `Driver` by hand. `session_broadcast`
    // runs the HTTP parser over every TCP flow (no port filter),
    // matching the old high-level `sessions()` behaviour.
    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut http_slot = builder.session_broadcast(HttpParser::default());
    let mut driver = builder.build();

    let mut events: Vec<Event<FiveTupleKey>> = Vec::new();
    let mut msgs: Vec<SlotMessage<HttpMessage, FiveTupleKey>> = Vec::new();
    let mut count = 0u64;

    for owned in source.views() {
        let owned = owned?;
        events.clear();
        driver.track_into(&owned, &mut events);
        msgs.clear();
        http_slot.drain(&mut msgs);
        for m in &msgs {
            count += 1;
            println!("{:?} → {:?}", m.key, m.message);
        }
    }

    // Flush any flows still buffered at end-of-input.
    let mut tail = Vec::new();
    driver.finish_into(&mut tail);
    msgs.clear();
    http_slot.drain(&mut msgs);
    for m in &msgs {
        count += 1;
        println!("{:?} → {:?}", m.key, m.message);
    }

    eprintln!("processed {count} HTTP message(s) from stdin");
    Ok(())
}

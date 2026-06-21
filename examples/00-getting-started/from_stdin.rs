//! Read pcap bytes from stdin — the `tcpdump -w - | ...`
//! pipe-mode pattern every other capture tool supports.
//!
//! Wraps `std::io::stdin().lock()` in [`PcapFlowSource::from_reader`]
//! (which has been the shape since 0.3) and drives the bytes
//! through the canonical [`PcapFlowSource::sessions`] high-level
//! pipeline. Output is one line per HTTP request observed.
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

use flowscope::extract::FiveTuple;
use flowscope::http::HttpParser;
use flowscope::pcap::PcapFlowSource;
use flowscope::session::SessionEvent;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let reader = BufReader::new(stdin().lock());
    let source = PcapFlowSource::from_reader(reader)?;

    let mut events = 0u64;
    for evt in source.sessions(FiveTuple::bidirectional(), HttpParser::default()) {
        let evt = evt?;
        if let SessionEvent::Application { key, message, .. } = evt {
            events += 1;
            println!("{:?} → {message:?}", key);
        }
    }
    eprintln!("processed {events} HTTP message(s) from stdin");
    Ok(())
}

//! The shortest hello-world for flowscope.
//!
//! Opens a pcap file, runs every HTTP request/response through the
//! built-in parser, and prints them. Zero `Driver::builder` /
//! `SlotHandle` ceremony — everything is wrapped in
//! [`PcapFlowSource::sessions`].
//!
//! ```bash
//! cargo run --features http,pcap --example hello_pipeline -- trace.pcap
//! ```
//!
//! Closes issue #36.

use flowscope::SessionEvent;
use flowscope::extract::FiveTuple;
use flowscope::http::HttpParser;
use flowscope::pcap::PcapFlowSource;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/http_session.pcap".to_string());

    for evt in
        PcapFlowSource::open(&path)?.sessions(FiveTuple::bidirectional(), HttpParser::default())
    {
        if let SessionEvent::Application { key, message, .. } = evt? {
            println!("{:?} → {:?}", key, message);
        }
    }

    Ok(())
}

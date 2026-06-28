//! The shortest hello-world for flowscope.
//!
//! Opens a pcap file, runs every HTTP request/response through the
//! built-in parser, and prints them. Zero `Driver::builder` /
//! `SlotHandle` ceremony — everything is wrapped in
//! [`flowscope::pcap::session_messages`].
//!
//! ```bash
//! cargo run --features http,pcap --example hello_pipeline -- trace.pcap
//! ```
//!
//! Closes issue #36.

use flowscope::http::HttpParser;
use flowscope::pcap::session_messages;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/http_session.pcap".to_string());

    for (key, message) in session_messages::<HttpParser>(&path)? {
        println!("{:?} → {:?}", key, message);
    }

    Ok(())
}

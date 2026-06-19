//! Custom `SessionParser` for a `\n`-terminated line protocol —
//! using [`flowscope::AccumulatingSessionParser`] (plan 106).
//!
//! The 0.9-era version of "write a custom parser" was a
//! `SessionParser` impl with hand-rolled `init_buf` /
//! `resp_buf` accumulation, a `parse_one` loop, and a drain
//! offset:
//!
//! ```ignore
//! #[derive(Default, Clone)]
//! struct LineParser { init_buf: Vec<u8>, resp_buf: Vec<u8> }
//! impl SessionParser for LineParser { … 25 lines … }
//! ```
//!
//! Plan 106 collapses the boilerplate to ONE constructor call
//! over a `parse_one(&[u8]) -> Option<(M, usize)>` closure.
//! `AccumulatingSessionParser` wraps two `BufferedFrameDrain`s
//! internally and threads the `parser_kind` label through.
//!
//! ```bash
//! cargo run --features pcap,extractors,session,test-helpers \
//!     --example accumulating_line_parser
//! ```

use flowscope::{
    AccumulatingSessionParser,
    driver::{Driver, Event, SlotMessage},
    extract::{FiveTuple, FiveTupleKey},
    pcap::PcapFlowSource,
};

fn parse_one(buf: &[u8]) -> Option<(String, usize)> {
    let nl = buf.iter().position(|&b| b == b'\n')?;
    let line = String::from_utf8_lossy(&buf[..nl]).into_owned();
    Some((line, nl + 1))
}

fn main() -> flowscope::Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/http_session.pcap".to_string());

    // ONE constructor call replaces a ~25-LoC SessionParser impl.
    let parser = AccumulatingSessionParser::new("line", parse_one);
    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut line_slot = builder.session_broadcast(parser);
    let mut driver = builder.build();

    let mut events: Vec<Event<FiveTupleKey>> = Vec::new();
    let mut msgs: Vec<SlotMessage<String, FiveTupleKey>> = Vec::new();

    let mut lines = 0usize;
    let mut bytes = 0usize;
    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        events.clear();
        driver.track_into(&owned, &mut events);
        msgs.clear();
        line_slot.drain(&mut msgs);
        for m in &msgs {
            lines += 1;
            bytes += m.message.len();
            if lines <= 10 {
                println!("  {:<32}  {}", format!("{}", m.key.a.ip()), m.message);
            }
        }
    }
    if lines > 10 {
        println!("  … plus {} more lines …", lines - 10);
    }
    println!();
    println!("decoded {lines} lines ({bytes} bytes total)");
    Ok(())
}

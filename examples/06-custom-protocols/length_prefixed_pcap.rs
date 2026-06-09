//! Length-prefixed binary protocol — minimal `SessionParser` example.
//!
//! Wire format (synthetic, modelled after DES PSMSG):
//!
//! ```text
//!   ┌────────┬──────────┬─────────────────────┐
//!   │ marker │ length   │ body                │
//!   │ "PFXn," │ u16/u32  │ body_len bytes      │
//!   └────────┴──────────┴─────────────────────┘
//! ```
//!
//! Two markers:
//!   - `PFX2,` → 2-byte u16 length follows. 7-byte header total.
//!   - `PFX4,` → 4-byte u32 length follows. 9-byte header total.
//!
//! For the live, async, netring-backed equivalent of the wiring at
//! the bottom of this file:
//!
//! ```text
//!     use netring::AsyncCapture;
//!     let mut events = AsyncCapture::open("eth0")?
//!         .flow_stream(FiveTuple::bidirectional())
//!         .session_stream(LengthPrefixedParser::default());
//!     while let Some(ev) = events.next().await { ... }
//! ```

use flowscope::driver::SlotMessage;
use flowscope::driver::{Driver, Event};
use flowscope::extract::{FiveTuple, FiveTupleKey};
use flowscope::pcap::PcapFlowSource;
use flowscope::{FlowSide, SessionParser, Timestamp};
use std::env;

const MARKER_2: &[u8] = b"PFX2,";
const MARKER_4: &[u8] = b"PFX4,";
const HDR_LEN_2: usize = MARKER_2.len() + 2; // 7
const HDR_LEN_4: usize = MARKER_4.len() + 4; // 9

/// One decoded message — opaque bytes, plus which side sent it.
#[derive(Debug, Clone)]
pub struct Record {
    pub side: FlowSide,
    pub body: Vec<u8>,
}

/// A `SessionParser` for the wire format above. One instance per
/// flow; `Default + Clone` so it auto-implements `SessionParserFactory`.
#[derive(Default, Clone)]
pub struct LengthPrefixedParser {
    init_buf: Vec<u8>,
    resp_buf: Vec<u8>,
}

impl SessionParser for LengthPrefixedParser {
    type Message = Record;

    fn feed_initiator(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<Record>) {
        Self::drain(&mut self.init_buf, bytes, FlowSide::Initiator, out);
    }
    fn feed_responder(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<Record>) {
        Self::drain(&mut self.resp_buf, bytes, FlowSide::Responder, out);
    }

    fn parser_kind(&self) -> &'static str {
        "length-prefixed"
    }
}

impl LengthPrefixedParser {
    fn drain(buf: &mut Vec<u8>, incoming: &[u8], side: FlowSide, out: &mut Vec<Record>) {
        buf.extend_from_slice(incoming);
        while let Some((hdr, body_len)) = peek_header(buf) {
            let total = hdr + body_len;
            if buf.len() < total {
                break;
            }
            let body = buf[hdr..total].to_vec();
            buf.drain(..total);
            out.push(Record { side, body });
        }
    }
}

/// Returns `Some((header_byte_count, body_byte_count))` if a complete
/// header sits at the front of `buf`. Doesn't consume.
///
/// On unknown marker this returns `None` and the parser stalls. A
/// production parser would normally choose between (a) drop the
/// leading byte and resync, (b) tear the flow down via an error
/// variant, or (c) leave it stalled until end-of-flow.
pub fn peek_header(buf: &[u8]) -> Option<(usize, usize)> {
    if buf.len() < HDR_LEN_2 {
        return None;
    }
    if buf.starts_with(MARKER_4) {
        if buf.len() < HDR_LEN_4 {
            return None;
        }
        let len = u32::from_be_bytes(buf[MARKER_4.len()..HDR_LEN_4].try_into().unwrap()) as usize;
        return Some((HDR_LEN_4, len));
    }
    if buf.starts_with(MARKER_2) {
        let len = u16::from_be_bytes(buf[MARKER_2.len()..HDR_LEN_2].try_into().unwrap()) as usize;
        return Some((HDR_LEN_2, len));
    }
    None
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args()
        .nth(1)
        .ok_or("usage: length_prefixed_pcap <trace.pcap>")?;

    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut slot = builder.session_broadcast(LengthPrefixedParser::default());
    let mut driver = builder.build();

    let mut events: Vec<Event<FiveTupleKey>> = Vec::new();
    let mut msgs: Vec<SlotMessage<Record, FiveTupleKey>> = Vec::new();

    for view in PcapFlowSource::open(&path)?.views() {
        let view = view?;
        events.clear();
        driver.track_into(&view, &mut events);
        msgs.clear();
        slot.drain(&mut msgs);
        for m in &msgs {
            let arrow = if m.message.side == FlowSide::Initiator {
                "→"
            } else {
                "←"
            };
            println!("{} {} bytes", arrow, m.message.body.len());
        }
    }
    Ok(())
}

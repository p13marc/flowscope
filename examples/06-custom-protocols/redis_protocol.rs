//! Worked example: write a `SessionParser` for the Redis RESP
//! protocol and print every observed command + reply.
//!
//! RESP is a simple text-based protocol:
//! - `+OK\r\n` — simple string
//! - `-ERR …\r\n` — error
//! - `:1234\r\n` — integer
//! - `$5\r\nhello\r\n` — bulk string (length-prefixed)
//! - `*N\r\n …` — array of N elements
//!
//! Clients send commands as arrays of bulk strings:
//! `*3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nbar\r\n` = `SET foo bar`.
//!
//! ```bash
//! cargo run --features pcap,extractors,reassembler --example redis_protocol
//! ```
//!
//! Demonstrates the custom-protocol pattern: minimal state
//! machine, splitting-invariant accumulator, no panic on garbage.

use flowscope::{
    FlowSide, SessionParser, Timestamp,
    driver::{Driver, Event, SlotMessage},
    extract::{FiveTuple, FiveTupleKey},
    pcap::PcapFlowSource,
};

#[derive(Debug, Clone)]
enum RespValue {
    SimpleString(String),
    Error(String),
    Integer(i64),
    BulkString(Option<Vec<u8>>),
    Array(Option<Vec<RespValue>>),
}

impl std::fmt::Display for RespValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RespValue::SimpleString(s) => write!(f, "+{s}"),
            RespValue::Error(s) => write!(f, "-{s}"),
            RespValue::Integer(n) => write!(f, ":{n}"),
            RespValue::BulkString(Some(b)) => write!(f, "{:?}", String::from_utf8_lossy(b)),
            RespValue::BulkString(None) => write!(f, "$-1"),
            RespValue::Array(Some(items)) => {
                write!(f, "[")?;
                for (i, v) in items.iter().enumerate() {
                    if i > 0 {
                        write!(f, " ")?;
                    }
                    write!(f, "{v}")?;
                }
                write!(f, "]")
            }
            RespValue::Array(None) => write!(f, "*-1"),
        }
    }
}

#[derive(Default, Clone)]
struct RespParser {
    init_buf: Vec<u8>,
    resp_buf: Vec<u8>,
}

impl SessionParser for RespParser {
    type Message = RespValue;

    fn feed_initiator(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<RespValue>) {
        self.init_buf.extend_from_slice(bytes);
        drain(&mut self.init_buf, out);
    }

    fn feed_responder(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<RespValue>) {
        self.resp_buf.extend_from_slice(bytes);
        drain(&mut self.resp_buf, out);
    }

    fn parser_kind(&self) -> flowscope::ParserKind {
        flowscope::ParserKind::Other("redis-resp")
    }
}

fn drain(buf: &mut Vec<u8>, out: &mut Vec<RespValue>) {
    while let Some((v, consumed)) = parse_one(buf) {
        out.push(v);
        buf.drain(..consumed);
    }
}

/// Try to parse a single RESP value from `buf[0..]`. Returns
/// `Some((value, consumed_bytes))` or `None` if `buf` is short.
fn parse_one(buf: &[u8]) -> Option<(RespValue, usize)> {
    if buf.is_empty() {
        return None;
    }
    match buf[0] {
        b'+' => {
            let (line, end) = read_line(&buf[1..])?;
            Some((
                RespValue::SimpleString(String::from_utf8_lossy(line).into_owned()),
                1 + end,
            ))
        }
        b'-' => {
            let (line, end) = read_line(&buf[1..])?;
            Some((
                RespValue::Error(String::from_utf8_lossy(line).into_owned()),
                1 + end,
            ))
        }
        b':' => {
            let (line, end) = read_line(&buf[1..])?;
            let n: i64 = std::str::from_utf8(line).ok()?.parse().ok()?;
            Some((RespValue::Integer(n), 1 + end))
        }
        b'$' => {
            let (line, end) = read_line(&buf[1..])?;
            let len: i64 = std::str::from_utf8(line).ok()?.parse().ok()?;
            if len < 0 {
                return Some((RespValue::BulkString(None), 1 + end));
            }
            let len = len as usize;
            let body_start = 1 + end;
            if buf.len() < body_start + len + 2 {
                return None;
            }
            let body = buf[body_start..body_start + len].to_vec();
            Some((RespValue::BulkString(Some(body)), body_start + len + 2))
        }
        b'*' => {
            let (line, end) = read_line(&buf[1..])?;
            let n: i64 = std::str::from_utf8(line).ok()?.parse().ok()?;
            if n < 0 {
                return Some((RespValue::Array(None), 1 + end));
            }
            let mut consumed = 1 + end;
            let mut items = Vec::with_capacity(n as usize);
            for _ in 0..n {
                let (v, c) = parse_one(&buf[consumed..])?;
                items.push(v);
                consumed += c;
            }
            Some((RespValue::Array(Some(items)), consumed))
        }
        _ => None,
    }
}

/// Find `\r\n` and return (slice-before, bytes-consumed).
fn read_line(buf: &[u8]) -> Option<(&[u8], usize)> {
    let mut i = 0;
    while i + 1 < buf.len() {
        if buf[i] == b'\r' && buf[i + 1] == b'\n' {
            return Some((&buf[..i], i + 2));
        }
        i += 1;
    }
    None
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("Demo without input: synthetic command/reply.");
        eprintln!("Provide a Redis pcap to drive the parser against real traffic:");
        eprintln!("  cargo run --example redis_protocol -- trace.pcap");
        eprintln!();
        demo_synthetic();
        return Ok(());
    };

    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut slot = builder.session_on_ports(RespParser::default(), [6379]);
    let mut driver = builder.build();

    let mut events: Vec<Event<FiveTupleKey>> = Vec::new();
    let mut msgs: Vec<SlotMessage<RespValue, FiveTupleKey>> = Vec::new();

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        events.clear();
        driver.track_into(&owned, &mut events);
        msgs.clear();
        slot.drain(&mut msgs);
        for m in &msgs {
            let arrow = match m.side {
                FlowSide::Initiator => "→",
                FlowSide::Responder => "←",
            };
            println!("{arrow} {}", m.message);
        }
    }
    Ok(())
}

fn demo_synthetic() {
    let mut parser = RespParser::default();
    // SET foo bar
    let cmd = b"*3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nbar\r\n";
    let mut msgs = Vec::new();
    parser.feed_initiator(cmd, Timestamp::default(), &mut msgs);
    for msg in msgs.drain(..) {
        println!("→ {msg}");
    }
    // +OK\r\n
    parser.feed_responder(b"+OK\r\n", Timestamp::default(), &mut msgs);
    for msg in msgs.drain(..) {
        println!("← {msg}");
    }
}

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

use flowscope::extract::FiveTuple;
use flowscope::pcap::PcapFlowSource;
use flowscope::{FlowSessionDriver, SessionEvent, SessionParser, Timestamp};

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

    fn feed_initiator(&mut self, bytes: &[u8], _ts: Timestamp) -> Vec<RespValue> {
        self.init_buf.extend_from_slice(bytes);
        drain(&mut self.init_buf)
    }

    fn feed_responder(&mut self, bytes: &[u8], _ts: Timestamp) -> Vec<RespValue> {
        self.resp_buf.extend_from_slice(bytes);
        drain(&mut self.resp_buf)
    }

    fn parser_kind(&self) -> &'static str {
        "redis-resp"
    }
}

fn drain(buf: &mut Vec<u8>) -> Vec<RespValue> {
    let mut out = Vec::new();
    while let Some((v, consumed)) = parse_one(buf) {
        out.push(v);
        buf.drain(..consumed);
    }
    out
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

fn main() -> flowscope::Result<()> {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("Demo without input: synthetic command/reply.");
        eprintln!("Provide a Redis pcap to drive the parser against real traffic:");
        eprintln!("  cargo run --example redis_protocol -- trace.pcap");
        eprintln!();
        demo_synthetic();
        return Ok(());
    };

    let mut driver = FlowSessionDriver::new(FiveTuple::bidirectional(), RespParser::default());

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        for ev in driver.track(&owned) {
            if let SessionEvent::Application { side, message, .. } = ev {
                let arrow = match side {
                    flowscope::FlowSide::Initiator => "→",
                    flowscope::FlowSide::Responder => "←",
                };
                println!("{arrow} {message}");
            }
        }
    }
    Ok(())
}

fn demo_synthetic() {
    let mut parser = RespParser::default();
    // SET foo bar
    let cmd = b"*3\r\n$3\r\nSET\r\n$3\r\nfoo\r\n$3\r\nbar\r\n";
    for msg in parser.feed_initiator(cmd, Timestamp::default()) {
        println!("→ {msg}");
    }
    // +OK\r\n
    for msg in parser.feed_responder(b"+OK\r\n", Timestamp::default()) {
        println!("← {msg}");
    }
}

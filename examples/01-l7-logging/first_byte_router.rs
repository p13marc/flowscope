//! Decide what a connection is speaking from its first bytes, then
//! hand those same bytes to the right parser.
//!
//! The classifier itself is one call. The part worth showing is the
//! composition around it, which is where this goes wrong in practice:
//!
//! - **Accumulate until it decides.** A short peek must yield
//!   `NeedMore`, never a guess. Deciding early is how a connection
//!   ends up at the wrong backend.
//! - **Replay the peeked bytes.** They were consumed to classify, but
//!   the parser still needs them — it has not seen anything yet.
//!   Forgetting this loses the request line.
//! - **The timeout is yours.** A server-speaks-first protocol (SSH,
//!   SMTP) leaves the client peek empty forever. The classifier keeps
//!   saying `NeedMore`; deciding to give up and treat the connection
//!   as opaque is the caller's call, not the parser's.
//!
//! Usage:
//!     cargo run --features http,http2 --example first_byte_router

use bytes::Bytes;
use flowscope::FlowSide;
use flowscope::classify::{Classify, WireProtocol, classify_first_bytes};
use flowscope::http::{HttpEvent, HttpProxyParser};
use flowscope::http2::{Http2Event, Http2Parser, PREFACE};

/// How many bytes we are willing to buffer before giving up and
/// treating the connection as opaque. The classifier needs 24 at
/// most (the h2 preface); this leaves room.
const PEEK_LIMIT: usize = 64;

/// The outcome of routing one connection.
enum Routed {
    Http1(Vec<String>),
    Http2(Vec<String>),
    Opaque(WireProtocol),
    /// Ran out of peek budget without a verdict.
    Undecided,
}

/// Feed a connection's bytes in arbitrary slices, classify, then
/// dispatch — replaying everything peeked into the chosen parser.
fn route(slices: &[&[u8]]) -> Routed {
    let mut peek: Vec<u8> = Vec::new();
    let mut verdict = None;

    // Phase 1: accumulate until the classifier commits.
    let mut consumed = 0usize;
    for slice in slices {
        peek.extend_from_slice(slice);
        consumed += 1;
        match classify_first_bytes(&peek) {
            Classify::Decided(p) => {
                verdict = Some(p);
                break;
            }
            // Still a viable prefix of something — read more.
            _ => {
                if peek.len() >= PEEK_LIMIT {
                    return Routed::Undecided;
                }
            }
        }
    }
    let Some(protocol) = verdict else {
        return Routed::Undecided;
    };

    // Everything that arrived, peeked or not. The parser has seen
    // none of it yet.
    let mut all = peek;
    for slice in &slices[consumed..] {
        all.extend_from_slice(slice);
    }
    let all = Bytes::from(all);

    // Phase 2: dispatch, replaying the peeked bytes.
    match protocol {
        WireProtocol::Http1 => {
            let mut p = HttpProxyParser::new();
            p.push(FlowSide::Initiator, &all);
            let mut seen = Vec::new();
            while let Some(ev) = p.next_event() {
                if let HttpEvent::RequestHead(h) = ev {
                    seen.push(format!(
                        "{} {}",
                        h.method_str().unwrap_or("?"),
                        h.path_str().unwrap_or("?")
                    ));
                }
            }
            Routed::Http1(seen)
        }
        WireProtocol::Http2Preface => {
            let mut p = Http2Parser::new();
            p.push(FlowSide::Initiator, &all);
            let mut seen = Vec::new();
            while let Some(ev) = p.next_event() {
                if let Http2Event::Head(h) = ev {
                    seen.push(format!(
                        "stream {} {}",
                        h.stream_id,
                        h.path().unwrap_or("?")
                    ));
                }
            }
            Routed::Http2(seen)
        }
        // TLS, SSH, and anything unrecognised are forwarded
        // untouched — flowscope has nothing to add, and guessing
        // further would be worse than passing through.
        other => Routed::Opaque(other),
    }
}

fn report(label: &str, routed: Routed) {
    match routed {
        Routed::Http1(reqs) => println!("{label:<22} HTTP/1 — {}", reqs.join(", ")),
        Routed::Http2(streams) => println!("{label:<22} HTTP/2 — {}", streams.join(", ")),
        Routed::Opaque(p) => println!("{label:<22} {p} — passthrough"),
        Routed::Undecided => println!("{label:<22} undecided — passthrough on timeout"),
    }
}

fn main() {
    // An HTTP/1 request dribbled in three slices. The first two are
    // too short to decide on.
    report(
        "http/1 (dribbled)",
        route(&[b"GE", b"T /index.html HTT", b"P/1.1\r\nHost: h\r\n\r\n"]),
    );

    // A prior-knowledge HTTP/2 client. "PRI " looks like an HTTP/1
    // method token, so a classifier that checked HTTP/1 first would
    // send this to the wrong parser.
    let mut h2 = PREFACE.to_vec();
    h2.extend_from_slice(&[
        0, 0, 5, 0x1, 0x4, 0, 0, 0, 1, // HEADERS, END_HEADERS, stream 1
        0x82, 0x87, 0x84, 0x41, 0x00, // :method GET, :scheme, :path /, authority ""
    ]);
    report("http/2 prior-knowledge", route(&[&h2]));

    // A TLS ClientHello: recognised, then left alone.
    report(
        "tls",
        route(&[&[0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc]]),
    );

    // SSH — the server speaks first in practice, but if the client
    // banner arrives it is recognisable.
    report("ssh", route(&[b"SSH-2.0-OpenSSH_9.6\r\n"]));

    // Something we do not recognise. `Raw` is a decision, not a
    // failure: forward it and stop looking.
    report(
        "binary junk",
        route(&[&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]]),
    );

    // A client that connects and says nothing — the server-speaks-
    // first case. The classifier never decides, so the caller's
    // timeout is what resolves it.
    report("silent client", route(&[b""]));
}

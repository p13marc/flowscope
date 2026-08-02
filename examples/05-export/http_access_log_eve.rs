//! Emit a SIEM-ready access log from the inline path.
//!
//! Switching a deployment from a tap to inline should not cost you
//! your HTTP logs. `HttpAccessLog` derives records from the streaming
//! parser's events — watching heads and counting bytes, never
//! retaining a body — and `EveJsonWriter::write_http_access` writes
//! them in the Suricata `event_type: "http"` shape a SIEM already
//! ingests.
//!
//! Four outcomes appear in the output, and the last is the one a
//! passive log cannot produce at all:
//!
//! - `completed` — request and response both framed.
//! - `no_response` — the connection ended with the request unanswered.
//! - `switched` — the connection became a tunnel.
//! - `refused` — the proxy declined to forward, and says which
//!   framing rule was violated.
//!
//! Usage:
//!     cargo run --features http,emit-eve --example http_access_log_eve

use bytes::Bytes;
use flowscope::emit::EveJsonWriter;
use flowscope::http::{HttpAccessLog, HttpAccessRecord, HttpProxyParser};
use flowscope::{FlowSide, Timestamp};

/// Run one connection through the parser and collect its records.
fn connection(client: &[u8], server: &[u8]) -> Vec<HttpAccessRecord> {
    let mut proxy = HttpProxyParser::new();
    let mut log = HttpAccessLog::new();
    let mut out = Vec::new();

    proxy.push(FlowSide::Initiator, &Bytes::copy_from_slice(client));
    proxy.push(FlowSide::Responder, &Bytes::copy_from_slice(server));
    while let Some(ev) = proxy.next_event() {
        log.observe(&ev, &mut out);
    }
    // Passing the poison is what turns "nothing came back" into
    // "refused, and here is why".
    log.finish(proxy.poison(), &mut out);
    out
}

fn main() {
    let mut records = Vec::new();

    // A normal exchange.
    records.extend(connection(
        b"POST /orders HTTP/1.1\r\nHost: api.example\r\nContent-Length: 5\r\n\r\nhello",
        b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok",
    ));

    // A request the server never answered.
    records.extend(connection(
        b"GET /health HTTP/1.1\r\nHost: api.example\r\n\r\n",
        b"",
    ));

    // A CONNECT tunnel — after this the bytes are not HTTP.
    records.extend(connection(
        b"CONNECT db.example:5432 HTTP/1.1\r\nHost: db.example:5432\r\n\r\n",
        b"HTTP/1.1 200 Connection Established\r\n\r\n",
    ));

    // A smuggling attempt: Content-Length and Transfer-Encoding
    // together, so two recipients could disagree about where this
    // message ends. The proxy refuses, and the log says so.
    records.extend(connection(
        b"POST /transfer HTTP/1.1\r\nHost: api.example\r\nContent-Length: 6\r\n\
          Transfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\n\r\n",
        b"",
    ));

    let stdout = std::io::stdout();
    let mut writer = EveJsonWriter::new(stdout.lock());
    for (i, rec) in records.iter().enumerate() {
        writer
            .write_http_access(rec, Timestamp::new(1_700_000_000 + i as u32, 0))
            .expect("write");
    }
    writer.flush().expect("flush");

    eprintln!(
        "\n{} records. Note the last one: a connection refused for a\n\
         framing violation still produces a log line, carrying the\n\
         specific rule that was broken under flowscope.refused_reason.\n\
         A log that stayed silent there would report that nothing\n\
         happened.",
        records.len()
    );
}

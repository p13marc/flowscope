//! Route HTTP requests on their head, forward the body verbatim, and
//! tear the connection down on a framing violation — the loop an
//! inline proxy runs, with no sockets involved.
//!
//! This is the shape [`HttpProxyParser`] exists for. The parser is a
//! *framing oracle beside the data path*: the proxy owns the sockets
//! and forwards bytes itself, feeding a copy to flowscope to learn
//! where messages begin and end and whether the framing can be
//! trusted at all.
//!
//! Three properties are demonstrated, each printed as it happens:
//!
//! 1. the routing key is available **before** any body byte is read;
//! 2. concatenating every event's `raw` reproduces the connection
//!    byte for byte, so forwarding is lossless;
//! 3. an ambiguously framed message stops the connection instead of
//!    being passed on.
//!
//! Usage:
//!     cargo run --features http --example http_streaming_proxy

use bytes::Bytes;
use flowscope::FlowSide;
use flowscope::http::{HttpEvent, HttpProxyParser, SwitchKind};

/// A connection's worth of client bytes, fed in arbitrary slices to
/// show the parser does not care where the boundaries fall.
fn client_traffic() -> Vec<&'static [u8]> {
    vec![
        b"POST /orders HTTP/1.1\r\nHost: api.exam",
        b"ple.com\r\nContent-Length: 11\r\n\r\nhello",
        b" world",
        b"GET /health HTTP/1.1\r\nHost: api.example.com\r\n\r\n",
    ]
}

fn main() {
    println!("== a well-framed connection ==\n");
    let mut proxy = HttpProxyParser::new();
    // What we would have written to the upstream socket.
    let mut forwarded: Vec<u8> = Vec::new();
    let mut body_seen = 0usize;

    for slice in client_traffic() {
        let mut pending = Bytes::from_static(slice);
        while !pending.is_empty() {
            let accepted = proxy.push(FlowSide::Initiator, &pending);
            if accepted == 0 {
                // Backpressure: drain events before offering more.
                // (With default caps and this much traffic it never
                // triggers, but a real proxy must handle it.)
                if proxy.next_event().is_none() {
                    break;
                }
                continue;
            }
            pending = pending.slice(accepted..);

            while let Some(ev) = proxy.next_event() {
                match ev {
                    HttpEvent::RequestHead(head) => {
                        // Routing happens here — no body byte has been
                        // looked at yet.
                        let authority = head
                            .authority()
                            .map(|a| a.host)
                            .unwrap_or_else(|_| "<unroutable>".into());
                        println!(
                            "route  {} {} -> backend for {authority} ({:?})",
                            head.method_str().unwrap_or("?"),
                            head.path_str().unwrap_or("?"),
                            head.framing,
                        );
                        forwarded.extend_from_slice(&head.raw);
                    }
                    HttpEvent::Body { data, raw, .. } => {
                        // The proxy relays the raw bytes; `data` is
                        // the decoded payload, here only to report a
                        // size. Neither is retained by the parser.
                        body_seen += data.len();
                        forwarded.extend_from_slice(&raw);
                    }
                    HttpEvent::Trailers { raw, .. } => forwarded.extend_from_slice(&raw),
                    HttpEvent::End { .. } => println!("       message complete"),
                    HttpEvent::SwitchProtocols { kind } => {
                        println!("       protocol switch: {kind:?} — splicing from here");
                        if matches!(kind, SwitchKind::ConnectTunnel) {
                            break;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    let original: Vec<u8> = client_traffic().concat();
    println!(
        "\nforwarded {} bytes, body payload {body_seen} bytes",
        forwarded.len()
    );
    assert_eq!(
        forwarded, original,
        "raw spans must reproduce the connection exactly"
    );
    println!("forwarded bytes are identical to what arrived ✓");

    println!("\n== an ambiguously framed connection ==\n");
    let mut proxy = HttpProxyParser::new();
    // Content-Length and Transfer-Encoding together: two recipients
    // can disagree about where this message ends, which is how
    // request smuggling works.
    let smuggled = Bytes::from_static(
        b"POST /orders HTTP/1.1\r\nHost: api.example.com\r\n\
          Content-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\n\r\n",
    );
    proxy.push(FlowSide::Initiator, &smuggled);
    while proxy.next_event().is_some() {}

    match proxy.poison() {
        Some(reason) => {
            println!("refused: {reason}");
            println!(
                "         (client fault: {:?})",
                reason.implies_client_fault()
            );
            // Nothing more is accepted, so the smuggled request that
            // follows can never be forwarded.
            let more = Bytes::from_static(b"GET /admin HTTP/1.1\r\n\r\n");
            assert_eq!(proxy.push(FlowSide::Initiator, &more), 0);
            println!("         connection is closed to further bytes ✓");
        }
        None => unreachable!("this framing is ambiguous by construction"),
    }
}

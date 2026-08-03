//! Let flowscope drive the HTTP/2 bytes: register `Http2Session` on
//! the typed `Driver` and drain per-stream events from a slot.
//!
//! `Http2Parser` (see `http2_streams`) is sans-IO — you hold the
//! socket and feed it. This is the other half: the driver owns
//! reassembly and flow lifecycle, and hands the parser its bytes, the
//! same way HTTP/1 registers `HttpProxySession`.
//!
//! Two things worth watching:
//!
//! 1. **The routing key is the stream, not the side.** Every message
//!    carries the `FlowSide` its bytes arrived on, but h2 multiplexes
//!    — one connection, many concurrent streams — so what identifies
//!    a request is the `stream_id` on the event itself.
//! 2. **Joining late is not an error.** `Http2Session::new()`
//!    tolerates a missing connection preface, because a driver picks
//!    flows up mid-connection all the time: capture started late, a
//!    heuristic slot pinned after probing, an h2c upgrade whose
//!    preface something else consumed. A strict parser reports those
//!    as a protocol violation when nothing is wrong.
//!
//! Usage:
//!     cargo run --features http2,extractors,tracker,reassembler,session \
//!         --example http2_driver

use bytes::Bytes;
use flowscope::driver::{Driver, Event};
use flowscope::extract::FiveTuple;
use flowscope::http2::{HpackEncoder, Http2Event, Http2Session, PREFACE, write_headers};
use flowscope::{PacketView, Timestamp};

/// Build an Ethernet/IPv4/TCP frame carrying `payload`.
///
/// Hand-rolled rather than pulled from `test_helpers`, so the example
/// builds with the features in its own usage line.
fn tcp_packet(src_port: u16, dst_port: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
    let (src_ip, dst_ip) = if src_port == 8080 {
        ([10, 0, 0, 2], [10, 0, 0, 1])
    } else {
        ([10, 0, 0, 1], [10, 0, 0, 2])
    };
    let mut v = Vec::new();
    // Ethernet II, IPv4.
    v.extend_from_slice(&[0xff; 6]);
    v.extend_from_slice(&[0xaa; 6]);
    v.extend_from_slice(&[0x08, 0x00]);
    // IPv4 header, 20 bytes, no options.
    let total_len = (20 + 20 + payload.len()) as u16;
    v.extend_from_slice(&[0x45, 0x00]);
    v.extend_from_slice(&total_len.to_be_bytes());
    v.extend_from_slice(&[0, 0, 0x40, 0x00, 64, 6, 0, 0]);
    v.extend_from_slice(&src_ip);
    v.extend_from_slice(&dst_ip);
    // TCP header, 20 bytes: PSH+ACK, no options.
    v.extend_from_slice(&src_port.to_be_bytes());
    v.extend_from_slice(&dst_port.to_be_bytes());
    v.extend_from_slice(&seq.to_be_bytes());
    v.extend_from_slice(&[0, 0, 0, 0]); // ack
    v.extend_from_slice(&[0x50, 0x18]); // offset 5, PSH+ACK
    v.extend_from_slice(&[0xff, 0xff, 0, 0, 0, 0]); // window, cksum, urg
    v.extend_from_slice(payload);
    v
}

fn field(name: &str, value: &str) -> (Bytes, Bytes) {
    (
        Bytes::copy_from_slice(name.as_bytes()),
        Bytes::copy_from_slice(value.as_bytes()),
    )
}

fn main() {
    let (mut driver, mut slot) = {
        let mut b = Driver::builder(FiveTuple::bidirectional());
        // Exactly the shape HTTP/1 uses with `HttpProxySession`.
        let slot = b.session_on_ports(Http2Session::new(), [8080]);
        (b.build(), slot)
    };

    // Synthesise a connection. h2 is normally inside TLS, so a real
    // capture would be opaque — an inline proxy that terminates TLS
    // is where these bytes come from.
    let mut enc = HpackEncoder::new();
    let mut client = PREFACE.to_vec();
    client.extend_from_slice(&[0, 0, 0, 0x4, 0, 0, 0, 0, 0]); // empty SETTINGS

    for (i, path) in ["/v1/orders", "/v1/customers", "/healthz"]
        .iter()
        .enumerate()
    {
        let block = enc
            .encode(&[
                field(":method", "GET"),
                field(":scheme", "https"),
                field(":authority", "api.example"),
                field(":path", path),
            ])
            .expect("encodable");
        client.extend(write_headers(i as u32 * 2 + 1, &block, true, 16_384).unwrap());
    }

    let mut events = Vec::new();
    driver.track_into(
        PacketView::new(
            &tcp_packet(44000, 8080, 1000, &client),
            Timestamp::new(1, 0),
        ),
        &mut events,
    );

    // Server responses, on the responder side of the same flow.
    let mut server_enc = HpackEncoder::new();
    let mut server = vec![0, 0, 0, 0x4, 0, 0, 0, 0, 0];
    for (i, status) in ["200", "200", "503"].iter().enumerate() {
        let block = server_enc
            .encode(&[
                field(":status", status),
                field("content-type", "application/json"),
            ])
            .expect("encodable");
        server.extend(write_headers(i as u32 * 2 + 1, &block, true, 16_384).unwrap());
    }
    driver.track_into(
        PacketView::new(
            &tcp_packet(8080, 44000, 5000, &server),
            Timestamp::new(2, 0),
        ),
        &mut events,
    );

    // ── drain the slot ───────────────────────────────────────────
    let mut msgs = Vec::new();
    slot.drain(&mut msgs);

    println!("== per-stream events off the slot ==\n");
    for m in &msgs {
        match &m.message {
            Http2Event::Head(h) => {
                let what = match (h.method(), h.status()) {
                    (Some(method), _) => format!("{method} {}", h.path().unwrap_or("?")),
                    (None, Some(status)) => format!("status {status}"),
                    _ => "?".to_string(),
                };
                println!("  stream {:>2}  {:?}  {what}", h.stream_id, m.side);
            }
            Http2Event::End { stream_id, dir } => {
                println!("  stream {stream_id:>2}  {dir:?}  end");
            }
            _ => {}
        }
    }

    println!(
        "\nNote the `side` column: it says which peer sent the bytes, not\n\
         which request they belong to. Both directions of stream 1 share\n\
         a TCP flow with every other stream, so `stream_id` is the key\n\
         you route and correlate on."
    );

    // ── joining a connection already in progress ─────────────────
    let (mut late, mut late_slot) = {
        let mut b = Driver::builder(FiveTuple::bidirectional());
        let slot = b.session_on_ports(Http2Session::new(), [8080]);
        (b.build(), slot)
    };
    let mut mid_stream = HpackEncoder::new();
    let block = mid_stream
        .encode(&[
            field(":method", "POST"),
            field(":scheme", "https"),
            field(":authority", "late.example"),
            field(":path", "/joined-late"),
        ])
        .expect("encodable");
    // Straight into a HEADERS frame: no preface, no SETTINGS.
    let mut late_events = Vec::new();
    late.track_into(
        PacketView::new(
            &tcp_packet(
                44001,
                8080,
                1000,
                &write_headers(9, &block, true, 16_384).unwrap(),
            ),
            Timestamp::new(3, 0),
        ),
        &mut late_events,
    );

    let mut late_msgs = Vec::new();
    late_slot.drain(&mut late_msgs);
    let routed = late_msgs.iter().find_map(|m| match &m.message {
        Http2Event::Head(h) => h.authority(),
        _ => None,
    });
    let torn_down = late_events
        .iter()
        .any(|e| matches!(e, Event::ParserClosed { .. }));

    println!("\n== a flow picked up mid-connection ==\n");
    println!("  routed to: {}", routed.unwrap_or("(nothing)"));
    println!("  parser torn down: {torn_down}");
    println!(
        "\n  The preface is long gone by the time this flow was seen.\n\
         `Http2Parser::new()` would refuse it as BadPreface — right when\n\
         you own the socket and know the connection started at byte\n\
         zero, wrong when a driver hands you whatever it found. That is\n\
         the one behavioural difference between the two constructors.\n\
         It tolerates a *missing* preface; it does not resynchronise, so\n\
         bytes that are not frame-aligned still fail."
    );
}

//! Print SNI / ALPN / cipher list for every TLS ClientHello in a
//! pcap. Uses the `TlsParser` typed-stream API on the plan-121
//! typed [`Driver`].
//!
//! Usage:
//!     cargo run --features tls,pcap --example tls_observer -- trace.pcap

use std::env;

use flowscope::{
    driver::{Driver, Event, SlotMessage},
    extract::{FiveTuple, FiveTupleKey},
    pcap::PcapFlowSource,
    tls::{TlsMessage, TlsParser},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args()
        .nth(1)
        .ok_or("usage: tls_observer <trace.pcap>")?;

    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut tls_slot = builder.session_on_ports(TlsParser::default(), [443, 8443]);
    let mut driver = builder.build();

    let mut client_hellos = 0u64;
    let mut server_hellos = 0u64;

    let mut events: Vec<Event<FiveTupleKey>> = Vec::new();
    let mut msgs: Vec<SlotMessage<TlsMessage, FiveTupleKey>> = Vec::new();

    for view in PcapFlowSource::open(&path)?.views() {
        let view = view?;
        events.clear();
        driver.track_into(&view, &mut events);
        msgs.clear();
        tls_slot.drain(&mut msgs);

        for m in &msgs {
            match &m.message {
                TlsMessage::ClientHello(h) => {
                    client_hellos += 1;
                    let sni = h.sni.as_deref().unwrap_or("(no SNI)");
                    let alpn = if h.alpn.is_empty() {
                        "(no ALPN)".to_string()
                    } else {
                        h.alpn.join(",")
                    };
                    println!(
                        "→ ClientHello sni={sni:?} alpn={alpn} ciphers={n} ext_count={ec}",
                        n = h.cipher_suites.len(),
                        ec = h.extension_types.len()
                    );
                }
                TlsMessage::ServerHello(h) => {
                    server_hellos += 1;
                    println!(
                        "← ServerHello cipher=0x{c:04x} alpn={alpn:?}",
                        c = h.cipher_suite,
                        alpn = h.alpn
                    );
                }
                _ => {}
            }
        }
    }

    events.clear();
    driver.finish_into(&mut events);
    msgs.clear();
    tls_slot.drain(&mut msgs);
    for m in &msgs {
        match &m.message {
            TlsMessage::ClientHello(_) => client_hellos += 1,
            TlsMessage::ServerHello(_) => server_hellos += 1,
            _ => {}
        }
    }

    eprintln!("\n--- summary: {client_hellos} ClientHellos, {server_hellos} ServerHellos");
    Ok(())
}

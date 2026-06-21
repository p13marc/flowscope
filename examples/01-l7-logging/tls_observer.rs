//! Print SNI / ALPN / cipher list for every TLS ClientHello in a
//! pcap.
//!
//! Demonstrates the high-level offline pipeline:
//! [`PcapFlowSource::sessions`] composes pcap source +
//! extractor + per-flow `TlsParser` into a single iterator of
//! [`SessionEvent`]s. No manual `Driver::builder` / `SlotHandle`
//! / `clear+drain` per-packet plumbing.
//!
//! Usage:
//!     cargo run --features tls,pcap --example tls_observer -- trace.pcap

use std::env;

use flowscope::{
    SessionEvent,
    extract::FiveTuple,
    pcap::PcapFlowSource,
    tls::{TlsMessage, TlsParser},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args()
        .nth(1)
        .ok_or("usage: tls_observer <trace.pcap>")?;

    let mut client_hellos = 0u64;
    let mut server_hellos = 0u64;

    for evt in
        PcapFlowSource::open(&path)?.sessions(FiveTuple::bidirectional(), TlsParser::default())
    {
        let SessionEvent::Application { message, .. } = evt? else {
            continue;
        };
        match message {
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

    eprintln!("\n--- summary: {client_hellos} ClientHellos, {server_hellos} ServerHellos");
    Ok(())
}

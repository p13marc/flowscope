//! Print SNI / ALPN / cipher list for every TLS ClientHello in a
//! pcap. Uses the `TlsParser` typed-stream API.
//!
//! Usage:
//!     cargo run --features tls,pcap --example tls_observer -- trace.pcap

use std::env;

use flowscope::extract::FiveTuple;
use flowscope::pcap::PcapFlowSource;
use flowscope::tls::{TlsMessage, TlsParser};
use flowscope::{FlowSessionDriver, SessionEvent};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args()
        .nth(1)
        .ok_or("usage: tls_observer <trace.pcap>")?;

    let mut driver = FlowSessionDriver::new(FiveTuple::bidirectional(), TlsParser::default());

    let mut client_hellos = 0u64;
    let mut server_hellos = 0u64;

    for view in PcapFlowSource::open(&path)?.views() {
        let view = view?;
        for ev in driver.track(&view) {
            if let SessionEvent::Application { message, .. } = ev {
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
        }
    }

    eprintln!("\n--- summary: {client_hellos} ClientHellos, {server_hellos} ServerHellos");
    Ok(())
}

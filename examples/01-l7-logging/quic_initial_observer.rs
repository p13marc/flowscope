//! Print SNI / ALPN for every QUIC Initial packet in a pcap.
//!
//! QUIC's first packet (Initial) is encrypted with keys derived
//! deterministically from the destination Connection ID + a
//! per-version "Initial Salt" (RFC 9001 §5.2). Any passive
//! observer can recover the keys and read the ClientHello.
//!
//! For HTTP/3 + DNS-over-QUIC, the QUIC Initial ClientHello is
//! the **only** L7 visibility a passive collector has — the
//! equivalent of TLS 1.3 visibility over TCP/443.
//!
//! Usage:
//!     cargo run --features quic,pcap --example quic_initial_observer -- trace.pcap

use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args()
        .nth(1)
        .ok_or("usage: quic_initial_observer <trace.pcap>")?;

    let mut initials = 0u64;
    let mut with_sni = 0u64;
    let mut total_alpn = 0u64;

    for (key, msg) in flowscope::quic::initials_from_pcap(&path)? {
        initials += 1;
        let sni = msg.sni.as_deref();
        let alpn = msg.alpn.join(",");
        let alpn_disp = if alpn.is_empty() { "-" } else { alpn.as_str() };
        let sni_disp = sni.unwrap_or("(no SNI)");
        let token_marker = if msg.token_present { " (retry)" } else { "" };
        println!(
            "{}:{} → {}:{}  {} sni={sni_disp:?} alpn={alpn_disp}{token_marker}",
            key.a.ip(),
            key.a.port(),
            key.b.ip(),
            key.b.port(),
            msg.version,
        );
        if sni.is_some() {
            with_sni += 1;
        }
        total_alpn += msg.alpn.len() as u64;
    }

    eprintln!(
        "\nDone — {initials} Initial packet(s), {with_sni} with SNI, \
         {total_alpn} ALPN entries total."
    );
    Ok(())
}

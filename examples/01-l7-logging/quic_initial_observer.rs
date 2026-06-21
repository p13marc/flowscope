//! Print SNI / ALPN for every QUIC Initial packet in a pcap.
//!
//! QUIC's first packet (Initial) is encrypted with keys derived
//! deterministically from the destination Connection ID + a
//! per-version "Initial Salt" (RFC 9001 §5.2). Any passive
//! observer can recover the keys and read the ClientHello.
//!
//! For HTTP/3 + DNS-over-QUIC, the QUIC Initial ClientHello is
//! the **only** L7 visibility a passive collector has — the
//! equivalent of TLS 1.3 visibility over TCP/443. This example
//! demonstrates the full pipeline:
//!
//! ```text
//! UDP datagram → parse_initial → derive Initial keys →
//! AEAD decrypt → CRYPTO frames → reassemble → ClientHello →
//! SNI + ALPN
//! ```
//!
//! Usage:
//!     cargo run --features quic,pcap --example quic_initial_observer -- trace.pcap

use std::env;

use flowscope::pcap::PcapFlowSource;
use flowscope::quic;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args()
        .nth(1)
        .ok_or("usage: quic_initial_observer <trace.pcap>")?;

    let mut initials = 0u64;
    let mut with_sni = 0u64;
    let mut total_alpn = 0u64;

    // pcap source replays every datagram in order. We're a
    // simple consumer: for each frame, try to find a UDP
    // payload and feed it through `quic::parse`. For a real
    // flow-aware consumer use the typed Driver with
    // `datagram_on_ports(QuicUdpParser, [443])`.
    for view in PcapFlowSource::open(&path)?.views() {
        let view = view?;
        let Some(udp_payload) = udp_payload(&view.frame) else {
            continue;
        };
        let Some(msg) = quic::parse(udp_payload) else {
            continue;
        };
        initials += 1;
        let sni = msg.sni.as_deref();
        let alpn = msg.alpn.join(",");
        let alpn_disp = if alpn.is_empty() { "-" } else { alpn.as_str() };
        let sni_disp = sni.unwrap_or("(no SNI)");
        let token_marker = if msg.token_present { " (retry)" } else { "" };
        println!(
            "→ QUIC Initial v=0x{:08x} dcid={} sni={sni_disp:?} alpn={alpn_disp}{token_marker}",
            msg.version,
            hex_short(&msg.dcid)
        );
        if sni.is_some() {
            with_sni += 1;
        }
        total_alpn += msg.alpn.len() as u64;
    }

    println!(
        "\nDone — {initials} Initial packet(s), {with_sni} with SNI, \
         {total_alpn} ALPN entries total."
    );
    Ok(())
}

/// Crude IPv4/IPv6 UDP payload extractor — enough for an
/// example. Real consumers should use the typed driver +
/// `QuicUdpParser`.
fn udp_payload(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < 14 + 20 + 8 {
        return None;
    }
    // Ethernet header is 14 bytes; skip past it.
    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    let l3 = &frame[14..];
    match ethertype {
        0x0800 => {
            // IPv4: bottom 4 bits of byte 0 = IHL in 32-bit words.
            let ihl = (l3[0] & 0x0F) as usize * 4;
            if l3.len() < ihl + 8 || l3[9] != 17 {
                return None;
            }
            let udp = &l3[ihl..];
            Some(&udp[8..])
        }
        0x86DD => {
            // IPv6: fixed 40-byte header; next-header at byte 6.
            if l3.len() < 40 + 8 || l3[6] != 17 {
                return None;
            }
            let udp = &l3[40..];
            Some(&udp[8..])
        }
        _ => None,
    }
}

fn hex_short(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b.iter().take(8) {
        use std::fmt::Write;
        write!(&mut s, "{byte:02x}").unwrap();
    }
    if b.len() > 8 {
        s.push('…');
    }
    s
}

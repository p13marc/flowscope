//! Unified offline replay: flow lifecycle **and** typed L7 messages
//! from one loop (issue #111).
//!
//! `session_pulses::<P>` interleaves `Started` / `Message` / `Ended`
//! into a single ordered iterator — no separate slot drain, no
//! trailing-drain footgun. Compare with `tls_observer.rs`
//! (messages only) and the `Driver::run_pcap` lifecycle-only path.
//!
//! ```text
//! cargo run --example pcap_pulses --features tls,pcap -- trace.pcap
//! ```

use flowscope::pcap::{Pulse, session_pulses};
use flowscope::tls::TlsParser;

fn main() -> flowscope::Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    let (mut flows, mut messages) = (0u64, 0u64);

    for pulse in session_pulses::<TlsParser>(&path)? {
        match pulse {
            Pulse::Started { key, ts } => {
                flows += 1;
                println!("[{ts:?}] flow up   {key:?}");
            }
            Pulse::Message(m) => {
                messages += 1;
                // One typed TLS message (ClientHello / ServerHello /
                // Alert / …) with its side + timestamp.
                println!("    [{:?}] {:?}: {:?}", m.ts, m.side, m.message);
            }
            Pulse::Ended {
                key, reason, stats, ..
            } => {
                println!(
                    "[?] flow down {key:?} ({reason:?}, {} pkts)",
                    stats.total_packets()
                );
            }
            _ => {}
        }
    }

    println!("\n{flows} flow(s), {messages} TLS message(s) — all in one pass");
    Ok(())
}

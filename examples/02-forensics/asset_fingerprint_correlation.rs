//! Correlate an L7 fingerprint into the MAC-keyed asset inventory
//! (issue #137).
//!
//! The asset `Inventory` is keyed by MAC and stitches every source
//! that mentions a host into one record. Before 0.22 the L2/L3
//! discovery parsers fed it, but TLS/SSH/p0f fingerprints — the
//! most *discriminating* device signal — never reached it. Now
//! `Asset::from_tls_handshake` / `from_ssh_kexinit` /
//! `from_tcp_fingerprint` wire them in, keyed by the frame's source
//! MAC, so an analyst can pivot host ↔ JA3/JA4/HASSH/p0f.
//!
//! This example is self-contained (no pcap needed): it observes a
//! TLS handshake and a hostname for the same MAC and shows them
//! merged into one record with a derived role + confidence.
//!
//! Usage:
//!     cargo run --features "asset,tls,tls-fingerprints" \
//!         --example asset_fingerprint_correlation

use flowscope::tls::TlsHandshake;
use flowscope::{Asset, Inventory, MacAddr, Timestamp};

fn main() {
    let mut inv = Inventory::new(1024);
    let mac = MacAddr([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let ts = Timestamp::new(1_000, 0);

    // 1. A hostname was learned earlier (e.g. from DHCP option 12).
    let mut named = Asset::new(mac);
    named.hostname = Some("workstation-07".to_string());
    inv.absorb_at(named, ts);

    // 2. A TLS ClientHello from the same host — source MAC comes
    //    from the Ethernet frame the handshake rode in on.
    let mut hs = TlsHandshake::default();
    hs.sni = Some("login.corp.example".to_string());
    hs.ja3 = Some("771,4865-4866-4867,0-23-65281,29-23-24,0".to_string());
    hs.ja4 = Some("t13d1516h2_8daaf6152771_b186095e22b6".to_string());
    inv.absorb_at(Asset::from_tls_handshake(&hs, mac), ts);

    // 3. One correlated record — hostname AND fingerprints, keyed
    //    by MAC.
    let a = inv.get(&mac).expect("asset present");
    println!("asset  {}", a.mac);
    println!("  hostname     : {:?}", a.hostname);
    println!("  role         : {}", a.role().as_str());
    println!("  sources      : {} distinct", a.source_count());
    println!("  JA3          : {:?}", a.fingerprints.ja3);
    println!("  JA4          : {:?}", a.fingerprints.ja4);

    assert_eq!(a.hostname.as_deref(), Some("workstation-07"));
    assert!(a.fingerprints.ja3.is_some() && a.fingerprints.ja4.is_some());
}

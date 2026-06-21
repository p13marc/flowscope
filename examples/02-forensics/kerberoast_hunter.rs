//! Detect Kerberoasting attempts in a pcap.
//!
//! A TGS-REQ that lists RC4-HMAC (etype 23) in its etype list is
//! the classic downgrade signal — the attacker is asking the KDC
//! for a service ticket encrypted with a weak cipher so they can
//! crack the service account's NTLM hash offline.
//!
//! **MITRE ATT&CK:** [T1558.003](https://attack.mitre.org/techniques/T1558/003/)
//! — Steal or Forge Kerberos Tickets: Kerberoasting.
//!
//! ## Known false positives
//!
//! - Legitimate downgrade for legacy KDC compatibility (rare in
//!   modern AD ≥ 2008, but still seen with NetApp / EMC SMB
//!   appliances on the wire).
//! - Penetration-testing exercises (Rubeus / Impacket / SharpHound
//!   trip this on purpose).
//! - Mis-configured services with `msDS-SupportedEncryptionTypes`
//!   set to RC4 only.
//!
//! ## Usage
//!
//! ```bash
//! cargo run --features kerberos,pcap --example kerberoast_hunter -- trace.pcap
//! ```
//!
//! Closes #39.

use flowscope::kerberos::{KerberosMessageKind, messages_from_pcap};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: kerberoast_hunter <trace.pcap>")?;

    let mut hits = 0u64;
    let mut total_tgs_req = 0u64;

    for (key, msg) in messages_from_pcap(&path)? {
        if matches!(msg.kind, KerberosMessageKind::TgsReq) {
            total_tgs_req += 1;
        }
        if msg.kerberoast_suspect {
            hits += 1;
            let etypes = msg
                .etypes
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join(",");
            println!(
                "[kerberoast]  {}:{} → {}:{}  realm={} cname={:?} sname={:?} etypes=[{etypes}]",
                key.a.ip(),
                key.a.port(),
                key.b.ip(),
                key.b.port(),
                msg.realm,
                msg.cname.as_deref().unwrap_or("?"),
                msg.sname.as_deref().unwrap_or("?"),
            );
        }
    }

    eprintln!(
        "\nFound {hits} suspect TGS-REQ(s) with RC4-HMAC downgrade \
         out of {total_tgs_req} TGS-REQ message(s) total."
    );
    Ok(())
}

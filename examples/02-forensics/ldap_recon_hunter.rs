//! Detect Active Directory reconnaissance via LDAP `servicePrincipalName`
//! queries (the BloodHound / GetUserSPNs enumeration pattern).
//!
//! An LDAP SearchRequest whose attribute list includes
//! `servicePrincipalName` is the prerequisite to Kerberoasting
//! (T1558.003) — the attacker enumerates SPNs across the domain
//! to find service accounts vulnerable to ticket cracking.
//!
//! **MITRE ATT&CK:**
//! - [T1087.002](https://attack.mitre.org/techniques/T1087/002/)
//!   — Account Discovery: Domain Account.
//! - Pairs with [T1558.003](https://attack.mitre.org/techniques/T1558/003/)
//!   — Kerberoasting (see `kerberoast_hunter.rs`).
//!
//! Also surfaces Simple LDAP binds with `creds_present == true`
//! — these carry the cleartext password in the bind packet, which
//! is itself a misconfiguration signal (Simple binds should be
//! tunnelled inside LDAPS).
//!
//! ## Known false positives
//!
//! - Monitoring tools (PRTG, Tanium, Quest Spotlight, Lansweeper)
//!   routinely enumerate SPNs for inventory.
//! - Legitimate AD audit jobs (`netdom`, `adexport`, Microsoft
//!   Endpoint Manager).
//! - Active Directory replication itself uses SPN lookups.
//!
//! ## Usage
//!
//! ```bash
//! cargo run --features ldap,pcap --example ldap_recon_hunter -- trace.pcap
//! ```
//!
//! Closes #40.

use flowscope::ldap::{LdapAuthKind, LdapOperation, LdapParser};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: ldap_recon_hunter <trace.pcap>")?;

    let mut spn_queries = 0u64;
    let mut cleartext_binds = 0u64;
    let mut total_searches = 0u64;
    let mut total_binds = 0u64;

    for (key, msg) in flowscope::pcap::session_messages::<LdapParser>(&path)? {
        match msg.operation {
            LdapOperation::SearchRequest => {
                total_searches += 1;
                if msg.search_attributes_spn_query {
                    spn_queries += 1;
                    println!(
                        "[spn-query]   {}:{} → {}:{}  base={:?} attrs={:?}",
                        key.a.ip(),
                        key.a.port(),
                        key.b.ip(),
                        key.b.port(),
                        msg.search_base.as_deref().unwrap_or("?"),
                        msg.search_attributes,
                    );
                }
            }
            LdapOperation::BindRequest => {
                total_binds += 1;
                if let Some(LdapAuthKind::Simple {
                    creds_present: true,
                }) = &msg.bind_auth_kind
                {
                    cleartext_binds += 1;
                    println!(
                        "[simple-bind] {}:{} → {}:{}  dn={:?}  (cleartext password — wrap in LDAPS)",
                        key.a.ip(),
                        key.a.port(),
                        key.b.ip(),
                        key.b.port(),
                        msg.bind_name.as_deref().unwrap_or("?"),
                    );
                }
            }
            _ => {}
        }
    }

    eprintln!(
        "\n--- summary --- \
         \n  {spn_queries} SPN-query SearchRequest(s) out of {total_searches} total searches \
         \n  {cleartext_binds} Simple bind(s) with cleartext credentials out of {total_binds} total binds"
    );
    Ok(())
}

//! Surface SMB2/3 lateral-movement signals from a pcap.
//!
//! The SMB2 parser surfaces a tight set of high-signal events
//! historically abused for Windows lateral movement
//! (MITRE T1021.002 — Remote Services: SMB/Windows Admin
//! Shares):
//!
//! - **Admin-share TREE_CONNECT** — `C$ / ADMIN$ / IPC$ /
//!   NETLOGON / SYSVOL` mounts. The PsExec / WMI-over-SMB /
//!   ransomware vector.
//! - **Named-pipe CREATE** on `svcctl` (service creation —
//!   T1569.002) / `lsarpc` + `samr` (credential dump —
//!   T1003) / `spoolss` (PrintNightmare — CVE-2021-34527) /
//!   `drsuapi` (DCSync — T1003.006).
//! - **NTLM SESSION_SETUP identity** — domain / user /
//!   workstation tuple for pass-the-hash attribution
//!   (T1550.002).
//! - **DCE-RPC BIND** UUIDs for the interface(s) the client
//!   wants to talk to (the operation layer on top of the
//!   pipe).
//!
//! Usage:
//!     cargo run --features smb,pcap --example smb_lateral_movement -- trace.pcap

use std::env;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args()
        .nth(1)
        .ok_or("usage: smb_lateral_movement <trace.pcap>")?;

    let mut admin_share_hits = 0u64;
    let mut admin_pipe_hits = 0u64;
    let mut ntlm_authens = 0u64;
    let mut dcerpc_binds = 0u64;

    for (key, msg) in flowscope::smb::messages_from_pcap(&path)? {
        let src = format!("{}:{}", key.a.ip(), key.a.port());
        let dst = format!("{}:{}", key.b.ip(), key.b.port());

        if msg.tree_connect_is_admin_share {
            admin_share_hits += 1;
            println!(
                "[admin-share]  {src:>15} → {dst:<15}  {:?}",
                msg.tree_connect_path.as_deref().unwrap_or("(none)"),
            );
        }
        if msg.create_is_admin_named_pipe {
            admin_pipe_hits += 1;
            println!(
                "[admin-pipe]   {src:>15} → {dst:<15}  pipe={:?}",
                msg.create_path.as_deref().unwrap_or("(none)"),
            );
        }
        if let Some(auth) = &msg.ntlm_auth {
            ntlm_authens += 1;
            println!(
                "[ntlm-auth]    {src:>15} → {dst:<15}  domain={:?} user={:?} workstation={:?}",
                auth.domain.as_deref().unwrap_or(""),
                auth.username.as_deref().unwrap_or(""),
                auth.workstation.as_deref().unwrap_or(""),
            );
        }
        if !msg.dcerpc_bind_uuids.is_empty() {
            dcerpc_binds += msg.dcerpc_bind_uuids.len() as u64;
            let rendered: Vec<String> = msg
                .dcerpc_bind_uuids
                .iter()
                .map(|u| match u.well_known_name() {
                    Some(name) => format!("{name} ({u})"),
                    None => u.to_string(),
                })
                .collect();
            println!(
                "[dcerpc-bind]  {src:>15} → {dst:<15}  uuids=[{}]",
                rendered.join(", "),
            );
        }
    }

    eprintln!(
        "\nSummary — {admin_share_hits} admin-share TREE_CONNECT, \
         {admin_pipe_hits} admin-pipe CREATE, \
         {ntlm_authens} NTLM AUTHENTICATE, \
         {dcerpc_binds} DCE-RPC BIND interface(s)."
    );
    Ok(())
}

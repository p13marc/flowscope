//! SMB (Server Message Block) v1 / v2 / v3 passive metadata
//! parser — TCP/445.
//!
//! Gated by the `smb` Cargo feature. Hand-rolled (no mature
//! rusticata crate exists; Suricata has its own in
//! `rust/src/smb/` but isn't published as a library).
//!
//! ## M1 scope (this release)
//!
//! - **Dialect detection** — SMB1 vs SMB2/3 protocol marker
//!   (`0xFF SMB` vs `0xFE SMB` vs `0xFD SMB` for encrypted
//!   SMB3). The `0xFD` encrypted-transform marker means the
//!   payload is AES-CCM/GCM ciphertext; we surface the
//!   encryption flag and skip the inner decode.
//! - **Command decode** — the SMB2 command nibble (NEGOTIATE
//!   / SESSION_SETUP / TREE_CONNECT / CREATE / READ / WRITE
//!   / IOCTL / ...) mapped to [`SmbCommand`]. For SMB1, only
//!   the few commands we still see in mixed environments
//!   are named; the rest fall to `Other(u8)`.
//! - **Tree-connect target path** — for SMB2
//!   TREE_CONNECT messages, the requested share path
//!   (UTF-16LE on the wire, decoded to UTF-8). The
//!   `C$ / ADMIN$ / IPC$ / NETLOGON / SYSVOL` admin shares
//!   are the **single highest lateral-movement signal**
//!   (MITRE T1021.002). A `tree_connect_is_admin_share`
//!   convenience boolean is set.
//! - **SMB1 downgrade signal** — `dialect == V1` after a
//!   SMB2 negotiation is suspicious by itself (legacy /
//!   downgrade attack indicator).
//!
//! ## M2 surface (shipped — file ops)
//!
//! - **CREATE filename** → `create_path` (UTF-16LE → UTF-8).
//!   `create_is_admin_named_pipe` boolean for well-known
//!   abused pipes (`svcctl` / `winreg` / `lsarpc` / `samr`
//!   / `netlogon` / `spoolss` / `atsvc` / `eventlog` /
//!   `ntsvcs` / `wkssvc` / `srvsvc` / `drsuapi`).
//! - **READ / WRITE offset + length** → `read_offset` /
//!   `read_length` / `write_offset` / `write_length`.
//!   Large reads = exfil signal; mass writes = ransomware
//!   signal.
//!
//! ## M3 surface (shipped — auth + RPC binds)
//!
//! - **NTLMSSP AUTHENTICATE** in SESSION_SETUP →
//!   [`NtlmAuth`] with `domain` / `username` /
//!   `workstation`. Scans the security buffer for the
//!   `NTLMSSP\0` magic to bypass SPNEGO/GSS-API wrapping
//!   (Wireshark-style).
//! - **DCE-RPC bind UUIDs** in WRITE bodies →
//!   `dcerpc_bind_uuids: Vec<String>`. One entry per
//!   offered abstract-syntax (the interface the client is
//!   binding to). Per the issue body: "note DCE-RPC binds,
//!   full DCE-RPC parsing is a follow-up".
//!
//! ## Out of scope
//!
//! - **NTLM Type 1 / Type 2 decode** — NEGOTIATE +
//!   CHALLENGE messages from the same SPNEGO exchange.
//!   Only AUTHENTICATE (Type 3) carries the identity
//!   tuple worth surfacing.
//! - **Full DCE-RPC PDU decoding** beyond BIND — request /
//!   response / fragment reassembly. The Suricata
//!   DCERPC-over-SMB CVE history is the load-bearing
//!   reason this stays opt-out.
//! - **Compound / chained** request decode — we read the
//!   first message in each NetBIOS PDU; chained
//!   `NextCommand`-offset traversal is deferred.
//! - **SMB3 encrypted-payload decoding** — the encryption
//!   keys derive from session-setup negotiation we don't
//!   have access to as a passive observer. The marker is
//!   surfaced; the payload stays opaque.
//!
//! ## Security
//!
//! SMB is adversarial-input-rich; the Suricata DCERPC-over-
//! SMB CVE history (CVE-2026-22258 and predecessors) warns
//! that aggressive decode is a CVE magnet. M1 decodes the
//! 64-byte SMB2 header and the SMB2 TREE_CONNECT path; both
//! are bounded by the NetBIOS message length envelope. All
//! buffer reads go through `.get()` so no panic on truncated
//! input.
//!
//! Issue #12 (0.18).

mod parser;
#[cfg(feature = "pcap")]
mod pcap_iter;
mod session;
mod types;

pub use parser::{ParseError, parse, parser_kind};
#[cfg(feature = "pcap")]
#[allow(deprecated)]
pub use pcap_iter::messages_from_pcap;
pub use session::{SMB_PORT, SmbParser};
pub use types::{DceRpcInterfaceUuid, NtlmAuth, SmbCommand, SmbDialect, SmbMessage};

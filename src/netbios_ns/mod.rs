//! NetBIOS Name Service (NBNS / NBT-NS) — RFC 1002 §4.2 over
//! UDP/137.
//!
//! Gated by the `netbios-ns` Cargo feature. NBNS is the
//! Windows-side counterpart to mDNS / SSDP for the broadcast
//! name-service asset-discovery story. The wire format is
//! "DNS-shaped" — same 12-byte header, same QDCOUNT/ANCOUNT,
//! similar RR layout — but with NetBIOS-specific opcodes and
//! a peculiar 32-byte "compressed" name encoding (16 raw
//! bytes encoded as 32 half-bytes shifted by `'A'`).
//!
//! # What this surfaces
//!
//! For each well-formed datagram, one [`NbnsMessage`]:
//!
//! - [`NbnsMessage::transaction_id`] — for query/response
//!   correlation.
//! - [`NbnsMessage::opcode`] — Query / Registration / Release
//!   / WACK / Refresh (see [`NbnsOpcode`]).
//! - [`NbnsMessage::is_response`] — derived from the QR flag.
//! - [`NbnsMessage::queried_name`] — the decoded NetBIOS name
//!   (whitespace-trimmed, suffix byte stripped). `None` when
//!   the question section was empty or the encoding was
//!   malformed.
//! - [`NbnsMessage::name_suffix`] — the suffix byte (host
//!   type — `0x00` workstation, `0x20` file server, etc.).
//! - [`NbnsMessage::answer_addresses`] — the IPv4 addresses
//!   carried in NB answer records. NBNS RR type 0x0020
//!   (`NB`) only.
//!
//! # Asset adapter
//!
//! With `asset` also on, `Asset::from_netbios_ns` contributes:
//!
//! - `mac` (caller-provided source MAC — NBNS payloads carry
//!   no L2).
//! - `hostname` (the decoded NetBIOS name).
//! - `ipv4` (every address in the answer section).
//! - `seen_via |= AssetSourceSet::NBNS`.
//!
//! # What this is NOT
//!
//! - SMB (TCP/445) parsing — separate issue (#12).
//! - LLMNR (UDP/5355) — different RFC, different name
//!   convention; ships separately if needed.
//! - Full RR-section walking — only the first NB answer is
//!   surfaced. Multi-IP responses (rare in practice) lose
//!   the second+ entries.
//!
//! Issue #14 (Tier-2 row 5 sub-piece) — completes the
//! broadcast-name-service trio alongside `mdns` (RFC 6762)
//! and `ssdp` (UPnP).

mod datagram;
mod name;
mod parser;
mod types;

pub use datagram::{NBNS_PORT, NbnsParser, PARSER_KIND};
pub use parser::parse;
pub use types::{NbnsMessage, NbnsOpcode};

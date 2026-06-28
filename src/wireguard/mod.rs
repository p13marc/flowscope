//! WireGuard passive handshake / transport detection.
//!
//! Gated by the `wireguard` Cargo feature. WireGuard is a
//! UDP-based VPN protocol (no well-known IANA port — 51820
//! is the convention). Each datagram starts with a 4-byte
//! header: `message_type(1) | reserved(3)`. The four
//! defined types (per the WireGuard whitepaper, Donenfeld
//! 2017):
//!
//! - **1 — Handshake Initiation** (148 bytes total).
//! - **2 — Handshake Response** (92 bytes).
//! - **3 — Cookie Reply** (64 bytes, anti-DoS).
//! - **4 — Transport Data** (16 + ciphertext, variable).
//!
//! # What this surfaces
//!
//! [`WireGuardMessage::kind`] — the message-type enum, and
//! for handshake messages the `sender_index` /
//! `receiver_index` u32 IDs (peer correlation). For
//! Transport Data, the `receiver_index` and the
//! `payload_length` (encrypted bytes count) are surfaced.
//!
//! Use case: passive identification of WireGuard tunneling
//! activity. The handshake messages are unmistakable by
//! their fixed length + type byte; transport datagrams can
//! be soft-matched once a peer is known. Issue #14 calls
//! this out as a rising 2025-26 evasion signal —
//! shadow-VPN / mesh-VPN setups bypass corporate DLP
//! controls, and identifying them on the wire is the only
//! safe passive detection path.
//!
//! # What this is NOT
//!
//! - Decryption — passive observer; we do not have the
//!   peer's static key.
//! - Peer-key fingerprinting beyond sender/receiver
//!   indices — the static keys are encrypted in
//!   Initiation.
//! - Strict-validation of the MAC1 / MAC2 fields — those
//!   require the responder's static public key.
//!
//! Issue #14 (rising 2025-26 evasion signal).

mod parser;
mod session;
mod types;

pub use parser::{ParseError, parse};
pub use session::{PARSER_KIND, WIREGUARD_PORT, WireGuardParser};
pub use types::{WireGuardKind, WireGuardMessage};

//! SSH handshake parser + HASSH fingerprint.
//!
//! Gated by the `ssh` feature. Parses the cleartext SSH-2
//! handshake (RFC 4253):
//!
//! 1. Version exchange ("SSH-2.0-..." banner lines).
//! 2. `SSH_MSG_KEXINIT` algorithm-negotiation packets from
//!    client and server.
//!
//! Emits a strongly-typed [`SshMessage`] per protocol event,
//! plus the [HASSH](https://github.com/salesforce/hassh) MD5
//! fingerprint (client side) and HASSHServer (server side),
//! built from the KEXINIT algorithm lists per the Salesforce
//! specification. HASSH is the SSH analogue of JA3 / JA4 for
//! TLS — same use case: client / server classification by
//! library-default algorithm preferences.
//!
//! Once both sides exchange `SSH_MSG_NEWKEYS` (msg type 21)
//! the remainder of the connection is encrypted; this parser
//! stops emitting events after that point — there's no
//! cleartext to see.
//!
//! # Scope
//!
//! - Banner exchange — `SshMessage::Banner`.
//! - KEXINIT decode — `SshMessage::KexInit` with the
//!   ten RFC 4253 §7.1 name-lists + HASSH/HASSHServer when
//!   the side is identified.
//! - NEWKEYS marker — `SshMessage::Encrypted` (parser stops
//!   advancing after).
//!
//! # Out of scope
//!
//! - Decryption (impossible passively).
//! - SSH-1 (deprecated; the parser rejects non-SSH-2 banners).
//! - DH key exchange messages, channel data, auth methods —
//!   all post-KEXINIT and most are encrypted anyway.
//!
//! Issue #7 (0.18).

// JA4SSH — FoxIO-licensed JA4+ SSH-session fingerprint. Opt-in via the
// `ja4plus` feature (issue #77).
#[cfg(feature = "ja4plus")]
mod ja4ssh;
mod parser;
#[cfg(feature = "pcap")]
mod pcap_iter;
mod session;
mod types;

#[cfg(feature = "ja4plus")]
pub use ja4ssh::{DEFAULT_PACKET_COUNT, Ja4sshAccumulator};
pub use parser::{
    compute_hassh, kexinit_message_byte, parse_kexinit_payload, version_banner_prefix,
};
#[cfg(feature = "pcap")]
pub use pcap_iter::messages_from_pcap;
pub use session::{PARSER_KIND, SshParser};
pub use types::{SshKexInit, SshMessage};

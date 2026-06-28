//! QUIC (RFC 9000) Initial-packet passive metadata parser.
//!
//! Gated by the `quic` Cargo feature. Wraps the
//! [`quic_parser`] crate (zero-copy QUIC Initial header
//! decode + RFC 9001 §5.2 Initial-secret derivation + AEAD
//! decrypt + CRYPTO-frame reassembly). The reassembled
//! ClientHello is then parsed with `tls-parser` to surface
//! SNI / ALPN.
//!
//! ## Why
//!
//! HTTP/3 + DNS-over-QUIC are encrypted-by-default but
//! QUIC's first-packet keying material is *public* — derived
//! from the destination Connection ID + a per-version
//! "Initial Salt" (RFC 9001 §5.2). Any passive observer can
//! decrypt the ClientHello, which carries SNI / ALPN / TLS
//! version / cipher list / JA3-style fingerprintable fields.
//!
//! For HTTP/3 hosts that are otherwise encrypted-end-to-end,
//! the QUIC ClientHello is the **only** L7 visibility a
//! passive collector has — same shape and value as TLS 1.3
//! ClientHello visibility over TCP/443.
//!
//! ## Surfaced fields
//!
//! [`QuicInitial`] carries:
//!
//! - `version` — QUIC version number
//!   (`0x00000001` v1 = RFC 9000, `0x6b3343cf` v2 = RFC 9369,
//!   `0xff000020+` draft versions).
//! - `dcid` / `scid` — destination / source connection IDs
//!   (max 20 bytes each per RFC 9000).
//! - `token_present` — whether a Retry token was attached
//!   to the Initial packet.
//! - `sni` — Server Name Indication from the TLS ClientHello
//!   extension.
//! - `alpn` — Application-Layer Protocol Negotiation list
//!   (`["h3", "h3-29", ...]`).
//!
//! ## Scope limits
//!
//! - **Initial packets only.** Subsequent QUIC packets
//!   (Handshake, 1-RTT) use keys derived from the TLS
//!   handshake we don't have, so they stay opaque to a
//!   passive observer. The Initial packet is enough for
//!   ClientHello visibility — that's the whole point.
//! - **No 0-RTT decryption.** 0-RTT uses keys from a prior
//!   session, also not available passively.
//! - **No QUIC connection-state tracking** — one record per
//!   Initial packet. CRYPTO-frame coalescence across multiple
//!   Initial packets (rare in practice) is OUT of M1.
//! - **JA4 / JA3** fingerprints not computed here yet — the
//!   tls-fingerprints feature works on TCP TLS today; QUIC
//!   ClientHello fingerprinting is a follow-up (the JA4 spec
//!   recognises QUIC via a transport-letter `q` instead of
//!   `t`).
//!
//! Issue #3 (0.18).

mod datagram;
mod parser;
#[cfg(feature = "pcap")]
mod pcap_iter;
mod types;

pub use datagram::{QUIC_PORT, QuicUdpParser};
pub use parser::{ParseError, parse, parser_kind};
#[cfg(feature = "pcap")]
#[allow(deprecated)]
pub use pcap_iter::initials_from_pcap;
pub use types::{QuicInitial, QuicVersion};

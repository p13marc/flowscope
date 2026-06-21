//! STUN — RFC 5389 / 8489 over UDP (typically 3478).
//!
//! Gated by the `stun` Cargo feature. Decodes STUN messages
//! per RFC 5389 (Binding requests/responses) — header +
//! TLV attributes. Useful for:
//!
//! - **WebRTC peer detection** — every WebRTC session
//!   exchanges STUN messages to discover candidate peer
//!   addresses. Identifying STUN flows surfaces P2P media
//!   sessions on a network.
//! - **NAT-type discovery** — the XOR-MAPPED-ADDRESS
//!   attribute carries the client's externally-visible
//!   (IP, port).
//! - **TURN identification** — TURN extends STUN
//!   (different message classes); the parser doesn't fully
//!   decode TURN's allocation messages but the class
//!   surfaces them as `Other(method)`.
//!
//! # What this surfaces
//!
//! For each well-formed datagram, one [`StunMessage`]:
//!
//! - `class` — Request / Indication / SuccessResponse /
//!   ErrorResponse.
//! - `method` — Binding (1) or Other(u16) for TURN /
//!   non-standard methods.
//! - `transaction_id` — 12-byte ID per RFC 5389.
//! - `mapped_address` — decoded XOR-MAPPED-ADDRESS (0x0020)
//!   when present. The non-XOR'd MAPPED-ADDRESS (0x0001)
//!   is also accepted.
//! - `username` — decoded USERNAME attribute (0x0006). May
//!   include `:`-separated realm prefix per long-term
//!   credential.
//! - `software` — decoded SOFTWARE attribute (0x8022) —
//!   vendor banner (`"Coturn-4.5.2"`, etc.).
//!
//! # Magic cookie identification
//!
//! Per RFC 5389 §6, every STUN message after the legacy
//! RFC 3489 era includes a fixed 4-byte magic cookie
//! `0x2112A442`. The parser requires it; legacy
//! RFC-3489-only messages are rejected — they're functionally
//! extinct on the modern internet.
//!
//! # What this is NOT
//!
//! - Full TURN parsing (allocation, channel binds).
//! - STUN integrity checks (MESSAGE-INTEGRITY HMAC). The
//!   parser surfaces the wire shape; downstream rules can
//!   request integrity proof separately.
//! - DTLS-wrapped STUN. Pair with `flowscope::tls` for the
//!   handshake; we don't reach into TLS records.
//!
//! Issue #14 (Tier-2 adjacent piece — pairs with WireGuard
//! for VPN/overlay visibility).

mod parser;
mod session;
mod types;

pub use parser::{MAGIC_COOKIE, parse};
pub use session::{PARSER_KIND, STUN_PORT, StunParser};
pub use types::{StunClass, StunMessage};

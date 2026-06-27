//! RDP — TCP/3389 X.224 Connection Request / Confirm parser.
//!
//! Gated by the `rdp` Cargo feature. **Metadata-only by
//! design** — we parse the TPKT + X.224 + RDP-negotiation
//! frames at the front of the session (cleartext, pre-TLS)
//! and **never** touch the RDP payload itself. FreeRDP's
//! codec history shows that RDP-payload parsing is a CVE
//! minefield; flowscope is a passive observer and stays
//! out of that surface entirely. The encrypted handshake
//! itself is just standard TLS — pair this parser with
//! `flowscope::tls` on the same flow for the
//! JA3/JA4 fingerprint of the wrapper.
//!
//! # What this surfaces
//!
//! For each parsed frame, one [`RdpMessage`]:
//!
//! - **Connection Request** (initiator → responder):
//!   - `cookie_username` — when a `Cookie: mstshash=USER\r\n`
//!     line is present in the X.224 user-data area. This is
//!     the canonical lateral-movement lead (T1021.001) — the
//!     attempted RDP target username appears in cleartext.
//!   - `routing_token` — when a Terminal Services Load
//!     Balancer routing token is present
//!     (`Cookie: msts=...\r\n`).
//!   - `requested_protocols` — bitset of the negotiation
//!     flags ([`RdpProtocols`]) — what the client is willing
//!     to upgrade to.
//! - **Connection Confirm** (responder → initiator):
//!   - `selected_protocol` — the protocol the server picked.
//!   - `negotiation_failure` — when the server rejected the
//!     negotiation, the [`RdpFailureCode`].
//!
//! # What this is NOT
//!
//! - Any post-X.224 frame parsing. Bytes after the Connection
//!   Confirm are TLS (when negotiated) or legacy MCS (when
//!   raw RDP) — neither is parsed here.
//! - FastPath input/output PDUs. Not parsed (security).
//! - License negotiation. Not parsed.
//!
//! Issue #14 (Tier-2 row 8 — top interactive lateral-
//! movement vector T1021.001).

mod parser;
mod session;
mod types;

pub use parser::{ParseError, parse_frame};
pub use session::{PARSER_KIND, RDP_PORT, RdpParser};
pub use types::{RdpFailureCode, RdpMessage, RdpProtocols};

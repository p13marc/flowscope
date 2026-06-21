//! DNP3 application-layer metadata-only parser.
//!
//! Gated by the `dnp3` Cargo feature. Passively decodes the
//! IEEE 1815-2012 wire format on TCP/20000.
//!
//! # What this surfaces
//!
//! Per data-link frame:
//!
//! - [`DnpMessage::dst_addr`] / [`DnpMessage::src_addr`] —
//!   the 16-bit link-layer addresses (LE on the wire).
//! - [`DnpMessage::link_function`] — the data link
//!   function code (`ResetLinkStates` / `UserData` /
//!   `RequestLinkStatus` / etc.).
//! - [`DnpMessage::link_dir`] — `true` for master → outstation.
//! - [`DnpMessage::link_prm`] — primary station bit.
//! - [`DnpMessage::application`] — when the first user-data
//!   block contains an application-layer frame, the
//!   parsed [`DnpApplication`].
//!
//! # What this is NOT
//!
//! - **Link-layer reassembly.** DNP3 frames CRC-protected
//!   16-byte user-data blocks. Parsing those across blocks
//!   is the part Suricata had CVE-2026-22259 in. We surface
//!   only the first block's content; deeper reassembly is
//!   left to specialised tools (or a future opt-in
//!   `dnp3-reassembly` feature with a documented attack
//!   surface caveat).
//! - **DNP3 SAv5 (Secure Authentication).** Same
//!   passive-observer-can't-see-the-secret problem as
//!   RADIUS User-Password.
//! - **DNP3 over serial (RS-232 / RS-485).** Only the TCP
//!   framing (TCP/20000) is parsed here.
//!
//! Issue #29.

mod parser;
mod session;
mod types;

pub use parser::parse;
pub use session::{DNP3_PORT, DnpParser, PARSER_KIND};
pub use types::{
    DnpAppFunctionKind, DnpApplication, DnpInternalIndications, DnpLinkFunctionKind, DnpMessage,
};

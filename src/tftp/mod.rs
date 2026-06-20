//! TFTP (Trivial File Transfer Protocol) parser.
//!
//! Gated by the `tftp` feature. RFC 1350 — UDP/69 binary
//! protocol with 5 opcodes:
//!
//! - `RRQ (1)` — read-request: client asks for a file.
//! - `WRQ (2)` — write-request: client uploads a file.
//! - `DATA (3)` — block transfer (512 B blocks).
//! - `ACK (4)` — block acknowledgement.
//! - `ERROR (5)` — error code + message.
//!
//! # Why it matters
//!
//! TFTP is the workhorse protocol for network-device config
//! distribution (Cisco / Juniper / Arista all use it),
//! PXE boot, and OT/SCADA firmware push. Passively observing
//! the cleartext RRQ / WRQ filenames gives a high-fidelity
//! signal for:
//!
//! - **Config-theft attempts** — `RRQ "running-config"`
//!   from an unexpected client is a strong T1602.002 IOC.
//! - **PXE-boot infrastructure mapping** — `RRQ "pxelinux.0"`
//!   identifies the boot infrastructure.
//! - **Firmware uploads** — `WRQ "<vendor>-<version>.bin"`
//!   tracks device update cadence.
//!
//! # Wire shape
//!
//! - [`parse`] — pure UDP payload.
//! - [`TftpParser`] — `DatagramParser` impl.
//!
//! Issue #14 (Tier-2 sub-piece).

mod datagram;
mod parser;
mod types;

pub use datagram::{PARSER_KIND, TFTP_SERVER_PORT, TftpParser};
pub use parser::parse;
pub use types::{TftpErrorCode, TftpMessage, TftpMode, TftpOpcode};

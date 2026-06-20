//! CDP (Cisco Discovery Protocol) parser.
//!
//! Gated by the `cdp` feature. CDP is the Cisco-proprietary
//! L2 discovery protocol — the LLDP sibling for environments
//! with Cisco gear. Operationally identical signal (asset /
//! rogue-switch / topology visibility), but wire-format-wise
//! completely different:
//!
//! - LLDP: EtherType 0x88cc, 7-bit-type / 9-bit-length TLVs.
//! - CDP: LLC+SNAP-encapsulated 802.3 frame, dst MAC
//!   `01:00:0c:cc:cc:cc`, OUI `00:00:0C`, PID `0x2000`,
//!   16-bit type / 16-bit length TLVs.
//!
//! # Operational signals
//!
//! - **Asset discovery on Cisco infrastructure**: Device-ID,
//!   Platform, Software-Version, Capabilities, Mgmt-Address.
//! - **Topology mapping**: Port-ID + Device-ID identifies the
//!   peer port of the directly-connected switch.
//! - **Rogue-switch detection**: a CDPDU on a port where one
//!   isn't expected (or a Device-ID that doesn't match the
//!   asset register) is a high-confidence MITM signal.
//!
//! # Wire shape
//!
//! - [`parse`] — pure CDPDU payload (after the LLC+SNAP+OUI+PID
//!   header). Use when the consumer has already validated the
//!   encapsulation.
//! - [`parse_frame`] — full Ethernet frame; validates the
//!   reserved Cisco multicast dst MAC + LLC + SNAP + OUI + PID
//!   sequence.
//! - [`CdpParser`] — stateless marker.
//!
//! Issue #25 (0.18).

mod parser;
mod types;

pub use parser::{CDP_DST_MAC, CDP_OUI, CDP_PID, CdpParser, parse, parse_frame};
pub use types::{CdpAddress, CdpCapabilities, CdpMessage};

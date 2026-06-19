//! ARP (Address Resolution Protocol) parser.
//!
//! Gated by the `arp` feature. Parses Ethernet/IPv4 ARP messages
//! (EtherType 0x0806) into a strongly-typed [`ArpMessage`] for
//! visibility and spoof-detection consumers.
//!
//! Pairs with [`crate::correlate::NeighborTable`] (always-on
//! since 0.17) for IP→MAC binding tracking and change detection.
//!
//! Issue #1 (0.17).

mod parser;
mod types;

pub use parser::{parse, parse_frame, ArpParser, ARP_ETHERTYPE};
pub use types::{ArpMessage, ArpOp};

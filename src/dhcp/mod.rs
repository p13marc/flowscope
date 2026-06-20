//! DHCP parser (RFC 2131 BOOTP + RFC 2132 options).
//!
//! Gated by the `dhcp` feature. DHCP is the #1 passive asset /
//! OS discovery signal — cleartext UDP/67-68 carrying
//! authoritative MAC ↔ IP ↔ hostname ↔ vendor bindings on
//! every lease cycle.
//!
//! # Why this is more than a Zeek port
//!
//! Zeek's base `dhcp.log` omits option 55 (Parameter Request
//! List) and gates option 60 (Vendor Class Identifier).
//! Together these two options form the Fingerbank-style DHCP
//! fingerprint — the discriminating OS/device signal. flowscope
//! surfaces both unconditionally via
//! [`DhcpMessage::fingerprint`].
//!
//! # Shape
//!
//! - [`DhcpParser`] — [`crate::session::DatagramParser`]; one
//!   datagram in, zero or one [`DhcpMessage`] out.
//! - [`parse`] — free function for callers that already hold a
//!   UDP payload and want to avoid the trait dance.
//!
//! Pairs naturally with the always-on
//! [`crate::correlate::NeighborTable<Ipv4Addr, MacAddr>`] for
//! IP↔MAC binding tracking.
//!
//! Issue #11 (0.18).

mod datagram;
mod parser;
mod types;

pub use datagram::DhcpParser;
pub use parser::parse;
pub use types::{DhcpMessage, DhcpMessageType, DhcpOp};

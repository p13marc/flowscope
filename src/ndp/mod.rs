//! IPv6 NDP (Neighbor Discovery Protocol) parser. RFC 4861.
//!
//! Gated by the `ndp` feature. Parses ICMPv6 Type 135 (Neighbor
//! Solicitation) and Type 136 (Neighbor Advertisement) into a
//! strongly-typed [`NdpMessage`] for visibility and SLAAC-
//! poisoning / NDP-spoof detection consumers.
//!
//! NDP is the IPv6 sibling of ARP. It pairs with the always-on
//! [`crate::correlate::NeighborTable`] — the same machinery used
//! for ARP/IPv4 also tracks `NeighborTable<Ipv6Addr, MacAddr>`
//! out of the box.
//!
//! ICMPv6 types 133 (Router Solicitation), 134 (Router
//! Advertisement), and 137 (Redirect) are also NDP messages but
//! aren't decoded here — the operationally-interesting
//! correlation surface is the NS / NA cache binding. Router
//! Advertisement parsing belongs in a separate feature when
//! demand surfaces.
//!
//! Issue #6 (0.18).

mod parser;
mod types;

pub use parser::{NdpParser, ParseError, parse, parse_icmpv6};
pub use types::{NdpKind, NdpMessage};

//! mDNS — Multicast DNS (RFC 6762) parser + service-discovery
//! helpers.
//!
//! Gated by the `mdns` feature. mDNS is wire-format-identical
//! to DNS — same header, same record format — so this module
//! is a thin wrapper around [`crate::dns::DnsUdpParser`] that
//! adds:
//!
//! - mDNS-specific port + multicast IP constants
//!   ([`MDNS_PORT`], [`MDNS_MULTICAST_V4`],
//!   [`MDNS_MULTICAST_V6`]).
//! - A [`MdnsParser`] newtype with the same shape as
//!   `DnsUdpParser` — present mostly so consumers wiring up
//!   dispatch can name the parser as `mdns` for metric
//!   slugs and log filtering.
//! - [`extract_services`] — walks the PTR records in a
//!   response and decodes the RFC 6763 DNS-SD instance-
//!   naming convention `<instance>._<service>._<proto>.local`
//!   into [`ServiceRecord`].
//! - When the `asset` feature is also on, an
//!   `Asset::from_mdns` adapter (defined in `src/asset/core.rs`)
//!   contributes the host's apparent hostname to the
//!   inventory plus the [`crate::asset::AssetSourceSet::MDNS`]
//!   source bit.
//!
//! # What this is NOT
//!
//! - A re-implementation of DNS parsing. Calls go through
//!   `flowscope::dns` directly.
//! - LLMNR (Link-Local Multicast Name Resolution, UDP/5355) —
//!   different RFC, different conventions. File separately
//!   if needed.
//!
//! Issue #14 row 5 sub-piece (the `NetBIOS-NS / mDNS / SSDP`
//! cluster). Completes the asset-inventory coverage gap noted
//! in [`crate::asset::AssetSourceSet::OTHER`].

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::dns::DnsResponse;

mod datagram;
mod service;

pub use datagram::{MdnsParser, PARSER_KIND};
pub use service::{ServiceRecord, extract_services};

/// IANA-assigned mDNS UDP port.
pub const MDNS_PORT: u16 = 5353;

/// IPv4 mDNS multicast group (RFC 6762 §3).
pub const MDNS_MULTICAST_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);

/// IPv6 mDNS multicast group (RFC 6762 §3).
pub const MDNS_MULTICAST_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x00fb);

/// Heuristic: `true` iff this DNS response was probably an
/// mDNS response (carries the unicast-query bit cleared in
/// most answers, or includes service-discovery PTR records).
///
/// Useful for consumers running a single DNS parser on both
/// 53 and 5353 traffic that want to label the message kind
/// after the fact.
pub fn looks_like_mdns(resp: &DnsResponse) -> bool {
    // mDNS uses transaction_id = 0 most of the time (RFC 6762
    // §18.1). That's a fragile single signal, but combined
    // with a service-discovery PTR record it's almost
    // certain.
    if resp.transaction_id == 0 {
        return true;
    }
    !extract_services(resp).is_empty()
}

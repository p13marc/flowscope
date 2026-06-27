//! SSDP (Simple Service Discovery Protocol) parser.
//!
//! Gated by the `ssdp` feature. SSDP is the UPnP / DLNA / IoT
//! service-discovery protocol — UDP/1900 multicast on
//! `239.255.255.250` (v4) or `ff02::c` (v6), HTTP-like
//! text-based message format. Useful for passive asset and
//! IoT discovery; complements DHCP (#11), LLDP (#23), CDP
//! (#25), NDP (#6), ARP (#1) on the same network.
//!
//! Three message types per UPnP Device Architecture 2.0:
//!
//! - `NOTIFY * HTTP/1.1` — device advertisement (broadcast).
//!   Carries `NTS` (`ssdp:alive`, `ssdp:byebye`, etc.) and
//!   `USN` / `LOCATION` / `NT`.
//! - `M-SEARCH * HTTP/1.1` — client query (multicast).
//!   Carries `ST` (search target) and `MX` (max wait).
//! - `HTTP/1.1 200 OK` — unicast response to M-SEARCH.
//!   Carries `ST` / `USN` / `LOCATION` / `SERVER`.
//!
//! Issue #14 (Tier-2 sub-piece).
//!
//! # Surfaced fields
//!
//! - [`SsdpMessage::kind`] — Notify / MSearch / Response.
//! - [`SsdpMessage::nts`] — Notification Sub-Type for NOTIFY
//!   (`ssdp:alive` / `ssdp:byebye` / `ssdp:update`).
//! - [`SsdpMessage::nt`] / [`SsdpMessage::st`] — Notification /
//!   Search Target — the device or service type
//!   (`upnp:rootdevice`, `urn:schemas-upnp-org:device:...`).
//! - [`SsdpMessage::usn`] — Unique Service Name (UUID +
//!   optional `::` + URN).
//! - [`SsdpMessage::location`] — Description URL.
//! - [`SsdpMessage::server`] — Vendor / device firmware
//!   banner (e.g. `"Linux/4.19.146 UPnP/1.0 ..."`).
//! - [`SsdpMessage::host`] — multicast address the message
//!   was sent to (presence-check, not a spoof predicate).
//! - [`SsdpMessage::cache_control_max_age`] — TTL of the
//!   announcement.
//!
//! # Out of scope
//!
//! - The HTTP body of the description URL pointed at by
//!   `LOCATION` — that's a separate TCP fetch flowscope
//!   doesn't perform (passive).
//! - SSDP signatures / vendor-specific header extensions —
//!   surfaced opaquely as the rest of the payload.

mod datagram;
mod parser;
mod types;

pub use datagram::{PARSER_KIND, SSDP_MULTICAST_PORT, SsdpParser};
pub use parser::{ParseError, parse};
pub use types::{SsdpKind, SsdpMessage};

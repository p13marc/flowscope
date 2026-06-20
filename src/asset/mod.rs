//! Passive asset inventory — a unified [`Asset`] record over
//! every L2/L3 discovery parser flowscope ships.
//!
//! Gated by the `asset` feature. Composes the per-protocol
//! parsers shipped in the 0.18 cycle (ARP / NDP / DHCP / LLDP
//! / CDP / SSDP) into one operationally-natural answer to
//! *"who is on my network, what are they, what's their
//! fingerprint?"* — the question every NIDS / SIEM / asset-
//! discovery deployment hand-rolls today.
//!
//! Issue #27 (0.18).
//!
//! # Wire shape
//!
//! - [`Asset`] — the per-MAC record. Carries IP bindings
//!   (v4 + v6 lists), hostname, FQDN, vendor banner,
//!   platform, capabilities (bitflags), the per-parser
//!   fingerprints, and a [`AssetSourceSet`] bitmask.
//! - [`Inventory`] — LRU-bounded `MacAddr → Asset` store.
//! - Adapter functions (one per parser feature):
//!   `Asset::from_arp` / `from_ndp` / `from_dhcp` /
//!   `from_lldp` / `from_cdp` / `from_ssdp`.
//!
//! # What this does NOT do
//!
//! - **Active enumeration.** flowscope is passive; this
//!   module surfaces only what's already crossed the wire.
//! - **Persistence.** `Inventory` is in-memory + LRU; SIEM
//!   storage is the consumer's responsibility.
//! - **TLS / SSH fingerprint correlation.** JA4 / HASSH /
//!   p0f surfaces from their own parsers; consumers populate
//!   `Asset::fingerprints` themselves to avoid coupling this
//!   module to the TLS / SSH parsers (and the FoxIO-licensed
//!   bits).
//!
//! # Sample integration
//!
//! ```no_run
//! # #[cfg(feature = "arp")] {
//! use flowscope::asset::{Asset, Inventory};
//!
//! let mut inv = Inventory::new(8192);
//! // Per ARP / NDP / etc. event arriving in your pipeline:
//! # let arp_msg = unimplemented!();
//! # let _: () = (|arp_msg| {
//! let update = Asset::from_arp(arp_msg);
//! inv.absorb(update);
//! # })(arp_msg);
//! # }
//! ```

mod core;
mod inventory;

pub use core::{Asset, AssetCapabilities, AssetFingerprints, AssetSourceSet};
pub use inventory::Inventory;

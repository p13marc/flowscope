//! LLDP parser (IEEE 802.1AB-2016, EtherType 0x88cc).
//!
//! Gated by the `lldp` feature. LLDP is the vendor-neutral L2
//! discovery protocol — every modern switch / router / IP-phone
//! / printer / IPMI BMC broadcasts identity + capabilities on
//! its directly-connected links. It's the L2 sibling of
//! [`crate::arp`] / [`crate::ndp`] for **infrastructure-device**
//! asset discovery, in contrast to [`crate::dhcp`] which sees
//! client-side bindings.
//!
//! # Operational signals
//!
//! - **Asset discovery**: chassis-ID + port-ID + system-name +
//!   management-address from a switch's LLDPDU reconstructs
//!   cable maps without logging in to the switch.
//! - **Rogue-switch detection**: an LLDPDU on a port where one
//!   isn't expected (or with a system-name that doesn't match
//!   the asset register) is a high-confidence MITM / VLAN-
//!   hopping IOC.
//! - **Shutdown announces**: `ttl_seconds == 0` is the
//!   "purge my entry" marker (IEEE 802.1AB §8.5.5); forged
//!   shutdown announces are a DoS signal.
//!
//! # Wire shape
//!
//! - [`parse`] — pure LLDPDU payload (after the
//!   `01:80:c2:..:..:..` Ethernet header). Use this when you've
//!   already routed by destination MAC + EtherType.
//! - [`parse_frame`] — full Ethernet frame (strips one optional
//!   802.1Q tag and validates dst MAC + EtherType 0x88cc).
//! - [`LldpParser`] — stateless marker for consumers wiring up
//!   slots / event hooks.
//!
//! Issue #23 (0.18).

mod parser;
mod types;

pub use parser::{LLDP_ETHERTYPE, LldpParser, parse, parse_frame};
pub use types::{
    CapabilityBits, ChassisId, LldpManagementAddress, LldpMessage, LldpVendorTlv, PortId,
    SystemCapabilities,
};

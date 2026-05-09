//! Built-in flow extractors and decap combinators.
//!
//! Available with the `extractors` feature (default-on).
//!
//! - [`FiveTuple`] — protocol + (src, dst) endpoints. Bidirectional
//!   by default (A→B and B→A merged).
//! - [`IpPair`] — IP address pair only; protocol ignored. Useful for
//!   ICMP and fragmented flows.
//! - [`MacPair`] — L2 MAC pair. Useful for ARP, BPDU, LLDP.
//!
//! Decap combinators wrap any extractor and peel one encapsulation
//! layer first:
//!
//! - [`StripVlan<E>`] — strip 802.1Q VLAN tag(s)
//! - [`StripMpls<E>`] — strip MPLS label stack
//! - [`InnerVxlan<E>`] — decap VXLAN, run extractor on inner Ethernet
//! - [`InnerGtpU<E>`] — decap GTP-U, run extractor on inner IP
//! - [`InnerGre<E>`] — decap GRE (IP proto 47), run extractor on
//!   inner IPv4/IPv6 (or inner Ethernet for TEB)
//! - [`AutoDetectEncap<E>`] — try plain → VLAN → MPLS → VXLAN →
//!   GTP-U → GRE in order; first match wins
//!
//! Key augmentation:
//!
//! - [`FlowLabel<E>`] — append the IPv6 flow label (RFC 6437) to
//!   any inner key. IPv4 packets get `label = 0`.
//!
//! Combinators compose: `StripVlan(InnerVxlan::new(FiveTuple::bidirectional()))`.

#[cfg(any(test, feature = "test-helpers"))]
pub mod parse;
#[cfg(not(any(test, feature = "test-helpers")))]
pub(crate) mod parse;

pub mod five_tuple;
pub mod ip_pair;
pub mod mac_pair;

pub mod encap_gre;
pub mod encap_gtp;
pub mod encap_mpls;
pub mod encap_vlan;
pub mod encap_vxlan;

pub mod auto_detect;
pub mod flow_label;

pub use five_tuple::{FiveTuple, FiveTupleKey};
pub use ip_pair::{IpPair, IpPairKey};
pub use mac_pair::{MacPair, MacPairKey};

pub use encap_gre::InnerGre;
pub use encap_gtp::InnerGtpU;
pub use encap_mpls::StripMpls;
pub use encap_vlan::StripVlan;
pub use encap_vxlan::InnerVxlan;

pub use auto_detect::{AutoDetectEncap, AutoEncapVariants};
pub use flow_label::{FlowLabel, FlowLabelKey};

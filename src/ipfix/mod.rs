//! IPFIX (RFC 7011 / RFC 7012) Information Element vocabulary.
//!
//! Ships the IANA-registry data for the operationally-common
//! Information Elements as a const table — id, name, abstract
//! type, units, description. Use it to:
//!
//! - Build a flow exporter (NetFlow v9 / IPFIX) without
//!   hand-rolling the IE registry.
//! - Validate that a per-flow field has the right abstract
//!   type before serialising.
//! - Look up the canonical IANA name for an IE id (or vice
//!   versa) at any sink.
//!
//! Scoped piece of #16. The full **re-key FlowRecord to IPFIX
//! IEs** work stays open in #16 — what's here today is the
//! IE-registry vocabulary as a stand-alone module; existing
//! emitters still use their own field sets.
//!
//! # Coverage
//!
//! The shipped table is the **operationally-common subset**
//! (~35 IEs) — every IE that flowscope's own emitters and the
//! mainstream tools (Zeek, Suricata, goflow2, nProbe) actually
//! reference. The full IANA registry has 500+ entries; if you
//! need an entry that isn't here, add it via a PR — the table
//! is a single const-array.
//!
//! # `flowEndReason` + `tcpControlBits` helpers
//!
//! Issue #16 explicitly calls out these two "commonly-missing-
//! yet-standard" IPFIX fields:
//!
//! - [`FlowEndReason`] enum + `From<crate::EndReason>` impl
//!   — the IPFIX-canonical 5-state termination cause.
//! - [`encode_tcp_control_bits`] — the cumulative TCP-flags
//!   field per RFC 5102 §5.11.6 (`u16`).
//!
//! Issue #16 (scoped sub-piece). Full FlowRecord re-key stays
//! open in #16 itself.

mod record;
mod registry;
mod types;

#[cfg(feature = "ipfix-export")]
pub mod wire;

pub use record::FlowRecord;
pub use registry::{IES, lookup_by_id, lookup_by_name};
pub use types::{FlowEndReason, IeAbstractType, InformationElement, encode_tcp_control_bits};

//! SNMP v1/v2c parser.
//!
//! Gated by the `snmp` Cargo feature. Decodes SNMP messages
//! per RFC 1157 (v1) and RFC 1905 (v2c) via the rusticata
//! [`snmp-parser`](https://crates.io/crates/snmp-parser)
//! crate (ASN.1 BER). Surfaces:
//!
//! - **Version** — v1 / v2c / Other(i64).
//! - **Community string** — cleartext credential (T1078).
//!   The default values are `"public"` (read-only) and
//!   `"private"` (read-write); their presence on the wire
//!   is a permanent finding for any compliance audit.
//! - **PDU type** — GetRequest / GetNextRequest / GetResponse
//!   / SetRequest / GetBulkRequest / InformRequest / Trap
//!   (v1) / TrapV2 / Report.
//! - **Request ID** — for query/response correlation.
//! - **Variable bindings** — the list of OIDs being
//!   queried or asserted, as dotted-decimal strings.
//!
//! Use cases:
//!
//! - Asset enumeration — `GetRequest` for sysName / sysDescr
//!   reveals device identity.
//! - DDoS amplification detection — public-internet-reachable
//!   SNMP responders with large response bodies are a known
//!   reflector vector.
//! - Default-credential audit — anything with community ==
//!   `"public"` or `"private"` on the wire is mis-configured.
//!
//! # What this is NOT
//!
//! - **SNMPv3** — USM authentication + privacy encryption
//!   are not parsed here. v3 detection would surface
//!   `version = Other(3)`; the rest stays opaque.
//! - **MIB resolution** — OIDs are surfaced as dotted-decimal
//!   strings. Translation to human names (e.g. `1.3.6.1.2.1.1.1`
//!   → `sysDescr`) is the consumer's responsibility.
//! - **Value parsing** — only the OIDs of the variable
//!   bindings are surfaced; the bound values (counters,
//!   strings, etc.) are dropped to keep the surface focused.
//!
//! Issue #14 (Tier-2 row 3).

mod datagram;
mod parser;
mod types;

pub use datagram::{PARSER_KIND, SNMP_PORT, SNMP_TRAP_PORT, SnmpParser};
pub use parser::parse;
pub use types::{SnmpMessage, SnmpPduKind, SnmpVersion};

//! LDAP (RFC 4511) passive metadata parser — TCP/389.
//!
//! Gated by the `ldap` Cargo feature. Wraps the rusticata
//! [`ldap_parser`] crate (ASN.1 BER decoder sharing the
//! `asn1-rs` / `der-parser` fuzz-hardened base used by SNMP
//! and Kerberos).
//!
//! ## Surfaced fields
//!
//! [`LdapMessage`] carries:
//!
//! - `message_id` — LDAP request/response correlation ID.
//! - `operation` — [`LdapOperation`] tag (BindRequest /
//!   SearchRequest / SearchResultDone / etc.).
//! - `bind_name` / `bind_auth_kind` — Bind DN and auth choice
//!   (Simple / SASL). For Simple binds we surface whether
//!   the credentials field was present (cleartext-creds
//!   visibility), but never the cleartext itself.
//! - `search_base` / `search_scope` / `search_attributes` —
//!   Search operation summary.
//! - `search_attributes_spn_query` — convenience boolean,
//!   `true` when the attribute list contains
//!   `servicePrincipalName`. The
//!   **GetUserSPNs / BloodHound enumeration** signal
//!   (MITRE T1087, prerequisite to T1558.003 Kerberoast).
//! - `result_code` — LDAP result code (e.g. 0 = success,
//!   49 = invalid credentials) on response operations.
//!
//! ## Scope limits
//!
//! - LDAPS / StartTLS-wrapped LDAP is OUT — we observe only
//!   the cleartext channel. Encrypted LDAP traffic surfaces
//!   no LDAP messages.
//! - Full LDAP search filter expression decoding is OUT —
//!   we surface the requested attribute names only. The
//!   rusticata `Filter` tree is available via the embedded
//!   parser if a consumer needs deeper inspection.
//! - SASL bind sub-mechanism (Kerberos / NTLM / GSSAPI) is
//!   surfaced as the SASL mechanism string verbatim.
//! - StartTLS upgrade detection is OUT (would require
//!   tracking the ExtendedRequest OID = "1.3.6.1.4.1.1466.20037"
//!   and switching parser modes; left for follow-up).
//!
//! Issue #13 (0.18).

mod parser;
#[cfg(feature = "pcap")]
mod pcap_iter;
mod session;
mod types;

pub use parser::{ParseError, parse, parser_kind};
#[cfg(feature = "pcap")]
pub use pcap_iter::messages_from_pcap;
pub use session::{LDAP_PORT, LdapParser};
pub use types::{LdapAuthKind, LdapMessage, LdapOperation, LdapResultCode, LdapSearchScope};

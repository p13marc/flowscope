//! Kerberos (RFC 4120) passive metadata parser.
//!
//! Gated by the `kerberos` Cargo feature. Wraps the
//! rusticata [`kerberos_parser`] crate (ASN.1 BER/DER decoder
//! sharing the `asn1-rs` / `der-parser` fuzz-hardened base
//! that SNMP also uses).
//!
//! ## Surfaced fields
//!
//! [`KerberosMessage`] carries:
//!
//! - `kind` — [`KerberosMessageKind`] (AsReq / AsRep / TgsReq
//!   / TgsRep / ApReq / ApRep / KrbError / Unknown).
//! - `pvno` — Kerberos protocol version number (typically 5).
//! - `realm` — Kerberos realm (server-side for requests,
//!   client-side for replies).
//! - `cname` — client principal name (`user/instance` joined).
//! - `sname` — server principal name (the service being
//!   requested).
//! - `etypes` — list of `EncryptionType` numbers offered by
//!   the client. **RC4-HMAC (etype 23) presence is the
//!   classic Kerberoasting downgrade signal (MITRE
//!   T1558.003).**
//! - `padata_types` — list of PA-DATA type numbers observed.
//! - `kerberoast_suspect` — convenience boolean: TGS-REQ with
//!   etype 23 (RC4-HMAC) listed.
//! - `error_code` — Kerberos error code on KRB-ERROR messages
//!   (e.g. KDC_ERR_PREAUTH_REQUIRED = 25).
//!
//! ## Scope limits
//!
//! - Encrypted PA-DATA / ticket contents are NOT decrypted —
//!   we surface the type/etype metadata only.
//! - TCP framing is the 4-byte length-prefix per RFC 4120
//!   §7.2.2; we handle reassembly internally. UDP frames are
//!   parsed verbatim per [`KerberosUdpParser`].
//! - Cross-correlation of AS-REQ → AS-REP → TGS-REQ → TGS-REP
//!   into a "Kerberos session" is OUT — left to consumers.
//!   The reference Zeek shape is one record per message.
//!
//! Issue #13 (0.18).

mod datagram;
mod parser;
#[cfg(feature = "pcap")]
mod pcap_iter;
mod session;
mod types;

pub use datagram::{KERBEROS_PORT, KerberosUdpParser};
pub use parser::{ParseError, parse, parser_kind};
#[cfg(feature = "pcap")]
pub use pcap_iter::messages_from_pcap;
pub use session::KerberosTcpParser;
pub use types::{KerberosErrorCode, KerberosEtype, KerberosMessage, KerberosMessageKind};

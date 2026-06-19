//! Passive TLS handshake observer.
//!
//! Bridges [`tls-parser`](https://crates.io/crates/tls-parser)
//! into `flowscope`'s [`SessionParser`](crate::SessionParser)
//! abstraction. Receives bytes from the per-flow TCP stream,
//! emits parsed [`TlsClientHello`] / [`TlsServerHello`] /
//! [`TlsAlert`] as [`TlsMessage`] variants.
//!
//! Two `SessionParser` shapes ship side by side:
//!
//! - [`TlsParser`] — per-message stream (ClientHello,
//!   ServerHello, Alert, optional JA3/JA4 fingerprints).
//! - [`TlsHandshakeParser`] — aggregator that emits one
//!   [`TlsHandshake`] event per observed handshake with SNI,
//!   ALPN, fingerprints, version, cipher, and
//!   [`HandshakeOutcome`] in a single struct.
//!
//! # Quick start
//!
//! ```no_run
//! use flowscope::extract::FiveTuple;
//! use flowscope::tls::{TlsMessage, TlsParser};
//! use flowscope::{FlowSessionDriver, SessionEvent};
//!
//! let _driver = FlowSessionDriver::new(
//!     FiveTuple::bidirectional(),
//!     TlsParser::default(),
//! );
//! ```
//!
//! # Scope
//!
//! - **Passive** observation only — no decryption, no MITM.
//! - ClientHello, ServerHello, Alert from the unencrypted
//!   handshake.
//! - SNI / ALPN / supported versions / cipher list / extension
//!   order.
//! - TLS 1.0 — TLS 1.3 (visibility limited after
//!   ChangeCipherSpec in 1.2 and after ServerHello in 1.3 since
//!   records are encrypted onward).
//! - Optional [JA3](https://github.com/salesforce/ja3) and
//!   [JA4](https://github.com/FoxIO-LLC/ja4) client fingerprinting
//!   behind the `tls-fingerprints` feature (was `ja3` + `ja4`
//!   pre-0.12; collapsed in plan 131).
//!
//! # Convenience accessors
//!
//! ## [`TlsClientHello`]
//!
//! | Method / field | Returns | Notes |
//! |----------------|---------|-------|
//! | [`sni`](TlsClientHello::sni) | `Option<&str>` | `Server Name Indication` extension |
//! | `cipher_suites` | `Vec<u16>` | offered cipher suites in order |
//! | `supported_versions` | `Vec<TlsVersion>` | TLS 1.3 `supported_versions` extension |
//! | `alpn` | `Vec<String>` | ALPN protocols offered |
//! | `extension_types` | `Vec<u16>` | extension order — used by JA3 / JA4 |
//!
//! ## [`TlsServerHello`]
//!
//! | Method / field | Returns | Notes |
//! |----------------|---------|-------|
//! | `cipher_suite` | `u16` | the chosen cipher |
//! | `alpn` | `Option<String>` | negotiated ALPN protocol |
//! | `supported_version` | `Option<TlsVersion>` | actual TLS 1.3 version |
//! | `extension_types` | `Vec<u16>` | extension order — used by JA4S |
//!
//! ## [`TlsHandshakeParser`] + [`TlsHandshake`]
//!
//! The aggregator emits one [`TlsHandshake`] event per
//! observed handshake with SNI / ALPN / JA3 / JA4 / version /
//! cipher / `resumption_attempted` / [`HandshakeOutcome`] in
//! a single struct.

#[cfg(feature = "tls-fingerprints")]
mod fingerprint;
pub mod handshake;
#[cfg(feature = "tls-fingerprints")]
pub mod ja4;
// JA4S is FoxIO License 1.1 (patent pending), NOT BSD like JA4/JA3 — gated
// behind the opt-in `ja4plus` feature. See LICENSE-FoxIO-1.1 + NOTICE.
#[cfg(feature = "ja4plus")]
pub mod ja4s;
mod parser;
mod session;
mod types;

pub use handshake::{EchOutcome, HandshakeOutcome, TlsHandshake, TlsHandshakeParser};
#[cfg(feature = "tls-fingerprints")]
pub use ja4::{ja4 as ja4_fingerprint, ja4_parts, Ja4Parts};
#[cfg(feature = "ja4plus")]
pub use ja4s::{ja4s as ja4s_fingerprint, ja4s_parts, Ja4sParts};
pub use session::{TlsMessage, TlsParser};
pub use types::*;

/// Slug returned by [`TlsParser`]'s `parser_kind()`. See
/// `flowscope::parser_kinds::TLS`.
///
/// Stability: locked from 0.8 forward.
pub const PARSER_KIND: &str = "tls";

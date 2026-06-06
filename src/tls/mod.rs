//! Passive TLS handshake observer.
//!
//! Bridges [`tls-parser`](https://crates.io/crates/tls-parser) into
//! `flowscope`'s [`Reassembler`](crate::Reassembler).  Receives bytes
//! from the per-flow TCP stream, emits parsed [`TlsClientHello`] /
//! [`TlsServerHello`] / [`TlsAlert`] events via a user-supplied
//! [`TlsHandler`].
//!
//! # Quick start
//!
//! ```no_run
//! use flowscope::tls::{TlsClientHello, TlsFactory, TlsHandler};
//!
//! struct Logger;
//! impl TlsHandler for Logger {
//!     fn on_client_hello(&self, h: &TlsClientHello) {
//!         println!("SNI: {:?}, ALPN: {:?}", h.sni, h.alpn);
//!     }
//! }
//! ```
//!
//! # Scope
//!
//! - **Passive** observation only — no decryption, no MITM.
//! - ClientHello, ServerHello, Alert from the unencrypted handshake.
//! - SNI / ALPN / supported versions / cipher list / extension order.
//! - TLS 1.0 — TLS 1.3 (visibility limited after ChangeCipherSpec
//!   in 1.2 and after ServerHello in 1.3 since records are
//!   encrypted onward).
//! - Optional [JA3](https://github.com/salesforce/ja3) fingerprinting
//!   behind the `ja3` feature.

mod factory;
#[cfg(feature = "ja3")]
mod fingerprint;
mod parser;
mod session;
mod types;

pub use factory::{TlsFactory, TlsReassembler};
pub use parser::Error;
pub use session::{TlsMessage, TlsParser};
pub use types::*;

/// Slug returned by [`TlsParser`]'s `parser_kind()`. See
/// `flowscope::parser_kinds::TLS`.
///
/// Stability: locked from 0.8 forward.
pub const PARSER_KIND: &str = "tls";

//! p0f-style passive TCP/IP stack fingerprint.
//!
//! Gated by the `tcp_fingerprint` feature. License-clean
//! alternative to FoxIO's `JA4T` / `JA4TS` (FoxIO-licensed) —
//! the *technique* is in the public domain; flowscope ships
//! the field extraction and the p0f-3 signature-string
//! formatter, not any pre-built signature database.
//!
//! # Inputs
//!
//! [`fingerprint_from_layers`] takes a per-packet
//! [`crate::layers::Layers`] view and returns a
//! [`TcpFingerprint`] when the packet is a SYN (client) or
//! SYN-ACK (server) over IPv4 or IPv6. Anything else returns
//! `None`.
//!
//! # Output shape
//!
//! [`TcpFingerprint`] surfaces the operationally-interesting
//! fields directly (initial TTL, guessed hop class, window
//! size, MSS, window scale, option layout, DF bit, quirks),
//! and [`TcpFingerprint::to_p0f_signature`] formats them as
//! the p0f-3 string `ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass`
//! consumers can match against a signature database.
//!
//! # Out of scope
//!
//! - **No signature database.** p0f's DB is LGPL and stale;
//!   consumers bring their own (Recog, custom).
//! - **No per-flow caching.** Each call is stateless; the
//!   caller decides which packets to fingerprint (typically
//!   the first SYN and SYN-ACK of every flow).
//!
//! Issue #9 (0.18).

mod fingerprint;

pub use fingerprint::{
    Quirks, TcpDirection, TcpFingerprint, fingerprint_from_layers, guess_initial_ttl,
};

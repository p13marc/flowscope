//! Passive DNS observer (UDP/53).
//!
//! Parses DNS query/response messages observed in UDP/53 traffic.
//! Two integration shapes:
//!
//! - [`DnsUdpObserver`] — callback-style tap that wraps an inner
//!   [`FlowExtractor`](crate::FlowExtractor) and fires
//!   [`DnsHandler`] events as a side effect of extraction.
//! - [`DnsUdpParser`] — typed message stream impl of
//!   [`DatagramParser`](crate::DatagramParser). Pair with
//!   `datagram_stream(...)` from `netring`.
//!
//! Both pair with the [`Correlator`] for query/response RTT
//! matching by 16-bit transaction ID, scoped per flow key.
//!
//! # Quick start (parser only)
//!
//! ```no_run
//! use flowscope::dns::{parse_message, DnsParseResult};
//!
//! let payload: &[u8] = b"";  // your UDP/53 payload
//! match parse_message(payload) {
//!     Ok(DnsParseResult::Query(q)) => println!("query: {} questions", q.questions.len()),
//!     Ok(DnsParseResult::Response(r)) => println!("response: rcode={:?}", r.rcode),
//!     Err(_e) => {}  // malformed — ignore
//! }
//! ```
//!
//! # Scope
//!
//! - **UDP/53 only** in v0.1. TCP/53 (large responses, AXFR/IXFR)
//!   and DoT (TLS/853) are deferred.
//! - **Passive** — no resolution, no validation.
//! - DNSSEC: RRSIG/DNSKEY surface as [`DnsRdata::Other`] with raw
//!   rdata; we don't validate.
//! - **Common record types** decoded: A, AAAA, CNAME, NS, PTR, MX.
//!   Everything else: `DnsRdata::Other { rtype, data }`.

mod correlator;
mod datagram;
mod observer;
mod parser;
mod types;

pub use correlator::Correlator;
pub use datagram::{DnsMessage, DnsUdpParser};
pub use observer::DnsUdpObserver;
pub use parser::{DnsParseResult, parse_message, parse_message_at};
pub use types::*;

/// Errors from the DNS module.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The payload could not be parsed as a DNS message.
    #[error("invalid DNS message: {0}")]
    Parse(String),
}

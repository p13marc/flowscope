//! Passive DNS parsing (UDP/53).
//!
//! Parses DNS query/response messages observed in UDP/53 traffic.
//!
//! [`DnsUdpParser`] is the integration point — a
//! [`DatagramParser`](crate::DatagramParser) impl yielding a typed
//! [`DnsMessage`] stream. Pair it with [`crate::FlowDatagramDriver`],
//! [`PcapFlowSource::datagrams`](crate::pcap::PcapFlowSource::datagrams),
//! or netring's `datagram_stream`. With correlation enabled
//! ([`DnsUdpParser::with_correlation`]) it matches responses to
//! queries — round-trip time lands in `DnsResponse::elapsed`, and
//! `on_tick` emits [`DnsMessage::Unanswered`] for queries that time
//! out. The [`Correlator`] is also public for advanced
//! custom-scoped correlation.
//!
//! # Quick start (stateless message parsing)
//!
//! ```no_run
//! use flowscope::dns::{parse_message, DnsParseResult};
//!
//! let payload: &[u8] = b"";  // your UDP/53 payload
//! match parse_message(payload) {
//!     Ok(DnsParseResult::Query(q)) => println!("query: {} questions", q.questions.len()),
//!     Ok(DnsParseResult::Response(r)) => println!("response: rcode={:?}", r.rcode),
//!     Ok(_) => {}    // future variants
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
//!
//! # Convenience accessors
//!
//! ## [`DnsQuery`] / [`DnsResponse`]
//!
//! | Field / method | Returns | Notes |
//! |----------------|---------|-------|
//! | `id` | `u16` | transaction ID (matches query ↔ response) |
//! | `questions` | `Vec<DnsQuestion>` | name + rtype + rclass per query slot |
//! | `answers` (response) | `Vec<DnsRecord>` | A / AAAA / CNAME / NS / PTR / MX |
//! | `rcode` (response) | [`DnsRcode`] | response code |
//! | `elapsed` (correlated response) | `Option<Duration>` | round-trip time |
//!
//! ## [`DnsFlags`]
//!
//! | Method | Returns |
//! |--------|---------|
//! | [`is_response`](DnsFlags::is_response) | `bool` |
//! | [`is_authoritative`](DnsFlags::is_authoritative) | `bool` |
//! | [`is_truncated`](DnsFlags::is_truncated) | `bool` |
//! | [`is_recursion_desired`](DnsFlags::is_recursion_desired) | `bool` |
//! | [`is_recursion_available`](DnsFlags::is_recursion_available) | `bool` |
//! | [`opcode`](DnsFlags::opcode) | `u8` |
//! | [`rcode_raw`](DnsFlags::rcode_raw) | `u8` |

mod correlator;
mod datagram;
mod exchange;
mod parser;
#[cfg(feature = "pcap")]
mod pcap_iter;
mod resolution_cache;
mod session;
mod types;

pub use correlator::Correlator;
pub use datagram::{DnsMessage, DnsUdpParser};
pub use exchange::{DnsExchange, DnsExchangeParser, DnsOutcome};
pub use parser::{DnsParseResult, parse_message, parse_message_at};
#[cfg(feature = "pcap")]
pub use pcap_iter::{exchanges_from_pcap, messages_from_pcap};
pub use resolution_cache::DnsResolutionCache;
pub use session::DnsTcpParser;
pub use types::*;

/// Slug returned by [`DnsUdpParser`]'s `parser_kind()`. See
/// `flowscope::parser_kinds::DNS_UDP`.
///
/// Stability: locked from 0.8 forward.
pub const PARSER_KIND_UDP: &str = "dns-udp";

/// Slug returned by [`DnsTcpParser`]'s `parser_kind()`. See
/// `flowscope::parser_kinds::DNS_TCP`.
///
/// Stability: locked from 0.8 forward.
pub const PARSER_KIND_TCP: &str = "dns-tcp";

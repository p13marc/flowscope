//! Passive HTTP/1.x observer.
//!
//! Bridges [`httparse`](https://crates.io/crates/httparse)'s
//! zero-copy parser into `flowscope`'s
//! [`SessionParser`](crate::SessionParser) abstraction. Receives
//! bytes from the per-flow TCP stream, emits parsed
//! [`HttpRequest`] / [`HttpResponse`] events as
//! [`HttpMessage`] variants.
//!
//! # Quick start
//!
//! Register an [`HttpParser`] on the typed
//! [`Driver`](crate::driver::Driver) and drain its slot:
//!
//! ```
//! use flowscope::driver::Driver;
//! use flowscope::extract::FiveTuple;
//! use flowscope::http::HttpParser;
//!
//! let mut builder = Driver::builder(FiveTuple::bidirectional());
//! let mut http = builder.session_on_ports(HttpParser::default(), [80, 8080]);
//! let _driver = builder.build();
//! # let _ = &mut http;
//! ```
//!
//! Each drained [`SlotMessage`](crate::driver::SlotMessage) carries
//! the parsed [`HttpMessage`] directly:
//!
//! ```no_run
//! use flowscope::driver::{Driver, Event, SlotMessage};
//! use flowscope::extract::{FiveTuple, FiveTupleKey};
//! use flowscope::http::{HttpMessage, HttpParser};
//! use flowscope::PacketView;
//!
//! let mut builder = Driver::builder(FiveTuple::bidirectional());
//! let mut http = builder.session_on_ports(HttpParser::default(), [80, 8080]);
//! let mut driver = builder.build();
//!
//! let mut events: Vec<Event<FiveTupleKey>> = Vec::new();
//! let mut msgs: Vec<SlotMessage<HttpMessage, FiveTupleKey>> = Vec::new();
//! # fn views() -> impl IntoIterator<Item = PacketView<'static>> { std::iter::empty() }
//! for view in views() {
//!     events.clear();
//!     msgs.clear();
//!     driver.track_into(view, &mut events);
//!     http.drain(&mut msgs);
//!     for m in &msgs {
//!         match &m.message {
//!             HttpMessage::Request(r)  => { let _ = r; /* handle request */ }
//!             HttpMessage::Response(r) => { let _ = r; /* handle response */ }
//!             _ => {}
//!         }
//!     }
//! }
//! ```
//!
//! # Scope
//!
//! - HTTP/1.0 and HTTP/1.1.
//! - Request line + headers + body via Content-Length.
//! - Pipelined requests on one connection.
//! - HTTP/2 / HTTP/3: out of scope.
//! - Chunked Transfer-Encoding: deferred.
//!
//! # Convenience accessors
//!
//! Every header accessor below skips the boilerplate of "iterate
//! the `headers: Vec<(String, Vec<u8>)>`, case-insensitive
//! compare, then `from_utf8`". They cover the headers every
//! HTTP-monitor example reached for.
//!
//! ## [`HttpRequest`]
//!
//! | Method | Returns | Equivalent |
//! |--------|---------|------------|
//! | [`host`](HttpRequest::host) | `Option<&str>` | first `Host` header |
//! | [`user_agent`](HttpRequest::user_agent) | `Option<&str>` | first `User-Agent` |
//! | [`cookie`](HttpRequest::cookie) | `Option<&str>` | first `Cookie` |
//! | [`content_type`](HttpRequest::content_type) | `Option<&str>` | `Content-Type` (**new in 0.10**) |
//! | [`content_length`](HttpRequest::content_length) | `Option<u64>` | parsed `Content-Length` (**new in 0.10**) |
//! | [`referer`](HttpRequest::referer) | `Option<&str>` | `Referer` (**new in 0.10**) |
//! | [`accept`](HttpRequest::accept) | `Option<&str>` | `Accept` (**new in 0.10**) |
//! | [`header`](HttpRequest::header) | `Option<&[u8]>` | first matching header (case-insensitive) |
//! | [`headers_all`](HttpRequest::headers_all) | `impl Iterator<Item = &[u8]>` | every matching header |
//!
//! ## [`HttpResponse`]
//!
//! | Method | Returns | Equivalent |
//! |--------|---------|------------|
//! | [`status_class`](HttpResponse::status_class) | `Option<u8>` | `status / 100` (**new in 0.10**) |
//! | [`is_success`](HttpResponse::is_success) | `bool` | `2xx` (**new in 0.10**) |
//! | [`is_redirect`](HttpResponse::is_redirect) | `bool` | `3xx` (**new in 0.10**) |
//! | [`is_client_error`](HttpResponse::is_client_error) | `bool` | `4xx` (**new in 0.10**) |
//! | [`is_server_error`](HttpResponse::is_server_error) | `bool` | `5xx` (**new in 0.10**) |
//! | [`content_type`](HttpResponse::content_type) | `Option<&str>` | `Content-Type` |
//! | [`content_length`](HttpResponse::content_length) | `Option<u64>` | parsed `Content-Length` |
//! | [`set_cookie`](HttpResponse::set_cookie) | `impl Iterator<Item = &str>` | every `Set-Cookie` header |
//! | [`header`](HttpResponse::header) | `Option<&[u8]>` | first matching header |
//! | [`headers_all`](HttpResponse::headers_all) | `impl Iterator<Item = &[u8]>` | every matching header |

mod exchange;
// JA4H is FoxIO License 1.1 (patent pending) — opt-in via the
// `ja4plus` feature alongside JA4S. See LICENSE-FoxIO-1.1 +
// NOTICE.
#[cfg(feature = "ja4plus")]
pub mod ja4h;
mod parser;
#[cfg(feature = "pcap")]
mod pcap_iter;
mod session;
mod types;

pub use exchange::{HttpExchange, HttpExchangeParser, HttpOutcome};
#[cfg(feature = "ja4plus")]
pub use ja4h::{Ja4hParts, ja4h as ja4h_fingerprint, ja4h_parts};
#[cfg(feature = "pcap")]
#[allow(deprecated)]
pub use pcap_iter::{exchanges_from_pcap, requests_from_pcap, responses_from_pcap};
pub use session::{HttpMessage, HttpParser};
pub use types::{HttpConfig, HttpRequest, HttpResponse, HttpVersion};

/// Slug returned by [`HttpParser`]'s `parser_kind()`. Use at
/// match sites in place of a string literal so typos fail to
/// resolve instead of silently miss. Available also as
/// `flowscope::parser_kinds::HTTP`.
///
/// Stability: locked from 0.8 forward.
pub const PARSER_KIND: &str = "http/1";

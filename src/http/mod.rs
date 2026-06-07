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
//! ```no_run
//! use flowscope::extract::FiveTuple;
//! use flowscope::http::{HttpMessage, HttpParser};
//! use flowscope::{FlowSessionDriver, SessionEvent, SessionParser, Timestamp};
//!
//! let _driver = FlowSessionDriver::new(
//!     FiveTuple::bidirectional(),
//!     HttpParser::default(),
//! );
//! ```
//!
//! For a callback-shaped interface, drive a `SessionParser` from
//! a consumer loop — `Application` events carry the parsed
//! `HttpMessage` directly:
//!
//! ```no_run
//! # use flowscope::extract::FiveTuple;
//! # use flowscope::http::{HttpMessage, HttpParser};
//! # use flowscope::{FlowSessionDriver, SessionEvent};
//! # let mut driver = FlowSessionDriver::new(FiveTuple::bidirectional(), HttpParser::default());
//! # fn views() -> impl IntoIterator<Item = flowscope::PacketView<'static>> { std::iter::empty() }
//! for view in views() {
//!     for ev in driver.track(view) {
//!         if let SessionEvent::Application { message, .. } = ev {
//!             match message {
//!                 HttpMessage::Request(r)  => { /* handle request */ }
//!                 HttpMessage::Response(r) => { /* handle response */ }
//!             }
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

mod parser;
mod session;
mod types;

pub use session::{HttpMessage, HttpParser};
pub use types::{HttpConfig, HttpRequest, HttpResponse, HttpVersion};

/// Slug returned by [`HttpParser`]'s `parser_kind()`. Use at
/// match sites in place of a string literal so typos fail to
/// resolve instead of silently miss. Available also as
/// `flowscope::parser_kinds::HTTP`.
///
/// Stability: locked from 0.8 forward.
pub const PARSER_KIND: &str = "http/1";

//! Passive HTTP/1.x observer.
//!
//! Bridges [`httparse`](https://crates.io/crates/httparse)'s
//! zero-copy parser into `flowscope`'s [`Reassembler`](crate::Reassembler)
//! and [`SessionParser`](crate::SessionParser) abstractions.
//! Receives bytes from the per-flow TCP stream, emits parsed
//! [`HttpRequest`] / [`HttpResponse`] events.
//!
//! Two integration shapes ship side by side:
//!
//! - [`HttpFactory`] — callback-style. Pair with
//!   `with_async_reassembler(...)` from `netring` (or
//!   [`FlowDriver`](crate::FlowDriver) for sync use).
//! - [`HttpParser`] — typed message stream. Pair with
//!   `session_stream(...)` from `netring`.
//!
//! Pick whichever fits your async/sync style.
//!
//! # Quick start
//!
//! ```no_run
//! use flowscope::http::{HttpFactory, HttpHandler, HttpRequest, HttpResponse};
//!
//! struct Logger;
//! impl HttpHandler for Logger {
//!     fn on_request(&self, req: &HttpRequest) {
//!         println!("{} {}", req.method, req.path);
//!     }
//!     fn on_response(&self, resp: &HttpResponse) {
//!         println!("  -> {} {}", resp.status, resp.reason);
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

mod factory;
mod parser;
mod session;
mod types;

pub use factory::{HttpFactory, HttpReassembler};
pub use parser::Error;
pub use session::{HttpMessage, HttpParser};
pub use types::{HttpConfig, HttpHandler, HttpRequest, HttpResponse, HttpVersion};

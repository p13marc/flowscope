//! Unified error type for flowscope.
//!
//! Every fallible API across the crate returns
//! [`Result<T>`](crate::Result) — an alias for `Result<T, Error>`.
//! `Error` carries:
//!
//! - a [`Module`] discriminant identifying which subsystem produced
//!   the error (HTTP / TLS / DNS / ICMP / pcap / reassembler /
//!   tracker / driver / emit / detect / aggregate / correlate /
//!   layers),
//! - an [`ErrorCode`] for ergonomic matching in user code
//!   (`Parse` / `BufferOverflow` / `Io` / `Unsupported` /
//!   `Truncated` / `Eof` / `Other`),
//! - a human-readable `message` whose format is *not* API-stable
//!   across releases (it may grow detail in patch versions),
//! - an optional `source` chain to the upstream parser library's
//!   error type (`httparse::Error`, `tls_parser::Err`,
//!   `simple_dns::SimpleDnsError`, `pcap_file::PcapError`,
//!   `std::io::Error`), so [`std::error::Error::source`] walks
//!   produce a complete trace.
//!
//! # Matching by kind
//!
//! ```
//! use flowscope::{Error, ErrorCode, Module};
//!
//! fn classify(e: &Error) {
//!     match (e.module(), e.code()) {
//!         (Module::Http, ErrorCode::BufferOverflow) => { /* … */ }
//!         (Module::Pcap, ErrorCode::Io)              => { /* … */ }
//!         _                                          => { /* … */ }
//!     }
//! }
//! ```
//!
//! # Source-chain walking
//!
//! `Error` implements `std::error::Error`, so existing tools
//! (`anyhow`, log formatters, the `?` operator) compose without
//! flowscope-specific code.
//!
//! ```no_run
//! use std::error::Error as _;
//!
//! fn print_chain(e: &flowscope::Error) {
//!     eprintln!("{e}");
//!     let mut src = e.source();
//!     while let Some(s) = src {
//!         eprintln!("  caused by: {s}");
//!         src = s.source();
//!     }
//! }
//! ```

use std::{error::Error as StdError, fmt};

/// Subsystem identifier for [`Error`].
///
/// Used in `match (e.module(), e.code()) { … }` patterns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Module {
    /// HTTP parser (`flowscope::http`).
    Http,
    /// TLS parser (`flowscope::tls`).
    Tls,
    /// DNS parser (`flowscope::dns`).
    Dns,
    /// ICMP parser (`flowscope::icmp`).
    Icmp,
    /// pcap source (`flowscope::pcap`).
    Pcap,
    /// TCP reassembler.
    Reassembler,
    /// Flow tracker.
    Tracker,
    /// `flowscope::layers` per-packet introspection.
    Layers,
    /// Typed driver / slot-handle path (`flowscope::driver`).
    /// New in 0.12.0 (plan 131).
    Driver,
    /// Emit writers (`flowscope::emit`). New in 0.12.0.
    Emit,
    /// Detection primitives (`flowscope::detect`). New in 0.12.0.
    Detect,
    /// Aggregation primitives (`flowscope::aggregate`).
    /// New in 0.12.0.
    Aggregate,
    /// Cross-flow correlation primitives (`flowscope::correlate`).
    /// New in 0.12.0.
    Correlate,
}

impl fmt::Display for Module {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Module::Http => "http",
            Module::Tls => "tls",
            Module::Dns => "dns",
            Module::Icmp => "icmp",
            Module::Pcap => "pcap",
            Module::Reassembler => "reassembler",
            Module::Tracker => "tracker",
            Module::Layers => "layers",
            Module::Driver => "driver",
            Module::Emit => "emit",
            Module::Detect => "detect",
            Module::Aggregate => "aggregate",
            Module::Correlate => "correlate",
        };
        f.write_str(s)
    }
}

/// Stable short identifier for matching in user code.
///
/// The `message` on [`Error`] is human-readable; this enum is the
/// machine-checkable axis. Pattern-match on `(module, code)` to
/// route errors without parsing strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    /// Wire bytes did not parse cleanly.
    Parse,
    /// A bounded buffer (reassembler, parser, correlator) exceeded
    /// its configured cap.
    BufferOverflow,
    /// An I/O error surfaced from the underlying source.
    Io,
    /// The operation is recognised but not yet implemented for the
    /// observed input (e.g. an unrecognised TLS version).
    Unsupported,
    /// The input ended before the expected message boundary.
    Truncated,
    /// The source has no more data.
    Eof,
    /// A catch-all for cases that don't fit the above. Prefer one
    /// of the typed codes; reach for `Other` only when none fits.
    Other,
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ErrorCode::Parse => "parse",
            ErrorCode::BufferOverflow => "buffer-overflow",
            ErrorCode::Io => "io",
            ErrorCode::Unsupported => "unsupported",
            ErrorCode::Truncated => "truncated",
            ErrorCode::Eof => "eof",
            ErrorCode::Other => "other",
        };
        f.write_str(s)
    }
}

/// Routing-and-context kind for an [`Error`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct ErrorKind {
    /// Subsystem that produced the error.
    pub module: Module,
    /// Stable code for matching.
    pub code: ErrorCode,
    /// Human-readable diagnostic. Format may change between
    /// releases; do not parse.
    pub message: String,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}: {}", self.module, self.code, self.message)
    }
}

/// The unified flowscope error type.
///
/// Constructed via crate-internal helpers (`Error::parse`,
/// `Error::buffer_overflow`, `Error::io`, …); consumers
/// inspect via [`Error::module`] / [`Error::code`] /
/// [`Error::kind`] and walk the `source` chain via
/// [`std::error::Error::source`].
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    source: Option<Box<dyn StdError + Send + Sync + 'static>>,
}

impl Error {
    #[cfg(any(feature = "http", feature = "tls", feature = "dns"))]
    pub(crate) fn parse(module: Module, message: impl Into<String>) -> Self {
        Self {
            kind: ErrorKind {
                module,
                code: ErrorCode::Parse,
                message: message.into(),
            },
            source: None,
        }
    }

    #[cfg(any(feature = "extractors", feature = "pcap", feature = "http"))]
    pub(crate) fn parse_with<E>(module: Module, message: impl Into<String>, source: E) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        Self {
            kind: ErrorKind {
                module,
                code: ErrorCode::Parse,
                message: message.into(),
            },
            source: Some(Box::new(source)),
        }
    }

    #[cfg(any(feature = "http", feature = "tls"))]
    pub(crate) fn buffer_overflow(module: Module, cap: usize) -> Self {
        Self {
            kind: ErrorKind {
                module,
                code: ErrorCode::BufferOverflow,
                message: format!("buffer exceeded cap={cap}"),
            },
            source: None,
        }
    }

    #[cfg(feature = "pcap")]
    pub(crate) fn io(module: Module, source: std::io::Error) -> Self {
        Self {
            kind: ErrorKind {
                module,
                code: ErrorCode::Io,
                message: source.to_string(),
            },
            source: Some(Box::new(source)),
        }
    }

    /// The full kind (module + code + message) of this error.
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    /// The subsystem that produced this error.
    pub fn module(&self) -> Module {
        self.kind.module
    }

    /// The stable code for this error. Match on
    /// `(module(), code())` to route errors.
    pub fn code(&self) -> ErrorCode {
        self.kind.code
    }

    /// `true` for transient / per-message failures
    /// (`Parse`, `BufferOverflow`, `Truncated`, `Unsupported`);
    /// `false` for terminal failures (`Io`, `Eof`).
    ///
    /// "Recoverable" here means "the calling pipeline can keep
    /// going against the next message / packet / flow." It does
    /// not promise the *current* operation can retry.
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self.kind.code,
            ErrorCode::Parse
                | ErrorCode::BufferOverflow
                | ErrorCode::Truncated
                | ErrorCode::Unsupported
        )
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.kind, f)
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_deref()
            .map(|s| s as &(dyn StdError + 'static))
    }
}

/// Result alias used throughout flowscope.
pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_carries_module_and_code() {
        let e = Error::parse(Module::Http, "bad request line");
        assert_eq!(e.module(), Module::Http);
        assert_eq!(e.code(), ErrorCode::Parse);
        assert!(e.is_recoverable());
        assert!(e.source().is_none());
    }

    #[test]
    fn error_wraps_source() {
        let io = std::io::Error::other("disk gone");
        let e = Error::io(Module::Pcap, io);
        assert_eq!(e.module(), Module::Pcap);
        assert_eq!(e.code(), ErrorCode::Io);
        assert!(!e.is_recoverable());
        assert!(e.source().is_some());
    }

    #[test]
    fn display_format() {
        let e = Error::parse(Module::Tls, "alert received");
        let s = format!("{e}");
        assert!(s.contains("tls"));
        assert!(s.contains("parse"));
        assert!(s.contains("alert received"));
    }

    #[test]
    fn send_sync_static() {
        fn assert_traits<T: Send + Sync + 'static>() {}
        assert_traits::<Error>();
    }

    #[test]
    fn source_chain_walks() {
        use std::error::Error as _;
        let io = std::io::Error::other("disk gone");
        let e = Error::io(Module::Pcap, io);
        let s = e.source().unwrap();
        assert!(format!("{s}").contains("disk gone"));
    }

    #[test]
    fn buffer_overflow_includes_cap() {
        let e = Error::buffer_overflow(Module::Http, 8192);
        assert!(e.to_string().contains("8192"));
    }

    #[test]
    fn module_display_covers_all_variants() {
        // Plan 131: new variants render as snake_case slugs.
        assert_eq!(Module::Driver.to_string(), "driver");
        assert_eq!(Module::Emit.to_string(), "emit");
        assert_eq!(Module::Detect.to_string(), "detect");
        assert_eq!(Module::Aggregate.to_string(), "aggregate");
        assert_eq!(Module::Correlate.to_string(), "correlate");
        // Pre-existing variants unchanged.
        assert_eq!(Module::Http.to_string(), "http");
        assert_eq!(Module::Layers.to_string(), "layers");
    }
}

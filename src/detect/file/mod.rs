//! `flowscope::detect::file` — streaming-hash sinks for
//! reassembled payload windows, plus a `FileType` enum that
//! classifies the first ~64 bytes via magic-byte detection.
//!
//! Behind the `file-hash` Cargo feature.
//!
//! New in 0.12.0 (plan 146).
//!
//! The DFIR / IR consumer ask: "what files crossed the wire and
//! what were their hashes?" — *without* storing the file bytes
//! themselves. Suricata's `file_md5` / `file_sha256` keywords
//! cover the same recipe; flowscope ships the equivalent as a
//! consumer-driven sink trait.
//!
//! Out of scope:
//! - File extraction / storage. Hashes only.
//! - YARA / AV matching. Bring your own.
//! - Streaming decompression (gzip / br / zstd). Hashes are over
//!   raw on-wire bytes.

mod md5;
mod sha256;
mod types;

pub use md5::Md5Sink;
pub use sha256::Sha256Sink;
pub use types::{FileHashEvent, FileType};

/// Trait for streaming-hash sinks attached to a reassembled
/// payload window or a session-parser body channel.
///
/// One sink per (flow, direction) typically. Construction is
/// consumer-driven; flowscope ships [`Sha256Sink`] and
/// [`Md5Sink`].
pub trait FileHashSink {
    /// Hash algorithm name (e.g. `"sha256"`, `"md5"`). Stable
    /// snake_case identifier suitable for log / emit fields.
    fn algorithm(&self) -> &'static str;

    /// Feed payload bytes. Cheap — typically one `update` call
    /// per reassembler drain.
    fn update(&mut self, bytes: &[u8]);

    /// Finalize: drain current hash + MIME classification,
    /// reset the sink for the next payload window.
    fn finish(&mut self) -> FileHashEvent;

    /// Total bytes hashed since last `finish()`.
    fn bytes_hashed(&self) -> u64;
}

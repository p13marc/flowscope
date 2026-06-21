//! `flowscope::nprint` — nPrint (CCS 2021) per-packet header-bit
//! matrix for model-agnostic ML pipelines.
//!
//! Gated by the `ml-features-nprint` Cargo feature. Issue #30.
//!
//! ## What ships
//!
//! [`NPrintMatrix`] is an append-only bounded matrix of
//! [`NPrintRow`]s, one per packet observed in the flow. Each row
//! is a ternary vector — `-1` (absent), `0`, `1` — encoding a
//! per-header-bit representation of the packet:
//!
//! - **Ethernet** — 14 bytes (112 bits): dst_mac + src_mac +
//!   ethertype.
//! - **IPv4 base header** — 20 bytes (160 bits). IPv4 options
//!   are NOT encoded in this release.
//! - **TCP base header** — 20 bytes (160 bits). TCP options
//!   absent / unparsed → encoded as `-1` placeholders only when
//!   the row is allocated with `with_tcp_options(true)`.
//! - **UDP** — 8 bytes (64 bits).
//!
//! When a layer is absent the corresponding region is filled
//! with `-1`s; when present the bits are extracted MSB-first
//! per byte.
//!
//! The per-row width is fixed at construction time via
//! [`NPrintConfig`] so all rows in the same matrix have the
//! same shape (a hard requirement for ML downstream).
//!
//! ## Why opt-in
//!
//! Per-packet storage is non-trivial. With 100 packets per flow
//! and a row of 14+20+20 = 54 bytes = 432 bits per row stored
//! as `Vec<NPrintBit>` (one byte per bit), the per-flow cost is
//! ~43 KiB. The aggregated stats in [`crate::ml_features`] are
//! O(1) per flow.
//!
//! ## Reference
//!
//! - <https://nprint.github.io/papers/nprint-ccs21.pdf>
//! - <https://github.com/nprint/nprint>
//!
//! ## Example
//!
//! ```no_run
//! # #[cfg(all(feature = "ml-features-nprint", feature = "extractors"))]
//! # fn _ex(view: flowscope::PacketView<'_>) {
//! use flowscope::nprint::{NPrintConfig, NPrintMatrix};
//!
//! let cfg = NPrintConfig::default();
//! let mut m = NPrintMatrix::new(cfg);
//! m.push_view(&view);
//! assert_eq!(m.rows().len(), 1);
//! # }
//! ```

mod matrix;
mod row;

pub use matrix::{NPrintConfig, NPrintMatrix};
pub use row::{NPrintBit, NPrintRow, bits_per_row};

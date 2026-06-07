//! `flowscope::aggregate` — distribution / quantile primitives.
//!
//! Two small types every observability example reinvents:
//!
//! - [`Histogram`] — explicit-bucket counter with `record` /
//!   `quantile` / `merge`. For "distribution of X" reports (flow
//!   durations, packet sizes, response times).
//! - [`Percentile`] — t-digest-style streaming quantile estimator
//!   for unbounded streams. Wraps the `tdigest` crate.
//!
//! Use [`Histogram`] when you know the buckets up front and want
//! exact counts per bucket. Use [`Percentile`] for unbounded
//! streams where memorising every sample isn't feasible and you
//! only need quantile reads at the tail (p95, p99, p999).
//!
//! ```
//! use flowscope::aggregate::Histogram;
//!
//! // Flow-duration buckets in seconds, log-spaced 100 ms → 1 h.
//! let mut h = Histogram::log_spaced(0.1, 3600.0, 6);
//! for d in [0.5, 1.2, 8.0, 45.0, 200.0] {
//!     h.record(d);
//! }
//! assert_eq!(h.samples(), 5);
//! let _p95 = h.quantile(0.95);
//! ```
//!
//! New in 0.10.0 (plan 102 sub-B).

mod histogram;
mod percentile;

pub use histogram::{Histogram, HistogramError};
pub use percentile::Percentile;

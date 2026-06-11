//! `flowscope::detect::patterns` — named, parameter-tuned
//! detectors that package the existing `correlate` + `detect`
//! primitives as canonical FAQ recipes.
//!
//! Each detector returns a typed **score** — not a verdict — so
//! consumers keep policy. Algorithm references are pinned in the
//! per-detector module docs and in `docs/detect-patterns.md`.
//!
//! New in 0.12.0 (plan 143).
//!
//! - [`PortScanDetector`] — per-source scanner-likelihood via
//!   Threshold Random Walk (Jung et al., IEEE S&P 2004).
//! - [`BeaconDetector`] — periodicity scoring via
//!   coefficient-of-variation on inter-arrival times, with a
//!   RITA-style composite score on bytes consistency.
//! - [`DgaScorer`] — DGA likelihood via bigram log-likelihood
//!   over a small embedded English-baseline table; auxiliary
//!   features (length, vowel ratio, digit ratio,
//!   consonant-run, entropy) for composite scoring.

pub mod beacon;
pub mod dga;
pub mod portscan;

pub use beacon::{BeaconDetector, BeaconScore};
pub use dga::{DgaScore, DgaScorer};
pub use portscan::{PortScanDetector, ScanScore, ScanVerdict};

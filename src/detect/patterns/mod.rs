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
//! - [`RitaBeaconDetector`] — robust periodicity scoring via
//!   Bowley skewness + median absolute deviation (RITA v5
//!   `analysis/beacons.go`); survives outliers (a missed beacon /
//!   retransmit) where the CV detector craters — better for
//!   jittered C2.
//! - [`DgaScorer`] — DGA likelihood via bigram log-likelihood
//!   over a small embedded English-baseline table; auxiliary
//!   features (length, vowel ratio, digit ratio,
//!   consonant-run, entropy) for composite scoring.

pub mod beacon;
pub mod dga;
pub mod portscan;
pub mod rita_beacon;

// Issue #132 — upstreamed NDR detectors on the unified `Detector`
// trait. Gated on `tracker` (they build on `correlate` primitives).
#[cfg(feature = "tracker")]
pub mod conn_flood;
#[cfg(feature = "tracker")]
pub mod data_exfil;
#[cfg(feature = "tracker")]
pub mod dns_tunnel;
#[cfg(feature = "tracker")]
pub mod nod;

pub use beacon::{BeaconDetector, BeaconScore};
pub use dga::{DgaScore, DgaScorer};
pub use portscan::{PortScanDetector, ScanScore, ScanVerdict};
pub use rita_beacon::{RitaBeaconDetector, RitaBeaconScore};

#[cfg(feature = "tracker")]
pub use conn_flood::{ConnectionFloodDetector, FloodScore};
#[cfg(feature = "tracker")]
pub use data_exfil::{DataExfilDetector, ExfilScore};
#[cfg(feature = "tracker")]
pub use dns_tunnel::{DnsTunnelDetector, DnsTunnelScore};
#[cfg(feature = "tracker")]
pub use nod::{NewlyObservedDomainDetector, NodScore};

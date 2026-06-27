//! `flowscope::analysis` — the opt-in composition layer that turns
//! parser output into enriched, SIEM-ready flow records.
//!
//! flowscope's `detect` primitives ([`FlowRisk`](crate::detect::FlowRisk),
//! [`IocSet`](crate::detect::IocSet), the fingerprints) are
//! decoupled by design — none of them are wired to the flow
//! lifecycle. This module is the **wiring**: feed it the parser
//! messages you already produce, and on flow end it hands back an
//! [`AnalyzedFlow`] bundling the 5-tuple, the
//! [`FlowStats`](crate::FlowStats), a curated [`L7Summary`], the
//! computed [`FlowRisk`](crate::detect::FlowRisk), and any
//! threat-intel [`IocMatch`](crate::detect::IocMatch) hits — so a
//! consumer doesn't re-implement risk/IOC/L7 correlation for the
//! Nth time.
//!
//! It stays true to the project's principles: runtime-free,
//! bounded memory ([`FlowAnalyzer::with_capacity`] + TTL eviction),
//! a pure composition layer over the existing parsers (not baked
//! into the core tracker), and **features/scores, not verdicts**
//! ([`AnalyzedFlow`] reports `FlowRisk` + IOC hits; the
//! malicious/benign call stays app-side).
//!
//! ```no_run
//! use std::time::Duration;
//! use flowscope::analysis::FlowAnalyzer;
//! use flowscope::detect::IocSet;
//! use flowscope::extract::FiveTupleKey;
//!
//! let mut ioc = IocSet::new();
//! ioc.insert(flowscope::detect::IocKind::Domain, "evil.example", Some(90), None);
//!
//! let mut analyzer =
//!     FlowAnalyzer::<FiveTupleKey>::with_capacity(Duration::from_secs(120), 100_000)
//!         .with_ioc(ioc);
//!
//! // … per flow: analyzer.observe_tls(&key, &handshake, ts); …
//! // on the flow's Ended event:
//! //   let record = analyzer.finalize(&key, stats);
//! //   if !record.is_clean() { ship(record); }
//! ```
//!
//! Issue #83.

mod analyzed_flow;
mod analyzer;
mod summary;

pub use analyzed_flow::AnalyzedFlow;
pub use analyzer::FlowAnalyzer;
pub use summary::{L7Summary, MAX_DNS_QUERIES};

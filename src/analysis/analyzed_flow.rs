//! [`AnalyzedFlow`] — the enriched, SIEM-ready flow record.
//!
//! The composition of everything flowscope knows about a finished
//! flow in one value: the flow key, the volumetric
//! [`FlowStats`](crate::FlowStats), the curated
//! [`L7Summary`](crate::analysis::L7Summary) of observed L7 facts,
//! the computed [`FlowRisk`](crate::detect::FlowRisk), and any
//! threat-intel [`IocMatch`](crate::detect::IocMatch) hits.
//!
//! Produced by [`FlowAnalyzer::finalize`](crate::analysis::FlowAnalyzer::finalize)
//! on flow end. This is the record a monitor logs / ships — no
//! consumer-side re-plumbing of risk + IOC + L7 correlation
//! required.

use crate::FlowStats;
use crate::analysis::L7Summary;
use crate::detect::{FlowRisk, IocMatch, RiskSeverity};

/// An enriched flow record: 5-tuple + stats + L7 summary +
/// computed risk + IOC hits.
///
/// Generic over the flow key `K`. `#[non_exhaustive]` — fields are
/// added additively; read via the public fields and the accessor
/// methods below.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AnalyzedFlow<K> {
    /// The flow key (typically [`crate::extract::FiveTupleKey`]).
    pub key: K,
    /// Volumetric + timing stats for the flow.
    pub stats: FlowStats,
    /// Curated L7 facts observed over the flow's lifetime.
    pub l7: L7Summary,
    /// Risk flags computed from the key + L7 summary + IOC hits.
    pub risk: FlowRisk,
    /// Threat-intel indicator hits (IP / domain / fingerprint).
    pub ioc_hits: Vec<IocMatch>,
}

impl<K> AnalyzedFlow<K> {
    /// `true` if the flow tripped no risk flags and matched no
    /// indicators — the "nothing to see here" fast path a monitor
    /// can use to skip cheap-but-not-free downstream emission.
    pub fn is_clean(&self) -> bool {
        self.risk.is_empty() && self.ioc_hits.is_empty()
    }

    /// The highest risk severity on the flow, or `None` when no
    /// risk flags are set. IOC hits do not carry a severity of
    /// their own — inspect [`Self::ioc_hits`] for those.
    pub fn severity(&self) -> Option<RiskSeverity> {
        self.risk.max_severity()
    }

    /// The aggregate nDPI-style risk score (sum of per-flag
    /// scores). `0` when no flags are set.
    pub fn score(&self) -> u16 {
        self.risk.score()
    }

    /// `true` if any threat-intel indicator matched.
    pub fn has_ioc(&self) -> bool {
        !self.ioc_hits.is_empty()
    }
}

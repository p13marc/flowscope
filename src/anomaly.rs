//! Canonical owned anomaly value type for detector-shaped
//! emission and retention.
//!
//! [`OwnedAnomaly`] is the shape produced by detectors (port-scan,
//! beacon, DGA, …) and consumed by emit sinks (EVE JSON, NDJSON).
//! Use it when:
//!
//! - A detector's `kind` is a slug (not a flowscope [`AnomalyKind`]
//!   variant) — typical for downstream-defined detectors.
//! - You need a serialisable value to retain past the event-loop
//!   frame (channels, batch writers, cross-process pipelines).
//! - You want a uniform emit path across multiple sinks.
//!
//! Use [`crate::FlowEvent::FlowAnomaly`] / [`crate::FlowEvent::TrackerAnomaly`]
//! when the kind IS a typed [`AnomalyKind`] (tracker-emitted
//! stream / parser anomalies). Bridge between the two with
//! [`OwnedAnomaly::from_flow_anomaly`].
//!
//! # Strongly-typed shape, allocation-frugal
//!
//! The struct backs `observations` and `metrics` with
//! [`smallvec::SmallVec<[_; 4]>`] — the typical detector
//! produces 2-5 of each, so zero heap allocations for the hot
//! construction path. Labels are `&'static str` (compile-time
//! constants); values use [`Cow<'static, str>`] so static
//! literals stay zero-alloc while runtime-built strings just
//! work via `into()`.
//!
//! # Wire stability
//!
//! Wire-stable from 0.13 forward under `#[non_exhaustive]` —
//! field additions are non-breaking. Behind the `serde` feature
//! the struct implements `Serialize` + `Deserialize`, suitable
//! for cross-process retention.

use std::borrow::Cow;
use std::net::IpAddr;

use smallvec::SmallVec;

use crate::Timestamp;
use crate::anomaly_fields::KeyFields;
use crate::event::{AnomalyKind, Severity};

/// Canonical owned anomaly value.
///
/// See the [module-level docs](self) for usage. Construct via
/// [`OwnedAnomaly::new`] + the `with_*` builder methods, or via
/// [`OwnedAnomaly::from_flow_anomaly`] to bridge a flowscope-
/// internal typed event.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct OwnedAnomaly {
    /// Detector / classification slug.
    ///
    /// `&'static str` literals stay zero-alloc;
    /// runtime-built slugs land in the owned variant. Typical
    /// values: `"PortScanTRW"`, `"BeaconCv"`, `"DgaScorer"`,
    /// downstream-defined detector names.
    pub kind: Cow<'static, str>,

    /// Severity tier. Drives downstream log / metric / alert
    /// routing.
    pub severity: Severity,

    /// Event timestamp.
    pub ts: Timestamp,

    /// 5-tuple-derived top-level fields. Each field independent
    /// — `None` if the source key returned `None` for it.
    /// Populate via [`Self::with_key`] from any [`KeyFields`]
    /// impl, or set directly.
    pub src_ip: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dest_ip: Option<IpAddr>,
    pub dest_port: Option<u16>,
    pub proto: Option<&'static str>,

    /// Free-form `(label, value)` observations. Labels are
    /// `&'static str` (compile-time constants); values use
    /// `Cow<'static, str>`. Typical detector output has 2-5
    /// observations, well under the `SmallVec` inline threshold
    /// — no heap allocation on the construction hot path.
    pub observations: SmallVec<[(&'static str, Cow<'static, str>); 4]>,

    /// `(label, value)` numeric metrics. `f64` covers integers,
    /// rates, ratios, durations-in-seconds uniformly.
    pub metrics: SmallVec<[(&'static str, f64); 4]>,

    /// Set when this anomaly bridges a flowscope-internal typed
    /// event into the owned shape (via
    /// [`Self::from_flow_anomaly`]). Retained for downstream
    /// typed-bridge consumers; `None` for detector-originated
    /// anomalies.
    pub flowscope_kind: Option<AnomalyKind>,
}

impl OwnedAnomaly {
    /// Construct with the given slug, severity, and timestamp.
    /// All other fields default to empty / `None`.
    pub fn new(kind: impl Into<Cow<'static, str>>, severity: Severity, ts: Timestamp) -> Self {
        Self {
            kind: kind.into(),
            severity,
            ts,
            src_ip: None,
            src_port: None,
            dest_ip: None,
            dest_port: None,
            proto: None,
            observations: SmallVec::new(),
            metrics: SmallVec::new(),
            flowscope_kind: None,
        }
    }

    /// Populate 5-tuple fields from any [`KeyFields`] impl. Each
    /// field independently `None` if the key returns `None` for
    /// it.
    pub fn with_key<K: KeyFields + ?Sized>(mut self, key: &K) -> Self {
        self.src_ip = key.src_ip();
        self.src_port = key.src_port();
        self.dest_ip = key.dest_ip();
        self.dest_port = key.dest_port();
        if let Some(p) = key.proto_str() {
            self.proto = Some(p);
        }
        self
    }

    /// Append a `(label, value)` observation. Label is a
    /// `&'static str` (compile-time constant); value can be a
    /// `&'static str` literal or a runtime `String` via `into()`.
    pub fn with_observation(
        mut self,
        label: &'static str,
        value: impl Into<Cow<'static, str>>,
    ) -> Self {
        self.observations.push((label, value.into()));
        self
    }

    /// Append a `(label, value)` numeric metric.
    pub fn with_metric(mut self, label: &'static str, value: f64) -> Self {
        self.metrics.push((label, value));
        self
    }

    /// Bridge a flowscope-internal `FlowAnomaly` /
    /// `TrackerAnomaly` event into the owned shape. Retains the
    /// typed `AnomalyKind` in `flowscope_kind` for downstream
    /// typed-bridge consumers.
    ///
    /// The owned anomaly's `kind` slug comes from the typed
    /// kind's `short_kind()` (e.g. `"buffer_overflow"`,
    /// `"ooo_segment"`); `severity` comes from
    /// `AnomalyKind::severity`.
    pub fn from_flow_anomaly<K: KeyFields>(key: &K, kind: AnomalyKind, ts: Timestamp) -> Self {
        let slug = kind.short_kind();
        let severity = kind.severity();
        Self {
            kind: Cow::Borrowed(slug),
            severity,
            ts,
            src_ip: key.src_ip(),
            src_port: key.src_port(),
            dest_ip: key.dest_ip(),
            dest_port: key.dest_port(),
            proto: key.proto_str(),
            observations: SmallVec::new(),
            metrics: SmallVec::new(),
            flowscope_kind: Some(kind),
        }
    }
}

/// Output-side conversion for detector scores.
///
/// Implemented by each shipped detector's score type:
/// - [`crate::detect::patterns::ScanScore<K>`] →
///   `"PortScanTRW"`
/// - [`crate::detect::patterns::BeaconScore<K>`] →
///   `"BeaconCv"`
/// - [`crate::detect::patterns::DgaScore`] →
///   `"DgaScorer"`
///
/// Provides a uniform `score → anomaly → sink` routing path
/// without trying to unify the heterogeneous detector input
/// surfaces (which are genuinely different — `(K, bool)` for
/// port-scan, `(K, ts, bytes)` for beacon, `&str` for DGA).
/// Per-detector dispatch stays per-detector; uniformity lives
/// here on the output side.
///
/// Custom detectors implement this on their own score types
/// for the same uniform routing.
pub trait DetectorScore {
    /// Stable detector name slug. Used as `OwnedAnomaly::kind`
    /// (which maps to EVE `anomaly.event`) and as a metric label.
    fn name(&self) -> &'static str;

    /// Convert into the canonical owned anomaly with the given
    /// timestamp.
    ///
    /// Consuming the score keeps the conversion zero-copy when
    /// the score holds owned data (e.g., a `String` SNI or a
    /// `Bytes`). Detectors that want to emit multiple anomalies
    /// from the same score (rare) clone first.
    fn into_anomaly(self, ts: Timestamp) -> OwnedAnomaly;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Severity;

    #[test]
    fn new_default_fields_are_empty() {
        let a = OwnedAnomaly::new("Test", Severity::Info, Timestamp::new(100, 0));
        assert_eq!(a.kind, "Test");
        assert_eq!(a.severity, Severity::Info);
        assert!(a.src_ip.is_none());
        assert!(a.observations.is_empty());
        assert!(a.metrics.is_empty());
        assert!(a.flowscope_kind.is_none());
    }

    #[test]
    fn smallvec_observations_stay_inline_under_4() {
        let a = OwnedAnomaly::new("Test", Severity::Info, Timestamp::new(0, 0))
            .with_observation("a", "1")
            .with_observation("b", "2")
            .with_observation("c", "3")
            .with_observation("d", "4");
        assert_eq!(a.observations.len(), 4);
        assert!(!a.observations.spilled(), "4 observations stay inline");
    }

    #[test]
    fn smallvec_observations_spill_above_4() {
        let mut a = OwnedAnomaly::new("Test", Severity::Info, Timestamp::new(0, 0));
        for i in 0..6 {
            // Use a known-static label; the spillage matters, not the label content.
            a.observations.push(("test_label", Cow::Owned(format!("{i}"))));
        }
        assert_eq!(a.observations.len(), 6);
        assert!(a.observations.spilled(), "6 observations spill to heap");
    }

    #[test]
    fn with_metric_appends() {
        let a = OwnedAnomaly::new("Test", Severity::Info, Timestamp::new(0, 0))
            .with_metric("score", 0.87)
            .with_metric("n_observed", 42.0);
        assert_eq!(a.metrics.len(), 2);
        assert_eq!(a.metrics[0], ("score", 0.87));
        assert_eq!(a.metrics[1], ("n_observed", 42.0));
    }

    #[cfg(feature = "extractors")]
    #[test]
    fn with_key_flattens_5tuple_from_fivetuple_key() {
        use crate::extract::FiveTupleKey;
        use crate::extractor::L4Proto;
        use std::net::{Ipv4Addr, SocketAddr};
        let key = FiveTupleKey {
            proto: L4Proto::Tcp,
            a: SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 33000)),
            b: SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 80)),
        };
        let a = OwnedAnomaly::new("Test", Severity::Info, Timestamp::new(0, 0)).with_key(&key);
        assert_eq!(a.src_ip, Some(IpAddr::from(Ipv4Addr::new(10, 0, 0, 1))));
        assert_eq!(a.src_port, Some(33000));
        assert_eq!(a.dest_ip, Some(IpAddr::from(Ipv4Addr::new(10, 0, 0, 2))));
        assert_eq!(a.dest_port, Some(80));
        assert_eq!(a.proto, Some("TCP"));
    }

    #[cfg(feature = "extractors")]
    #[test]
    fn from_flow_anomaly_retains_typed_kind() {
        use crate::event::{AnomalyKind, FlowSide};
        use crate::extract::FiveTupleKey;
        use crate::extractor::L4Proto;
        use std::net::{Ipv4Addr, SocketAddr};
        let key = FiveTupleKey {
            proto: L4Proto::Tcp,
            a: SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 33000)),
            b: SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 80)),
        };
        let kind = AnomalyKind::OutOfOrderSegment {
            side: FlowSide::Initiator,
            count: 3,
        };
        let a = OwnedAnomaly::from_flow_anomaly(&key, kind.clone(), Timestamp::new(0, 0));
        assert_eq!(a.kind, "ooo_segment");
        assert!(matches!(
            a.flowscope_kind,
            Some(AnomalyKind::OutOfOrderSegment { count: 3, .. })
        ));
        assert_eq!(a.src_ip, Some(IpAddr::from(Ipv4Addr::new(10, 0, 0, 1))));
    }
}

//! [`DetectorKind`] — typed detector identity.
//!
//! Replaces the stringly-typed detector slug that
//! [`crate::OwnedAnomaly`] carried through 0.20 (`kind:
//! Cow<'static, str>`) and that [`crate::DetectorScore::kind`]
//! (formerly `name()`) returned. Landed in 0.21 (issue #133) as
//! the detection-side sibling of [`crate::ParserKind`] (0.20,
//! #109): routing on the enum at sink / emit / consumer sites is
//! compile-checked — typos fail to resolve, and `match` arms
//! enforce exhaustiveness against the standard variants.
//!
//! The enum is `#[non_exhaustive]` and includes an
//! `Other(&'static str)` variant so downstream crates can register
//! their own detector kinds without flowscope code changes.
//!
//! # ATT&CK technique mapping
//!
//! Each built-in variant optionally maps to a stable MITRE ATT&CK
//! technique ID via [`attack_technique`](DetectorKind::attack_technique),
//! so the technique tag travels with the anomaly instead of every
//! consumer maintaining its own slug → technique table. Technique
//! IDs (`Txxxx` / `Txxxx.yyy`) are the stable ATT&CK identifiers —
//! ATT&CK v18 (Oct 2025) deprecated Data Source objects in favour
//! of Detection Strategies, but technique IDs are unaffected.

/// Which detector produced an anomaly.
///
/// Built-in variants cover every detector shipped in
/// [`crate::detect::patterns`]. Downstream crates register their
/// own kinds via [`Self::Other`].
///
/// `#[non_exhaustive]` — future detectors will add variants;
/// matching on this enum should always include a wildcard arm.
/// Serializes as its [`as_str`](Self::as_str) slug — a plain JSON
/// string (e.g. `"BeaconCv"`), not a tagged object — so the
/// `kind` field in emitted anomalies matches the pre-0.21
/// `Cow<'static, str>` wire shape byte-for-byte. Deserializes a
/// slug back via [`from_slug`](Self::from_slug): built-in slugs
/// round-trip to their variant; an unrecognised slug (including a
/// downstream [`Other`](Self::Other) label) deserializes to
/// [`Unknown`](Self::Unknown) — it cannot rebuild the
/// `&'static str` an `Other` needs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DetectorKind {
    /// Coefficient-of-variation beacon detector
    /// ([`crate::detect::patterns::BeaconDetector`]).
    BeaconCv,
    /// RITA-style robust beacon detector (Bowley skewness + MADM;
    /// [`crate::detect::patterns::RitaBeaconDetector`]).
    BeaconRita,
    /// Threshold Random Walk port-scan detector
    /// ([`crate::detect::patterns::PortScanDetector`]).
    PortScanTrw,
    /// DGA domain scorer
    /// ([`crate::detect::patterns::DgaScorer`]).
    Dga,
    /// DNS tunneling detector — distinct-subdomain cardinality
    /// (`DnsTunnelDetector`, issue #132).
    DnsTunnel,
    /// Newly-observed-domain detector — bounded first-seen set
    /// (`NewlyObservedDomainDetector`, issue #132).
    NewlyObservedDomain,
    /// Per-source connection-rate flood detector
    /// (`ConnectionFloodDetector`, issue #132).
    ConnectionFlood,
    /// EWMA-variance outbound-volume exfiltration detector
    /// (`DataExfilDetector`, issue #132).
    DataExfil,
    /// Downstream-registered detector kind. The `&'static str`
    /// label should be a unique stable slug — typical convention
    /// is `"crate-name/detector"` (e.g. `"zensight/sigma"`).
    Other(&'static str),
    /// Detector identity unknown — the deserialization fallback
    /// for unrecognised slugs (an [`Other`](Self::Other) can't be
    /// rebuilt from a runtime string). Also the `Default`.
    #[default]
    Unknown,
}

impl DetectorKind {
    /// Stable slug — same vocabulary the 0.20-and-earlier
    /// `OwnedAnomaly::kind` string carried. Use for metric labels
    /// and JSON emission (EVE `anomaly.event`, NDJSON `kind`).
    ///
    /// Each built-in variant maps to the slug its detector
    /// historically emitted (`BeaconCv` → `"BeaconCv"`,
    /// `PortScanTrw` → `"PortScanTRW"`, `Dga` → `"DgaScorer"`, …);
    /// the full mapping is regression-pinned by
    /// `slug_vocabulary_locked`. [`Self::Other`] yields its wrapped
    /// caller-supplied slug; [`Self::Unknown`] yields `"unknown"`.
    /// [`from_slug`](Self::from_slug) is the inverse.
    pub fn as_str(&self) -> &'static str {
        match self {
            DetectorKind::BeaconCv => "BeaconCv",
            DetectorKind::BeaconRita => "BeaconRita",
            DetectorKind::PortScanTrw => "PortScanTRW",
            // Historic slug from the 0.12-era `DetectorScore::name()`
            // impl — kept for wire compatibility.
            DetectorKind::Dga => "DgaScorer",
            DetectorKind::DnsTunnel => "DnsTunnel",
            DetectorKind::NewlyObservedDomain => "NewlyObservedDomain",
            DetectorKind::ConnectionFlood => "ConnectionFlood",
            DetectorKind::DataExfil => "DataExfil",
            DetectorKind::Other(s) => s,
            DetectorKind::Unknown => "unknown",
        }
    }

    /// Inverse of [`as_str`](Self::as_str) for the built-in slugs.
    ///
    /// A recognised built-in slug maps to its variant; any other
    /// string maps to [`Unknown`](Self::Unknown) (it can't become
    /// an [`Other`](Self::Other) — that variant needs a
    /// `&'static str`, which a runtime string isn't). Used by the
    /// `Deserialize` impl.
    pub fn from_slug(s: &str) -> DetectorKind {
        match s {
            "BeaconCv" => DetectorKind::BeaconCv,
            "BeaconRita" => DetectorKind::BeaconRita,
            "PortScanTRW" => DetectorKind::PortScanTrw,
            "DgaScorer" => DetectorKind::Dga,
            "DnsTunnel" => DetectorKind::DnsTunnel,
            "NewlyObservedDomain" => DetectorKind::NewlyObservedDomain,
            "ConnectionFlood" => DetectorKind::ConnectionFlood,
            "DataExfil" => DetectorKind::DataExfil,
            _ => DetectorKind::Unknown,
        }
    }

    /// MITRE ATT&CK technique ID for the behaviour this detector
    /// flags, in the stable `Txxxx` / `Txxxx.yyy` form, or `None`
    /// when no single technique applies ([`Other`](Self::Other) /
    /// [`Unknown`](Self::Unknown)).
    ///
    /// Mapping rationale:
    ///
    /// - Beaconing → [T1071] *Application Layer Protocol* (the C2
    ///   channel protocol is unknown at detection time, so the
    ///   parent technique — not a sub-technique — applies).
    /// - Port scan → [T1046] *Network Service Discovery*.
    /// - DGA → [T1568.002] *Dynamic Resolution: Domain Generation
    ///   Algorithms*.
    /// - DNS tunnel → [T1071.004] *Application Layer Protocol:
    ///   DNS*.
    /// - Newly-observed domain → [T1568] *Dynamic Resolution*
    ///   (NOD is the defender-observable signal of dynamic
    ///   resolution infrastructure; T1583.001 covers adversary
    ///   *acquisition*, which passive capture can't see).
    /// - Connection flood → [T1498] *Network Denial of Service*
    ///   (rate-shaped; *scan*-shaped fan-out is
    ///   [`PortScanTrw`](Self::PortScanTrw)'s T1046).
    /// - Data exfil → [T1048] *Exfiltration Over Alternative
    ///   Protocol* (the RITA / AC-Hunter N-sigma outbound-volume
    ///   precedent; T1030 *Data Transfer Size Limits* is the
    ///   adversary's evasion of exactly this detector — wrong
    ///   axis).
    ///
    /// [T1071]: https://attack.mitre.org/techniques/T1071/
    /// [T1046]: https://attack.mitre.org/techniques/T1046/
    /// [T1568.002]: https://attack.mitre.org/techniques/T1568/002/
    /// [T1071.004]: https://attack.mitre.org/techniques/T1071/004/
    /// [T1568]: https://attack.mitre.org/techniques/T1568/
    /// [T1498]: https://attack.mitre.org/techniques/T1498/
    /// [T1048]: https://attack.mitre.org/techniques/T1048/
    pub fn attack_technique(&self) -> Option<&'static str> {
        match self {
            DetectorKind::BeaconCv | DetectorKind::BeaconRita => Some("T1071"),
            DetectorKind::PortScanTrw => Some("T1046"),
            DetectorKind::Dga => Some("T1568.002"),
            DetectorKind::DnsTunnel => Some("T1071.004"),
            DetectorKind::NewlyObservedDomain => Some("T1568"),
            DetectorKind::ConnectionFlood => Some("T1498"),
            DetectorKind::DataExfil => Some("T1048"),
            DetectorKind::Other(_) | DetectorKind::Unknown => None,
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for DetectorKind {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for DetectorKind {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let slug = std::borrow::Cow::<'de, str>::deserialize(deserializer)?;
        Ok(DetectorKind::from_slug(&slug))
    }
}

impl std::fmt::Display for DetectorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_vocabulary_locked() {
        // Regression-pin the slugs — downstream EVE / NDJSON /
        // metric pipelines depend on these staying byte-identical
        // to the pre-0.21 string values.
        assert_eq!(DetectorKind::BeaconCv.as_str(), "BeaconCv");
        assert_eq!(DetectorKind::BeaconRita.as_str(), "BeaconRita");
        assert_eq!(DetectorKind::PortScanTrw.as_str(), "PortScanTRW");
        assert_eq!(DetectorKind::Dga.as_str(), "DgaScorer");
        assert_eq!(DetectorKind::DnsTunnel.as_str(), "DnsTunnel");
        assert_eq!(
            DetectorKind::NewlyObservedDomain.as_str(),
            "NewlyObservedDomain"
        );
        assert_eq!(DetectorKind::ConnectionFlood.as_str(), "ConnectionFlood");
        assert_eq!(DetectorKind::DataExfil.as_str(), "DataExfil");
        assert_eq!(DetectorKind::Unknown.as_str(), "unknown");
        assert_eq!(
            DetectorKind::Other("zensight/sigma").as_str(),
            "zensight/sigma"
        );
    }

    #[test]
    fn attack_technique_table_locked() {
        assert_eq!(DetectorKind::BeaconCv.attack_technique(), Some("T1071"));
        assert_eq!(DetectorKind::BeaconRita.attack_technique(), Some("T1071"));
        assert_eq!(DetectorKind::PortScanTrw.attack_technique(), Some("T1046"));
        assert_eq!(DetectorKind::Dga.attack_technique(), Some("T1568.002"));
        assert_eq!(
            DetectorKind::DnsTunnel.attack_technique(),
            Some("T1071.004")
        );
        assert_eq!(
            DetectorKind::NewlyObservedDomain.attack_technique(),
            Some("T1568")
        );
        assert_eq!(
            DetectorKind::ConnectionFlood.attack_technique(),
            Some("T1498")
        );
        assert_eq!(DetectorKind::DataExfil.attack_technique(), Some("T1048"));
        assert_eq!(DetectorKind::Other("custom").attack_technique(), None);
        assert_eq!(DetectorKind::Unknown.attack_technique(), None);
    }

    #[test]
    fn default_is_unknown() {
        assert_eq!(DetectorKind::default(), DetectorKind::Unknown);
    }

    #[test]
    fn display_uses_slug() {
        assert_eq!(DetectorKind::BeaconCv.to_string(), "BeaconCv");
        assert_eq!(DetectorKind::Other("custom").to_string(), "custom");
    }

    #[test]
    fn from_slug_round_trips_builtins() {
        for k in [
            DetectorKind::BeaconCv,
            DetectorKind::BeaconRita,
            DetectorKind::PortScanTrw,
            DetectorKind::Dga,
            DetectorKind::DnsTunnel,
            DetectorKind::NewlyObservedDomain,
            DetectorKind::ConnectionFlood,
            DetectorKind::DataExfil,
        ] {
            assert_eq!(DetectorKind::from_slug(k.as_str()), k);
        }
        // Unknown / downstream slug can't rebuild `Other` → Unknown.
        assert_eq!(
            DetectorKind::from_slug("zensight/sigma"),
            DetectorKind::Unknown
        );
        assert_eq!(DetectorKind::from_slug(""), DetectorKind::Unknown);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_is_a_plain_slug_string() {
        // Serializes as a bare string, not a tagged object — the
        // pre-0.21 wire shape.
        assert_eq!(
            serde_json::to_string(&DetectorKind::PortScanTrw).unwrap(),
            "\"PortScanTRW\""
        );
        assert_eq!(
            serde_json::to_string(&DetectorKind::Other("x")).unwrap(),
            "\"x\""
        );
        // Built-in slug round-trips; unknown → Unknown.
        let back: DetectorKind = serde_json::from_str("\"BeaconCv\"").unwrap();
        assert_eq!(back, DetectorKind::BeaconCv);
        let unknown: DetectorKind = serde_json::from_str("\"x\"").unwrap();
        assert_eq!(unknown, DetectorKind::Unknown);
    }
}

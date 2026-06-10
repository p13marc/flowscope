//! `AnomalyFields` trait — structured field access for emit
//! writers (EVE, NDJSON, custom).
//!
//! Lets writers pull typed accessors (`IpAddr`, `u16`,
//! `&'static str`) off a flow key + an [`crate::AnomalyKind`]
//! without going through `Debug` formatting. Default impls
//! on [`crate::extract::FiveTupleKey`], [`crate::L4Proto`], and
//! [`crate::AnomalyKind`] cover the most common cases;
//! consumers with custom keys implement the trait themselves.
//!
//! Plan 126 (0.12.0).

use std::net::IpAddr;

/// Structured access to flow-key / anomaly-kind fields for
/// emit writers.
///
/// All methods default to `None` so implementors override only
/// the fields they actually carry. Emit writers MUST tolerate
/// `None` returns — they correspond to "field not applicable
/// for this key type" (e.g. `src_port()` on an IP-only key).
///
/// # Implementing for custom keys
///
/// Custom [`crate::FlowExtractor::Key`] types should implement
/// this trait if they want to flow through EVE / NDJSON without
/// fallback `Debug` formatting:
///
/// ```
/// use std::net::IpAddr;
/// use flowscope::AnomalyFields;
///
/// struct MyKey { src: IpAddr, dst: IpAddr }
///
/// impl AnomalyFields for MyKey {
///     fn src_ip(&self) -> Option<IpAddr> { Some(self.src) }
///     fn dest_ip(&self) -> Option<IpAddr> { Some(self.dst) }
/// }
/// ```
pub trait AnomalyFields {
    /// Source IP for the flow.
    fn src_ip(&self) -> Option<IpAddr> {
        None
    }

    /// Source port (TCP/UDP).
    fn src_port(&self) -> Option<u16> {
        None
    }

    /// Destination IP for the flow.
    fn dest_ip(&self) -> Option<IpAddr> {
        None
    }

    /// Destination port (TCP/UDP).
    fn dest_port(&self) -> Option<u16> {
        None
    }

    /// L4 protocol as a static EVE-compatible label.
    fn proto_str(&self) -> Option<&'static str> {
        None
    }

    /// Application-layer protocol label, e.g. `"http"` /
    /// `"dns"` / `"tls"`. Default `None` — emit writers
    /// typically thread the `parser_kind` from
    /// [`crate::driver::SlotMessage`] instead. Override only on
    /// custom keys that carry app-layer hints natively.
    fn app_proto_str(&self) -> Option<&'static str> {
        None
    }

    /// EVE `anomaly.type` classification.
    ///
    /// Suricata schema:
    /// - `"stream"` — transport-layer state / reassembly anomalies
    /// - `"decode"` — frame-integrity anomalies
    /// - `"applayer"` — parser-driven application-layer anomalies
    ///
    /// Default `None` — only implemented on [`crate::AnomalyKind`].
    fn anomaly_type(&self) -> Option<&'static str> {
        None
    }

    /// EVE `anomaly.event` — the stable slug, e.g.
    /// `"ooo_segment"` or `"buffer_overflow"`. Default `None`;
    /// [`crate::AnomalyKind`] implements via `short_kind()`.
    fn anomaly_event(&self) -> Option<&'static str> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct CustomKey {
        src: IpAddr,
        dst: IpAddr,
    }

    impl AnomalyFields for CustomKey {
        fn src_ip(&self) -> Option<IpAddr> {
            Some(self.src)
        }
        fn dest_ip(&self) -> Option<IpAddr> {
            Some(self.dst)
        }
    }

    #[test]
    fn default_impls_return_none() {
        struct Empty;
        impl AnomalyFields for Empty {}
        let e = Empty;
        assert!(e.src_ip().is_none());
        assert!(e.src_port().is_none());
        assert!(e.dest_ip().is_none());
        assert!(e.dest_port().is_none());
        assert!(e.proto_str().is_none());
        assert!(e.app_proto_str().is_none());
        assert!(e.anomaly_type().is_none());
        assert!(e.anomaly_event().is_none());
    }

    #[test]
    fn custom_key_overrides_only_chosen_fields() {
        let k = CustomKey {
            src: "10.0.0.1".parse().unwrap(),
            dst: "10.0.0.2".parse().unwrap(),
        };
        assert_eq!(k.src_ip(), Some("10.0.0.1".parse().unwrap()));
        assert_eq!(k.dest_ip(), Some("10.0.0.2".parse().unwrap()));
        // Not overridden — defaults to None.
        assert!(k.src_port().is_none());
        assert!(k.proto_str().is_none());
    }
}

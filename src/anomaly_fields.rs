//! [`KeyFields`] + [`AnomalyFields`] — structured field access
//! for emit writers (EVE, NDJSON, CSV, Zeek, custom).
//!
//! Lets writers pull typed accessors (`IpAddr`, `u16`,
//! `&'static str`) off a flow key + an [`crate::AnomalyKind`]
//! without going through `Debug` formatting.
//!
//! Plan 126 introduced these as one trait; plan 130 (0.12.0)
//! split them along their natural cleavage so the type system
//! reflects what's a flow-key property vs an anomaly property:
//!
//! - [`KeyFields`] — 5-tuple / protocol accessors. Default
//!   impls on [`crate::extract::FiveTupleKey`] and
//!   [`crate::L4Proto`]. Implement for custom keys to make them
//!   work with every [`crate::emit`] writer.
//! - [`AnomalyFields`] — anomaly-classification accessors.
//!   Implemented on [`crate::AnomalyKind`].

use std::net::IpAddr;

/// Structured access to flow-key fields for emit writers.
///
/// All methods default to `None` so implementors override only
/// the fields they actually carry. Emit writers MUST tolerate
/// `None` returns — they correspond to "field not applicable
/// for this key type" (e.g. `src_port()` on an IP-only key).
///
/// # Implementing for custom keys
///
/// Custom [`crate::FlowExtractor::Key`] types should implement
/// this trait if they want to flow through CSV / NDJSON / Zeek /
/// EVE without fallback `Debug` formatting:
///
/// ```
/// use std::net::IpAddr;
/// use flowscope::KeyFields;
///
/// struct MyKey { src: IpAddr, dst: IpAddr }
///
/// impl KeyFields for MyKey {
///     fn src_ip(&self) -> Option<IpAddr> { Some(self.src) }
///     fn dest_ip(&self) -> Option<IpAddr> { Some(self.dst) }
/// }
/// ```
pub trait KeyFields {
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

    /// L4 protocol as a static EVE-compatible label
    /// (`"TCP"` / `"UDP"` / `"ICMP"` / `"ICMPv6"` / `"SCTP"`).
    fn proto_str(&self) -> Option<&'static str> {
        None
    }

    /// L4 protocol number per IANA assigned numbers
    /// (TCP=6, UDP=17, ICMP=1, ICMPv6=58, SCTP=132). Used by
    /// IPFIX-IE-keyed exporters that need the numeric ID
    /// alongside the [`Self::proto_str`] label. Default `None`
    /// — override on keys that carry an L4 protocol.
    ///
    /// Issue #16 — needed by the
    /// [`FlowRecord::from_key_fields`](crate::FlowRecord::from_key_fields)
    /// generic constructor so emit writers can unify the
    /// `write_event(FlowEnded)` → `write_flow_record` code path.
    fn protocol_identifier(&self) -> Option<u8> {
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
}

/// Anomaly classification accessor — implemented on
/// [`crate::AnomalyKind`] in this crate. Consumers writing
/// alert-shaped emit writers (EVE, future Suricata-shaped
/// outputs) constrain on this trait separately from
/// [`KeyFields`].
pub trait AnomalyFields {
    /// EVE `anomaly.type` classification.
    ///
    /// Suricata schema:
    /// - `"stream"` — transport-layer state / reassembly anomalies
    /// - `"decode"` — frame-integrity anomalies
    /// - `"applayer"` — parser-driven application-layer anomalies
    fn anomaly_type(&self) -> Option<&'static str> {
        None
    }

    /// EVE `anomaly.event` — the stable slug, e.g.
    /// `"ooo_segment"` or `"buffer_overflow"`.
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

    impl KeyFields for CustomKey {
        fn src_ip(&self) -> Option<IpAddr> {
            Some(self.src)
        }
        fn dest_ip(&self) -> Option<IpAddr> {
            Some(self.dst)
        }
    }

    #[test]
    fn key_fields_default_impls_return_none() {
        struct Empty;
        impl KeyFields for Empty {}
        let e = Empty;
        assert!(e.src_ip().is_none());
        assert!(e.src_port().is_none());
        assert!(e.dest_ip().is_none());
        assert!(e.dest_port().is_none());
        assert!(e.proto_str().is_none());
        assert!(e.app_proto_str().is_none());
    }

    #[test]
    fn anomaly_fields_default_impls_return_none() {
        struct Empty;
        impl AnomalyFields for Empty {}
        let e = Empty;
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

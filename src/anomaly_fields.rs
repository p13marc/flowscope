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
    /// `write_event(Ended)` → `write_flow_record` code path.
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

    /// Stable, **seed-fixed** 64-bit hash over the canonical
    /// (direction-normalized) 5-tuple.
    ///
    /// Unlike a `#[derive(Hash)]` run through `RandomState` (a
    /// per-process random seed), this is **reproducible across
    /// threads and processes** — the property required for
    /// sharding a merged flow table so both legs of a flow always
    /// land on the same worker (see [`Self::shard_index`]). A→B
    /// and B→A produce the same value.
    ///
    /// Returns `None` if any of (proto, src ip/port, dest ip/port)
    /// is unknown. The algorithm is FNV-1a. This is a fast,
    /// **non-portable** in-process identifier — it is *not* emitted by
    /// the EVE / NDJSON writers (which lead with the portable
    /// [`community_id`](Self::community_id) since 0.19, issue #88). Use
    /// it for sharding / in-memory keying, not for cross-tool pivots.
    ///
    /// Issue #76 (folds #70).
    fn stable_hash(&self) -> Option<u64> {
        let src_ip = self.src_ip()?;
        let src_port = self.src_port()?;
        let dest_ip = self.dest_ip()?;
        let dest_port = self.dest_port()?;
        // Proto component: the string label when the key carries one
        // (stable across direction for TCP/UDP/…), else the numeric
        // protocol id.
        let mut id_buf = [0u8; 1];
        let proto: &[u8] = if let Some(s) = self.proto_str() {
            s.as_bytes()
        } else if let Some(id) = self.protocol_identifier() {
            id_buf[0] = id;
            &id_buf
        } else {
            return None;
        };
        Some(fnv1a_five_tuple(
            proto, src_ip, src_port, dest_ip, dest_port,
        ))
    }

    /// Deterministic shard index in `0..n` for sharded flow
    /// tables. `None` if `n == 0` or the key lacks a full 5-tuple.
    ///
    /// Built on [`Self::stable_hash`], so both directions of a
    /// flow map to the same shard across processes — the
    /// correctness requirement for tap-merge sharding.
    ///
    /// Issue #76 (folds #70).
    fn shard_index(&self, n: usize) -> Option<usize> {
        if n == 0 {
            return None;
        }
        Some((self.stable_hash()? % n as u64) as usize)
    }

    /// [Corelight Community ID](https://github.com/corelight/community-id-spec)
    /// v1 with the universal default seed (0) — the cross-tool
    /// flow id for pivoting flowscope output against Zeek /
    /// Suricata / Security Onion.
    ///
    /// Returns `Some` only when the crate is built with the
    /// `community-id` feature **and** the key carries a full
    /// 5-tuple; otherwise `None`. TCP/UDP/SCTP are exact; ICMP is
    /// stable but not spec-compatible (see [`crate::community_id`]).
    ///
    /// Issue #76.
    fn community_id(&self) -> Option<String> {
        self.community_id_seeded(0)
    }

    /// [`Self::community_id`] with an explicit sensor seed.
    fn community_id_seeded(&self, seed: u16) -> Option<String> {
        #[cfg(feature = "community-id")]
        {
            crate::community_id::community_id_for_key(self, seed)
        }
        #[cfg(not(feature = "community-id"))]
        {
            let _ = seed;
            None
        }
    }
}

/// FNV-1a over the canonical 5-tuple: `proto.as_bytes() ‖ lo_ip
/// ‖ lo_port_be ‖ hi_ip ‖ hi_port_be`, where `(lo_ip, lo_port)`
/// is the lexicographically smaller endpoint. Direction- and
/// process-stable. Backs [`KeyFields::stable_hash`] — a non-portable
/// in-process identifier (the portable cross-tool id is
/// [`KeyFields::community_id`]).
pub(crate) fn fnv1a_five_tuple(
    proto: &[u8],
    src_ip: IpAddr,
    src_port: u16,
    dest_ip: IpAddr,
    dest_port: u16,
) -> u64 {
    let (lo_ip, lo_port, hi_ip, hi_port) = if (src_ip, src_port) <= (dest_ip, dest_port) {
        (src_ip, src_port, dest_ip, dest_port)
    } else {
        (dest_ip, dest_port, src_ip, src_port)
    };

    const FNV_OFFSET: u64 = 0xcbf29ce484222325;
    const FNV_PRIME: u64 = 0x100000001b3;
    let mut h = FNV_OFFSET;
    fn feed(b: u8, h: &mut u64) {
        *h ^= b as u64;
        *h = h.wrapping_mul(FNV_PRIME);
    }
    fn feed_ip(ip: IpAddr, h: &mut u64) {
        match ip {
            IpAddr::V4(v4) => {
                for &b in &v4.octets() {
                    feed(b, h);
                }
            }
            IpAddr::V6(v6) => {
                for &b in &v6.octets() {
                    feed(b, h);
                }
            }
        }
    }
    fn feed_port(p: u16, h: &mut u64) {
        feed((p >> 8) as u8, h);
        feed((p & 0xff) as u8, h);
    }
    for &b in proto {
        feed(b, &mut h);
    }
    feed_ip(lo_ip, &mut h);
    feed_port(lo_port, &mut h);
    feed_ip(hi_ip, &mut h);
    feed_port(hi_port, &mut h);
    h
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

//! Suricata EVE JSON writer (plan 123).
//!
//! Emits one JSON object per line in the
//! [Suricata 7.x EVE format](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html).
//! Schema-compatible with Filebeat's Suricata module, Splunk
//! Suricata TA, Tenzir's `read_suricata`, and ECS-converting
//! downstream pipelines.
//!
//! Three `event_type` values produced:
//! - `"flow"` — per-flow on [`FlowEvent::Ended`].
//! - `"anomaly"` — per [`FlowEvent::FlowAnomaly`] or
//!   [`FlowEvent::TrackerAnomaly`].
//! - `"stats"` — per [`FlowEvent::Tick`] (off by default; opt-in
//!   via [`EveOptions::include_stats`]).
//!
//! Per-message protocol records (`event_type: "http"` / `"dns"` /
//! `"tls"`) are out of scope for 0.12 — add per-protocol EVE
//! shapes when a consumer asks.

use std::io::{self, Write};
use std::net::IpAddr;

use serde_json::json;

use crate::event::{AnomalyKind, EndReason, FlowEvent, FlowStats, Severity};
use crate::{AnomalyFields, KeyFields};

/// Suricata EVE JSON writer. One JSON object per line.
///
/// Each `write_event` call: clears the per-event JSON `Map`,
/// fills the required + optional fields, calls
/// `serde_json::to_writer` straight into the sink, then writes
/// the trailing newline. No intermediate string allocation per
/// event.
pub struct EveJsonWriter<W>
where
    W: Write,
{
    sink: W,
    options: EveOptions,
    flow_id_counter: u64,
    ts_buf: String,
}

/// Options for [`EveJsonWriter`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct EveOptions {
    /// Interface name embedded as `in_iface`. Default empty —
    /// the field is omitted when empty.
    pub in_iface: String,
    /// Include `event_type: "flow"` records for `FlowEnded`
    /// (default `true`).
    pub include_flow: bool,
    /// Include `event_type: "anomaly"` for `FlowAnomaly` +
    /// `TrackerAnomaly` (default `true`).
    pub include_anomalies: bool,
    /// Include `event_type: "stats"` for `FlowTick`. Default
    /// `false` — high cardinality; opt in for verbose pipelines.
    pub include_stats: bool,
    /// Map flowscope's [`Severity`] to the EVE `severity` field
    /// (numeric 1–4, lower = more severe). Default: identity
    /// mapping — `Critical=1, Error=2, Warning=3, Info=4`
    /// (Suricata's convention).
    pub severity_numeric: fn(Severity) -> u8,
    /// EVE `anomaly.type` value used by
    /// [`EveJsonWriter::write_owned_anomaly`] when the
    /// `OwnedAnomaly` doesn't carry a `flowscope_kind`. Default
    /// `"applayer"` — Suricata's convention for application-
    /// layer detection events.
    ///
    /// Schema-permissive: downstream tooling tolerates any
    /// string. Override for downstream detector frameworks that
    /// classify on a different axis.
    pub custom_anomaly_type: &'static str,
}

impl Default for EveOptions {
    fn default() -> Self {
        Self {
            in_iface: String::new(),
            include_flow: true,
            include_anomalies: true,
            include_stats: false,
            severity_numeric: default_severity_numeric,
            custom_anomaly_type: "applayer",
        }
    }
}

/// Identity mapping: `Critical=1, Error=2, Warning=3, Info=4`.
/// Matches Suricata's convention (1=high, 4=low).
pub fn default_severity_numeric(s: Severity) -> u8 {
    match s {
        Severity::Critical => 1,
        Severity::Error => 2,
        Severity::Warning => 3,
        Severity::Info => 4,
    }
}

impl<W> EveJsonWriter<W>
where
    W: Write,
{
    /// Construct with default options.
    pub fn new(sink: W) -> Self {
        Self::with_options(sink, EveOptions::default())
    }

    /// Construct with custom options.
    pub fn with_options(sink: W, options: EveOptions) -> Self {
        Self {
            sink,
            options,
            flow_id_counter: 0,
            ts_buf: String::with_capacity(40),
        }
    }

    /// Write one event. Skipped variants per
    /// [`EveOptions`] produce no output and return `Ok(())`.
    pub fn write_event<K>(&mut self, ev: &FlowEvent<K>) -> io::Result<()>
    where
        K: KeyFields,
    {
        match ev {
            FlowEvent::Ended {
                key,
                reason,
                stats,
                l4: _,
                ..
            } if self.options.include_flow => self.write_flow_ended(key, *reason, stats),
            FlowEvent::FlowAnomaly { key, kind, ts } if self.options.include_anomalies => {
                self.write_anomaly(Some(key), kind, *ts)
            }
            FlowEvent::TrackerAnomaly { kind, ts } if self.options.include_anomalies => {
                self.write_anomaly::<K>(None, kind, *ts)
            }
            FlowEvent::Tick { key, stats, ts } if self.options.include_stats => {
                self.write_stats(key, stats, *ts)
            }
            _ => Ok(()),
        }
    }

    /// Flush the underlying sink.
    pub fn flush(&mut self) -> io::Result<()> {
        self.sink.flush()
    }

    /// Flush and recover the underlying sink.
    pub fn finish(mut self) -> io::Result<W> {
        self.flush()?;
        Ok(self.sink)
    }

    /// Emit `event_type: "anomaly"` from a canonical
    /// [`crate::OwnedAnomaly`].
    ///
    /// Schema mapping:
    /// - `kind` → `anomaly.event`
    /// - `severity` → `severity` (via
    ///   [`EveOptions::severity_numeric`])
    /// - `(src_ip, src_port, dest_ip, dest_port, proto)` →
    ///   top-level fields (each omitted if `None`)
    /// - `observations` → `anomaly.labels.<label>: <value>`
    /// - `metrics` → `anomaly.metrics.<label>: <number>`
    /// - `anomaly.type` ← [`EveOptions::custom_anomaly_type`]
    ///   unless `flowscope_kind.is_some()`, in which case the
    ///   typed kind's [`crate::AnomalyFields::anomaly_type`]
    ///   takes precedence (for bridged events).
    ///
    /// See [`crate::OwnedAnomaly`] for canonical detector-
    /// shaped emission. Use [`Self::write_event`] for
    /// flowscope-internal `FlowEvent` variants.
    pub fn write_owned_anomaly(&mut self, a: &crate::OwnedAnomaly) -> io::Result<()> {
        use crate::anomaly_fields::AnomalyFields;
        self.ts_buf.clear();
        let _ = a.ts.write_iso8601(&mut self.ts_buf);
        let flow_id = self.next_flow_id();
        let severity = (self.options.severity_numeric)(a.severity);

        // anomaly.type: prefer flowscope_kind's classification (bridged
        // tracker anomalies) over the configured default.
        let anomaly_type: &str = a
            .flowscope_kind
            .as_ref()
            .and_then(|k| k.anomaly_type())
            .unwrap_or(self.options.custom_anomaly_type);

        let mut obj = serde_json::Map::with_capacity(12);
        obj.insert("timestamp".into(), json!(self.ts_buf));
        obj.insert("flow_id".into(), json!(flow_id));
        obj.insert("event_type".into(), json!("anomaly"));
        if !self.options.in_iface.is_empty() {
            obj.insert("in_iface".into(), json!(self.options.in_iface));
        }

        // Top-level 5-tuple fields from the OwnedAnomaly directly
        // (no KeyFields re-traversal needed; the value carries
        // the flattened fields).
        if let Some(ip) = a.src_ip {
            obj.insert("src_ip".into(), json!(ip.to_string()));
        }
        if let Some(p) = a.src_port {
            obj.insert("src_port".into(), json!(p));
        }
        if let Some(ip) = a.dest_ip {
            obj.insert("dest_ip".into(), json!(ip.to_string()));
        }
        if let Some(p) = a.dest_port {
            obj.insert("dest_port".into(), json!(p));
        }
        if let Some(p) = a.proto {
            obj.insert("proto".into(), json!(p));
        }

        let mut anomaly_obj = serde_json::Map::with_capacity(4);
        anomaly_obj.insert("type".into(), json!(anomaly_type));
        anomaly_obj.insert("event".into(), json!(a.kind.as_ref()));
        anomaly_obj.insert("code".into(), json!(0u32));

        if !a.observations.is_empty() {
            let mut labels = serde_json::Map::with_capacity(a.observations.len());
            for (label, value) in &a.observations {
                labels.insert((*label).to_string(), json!(value.as_ref()));
            }
            anomaly_obj.insert("labels".into(), serde_json::Value::Object(labels));
        }
        if !a.metrics.is_empty() {
            let mut metrics = serde_json::Map::with_capacity(a.metrics.len());
            for (label, value) in &a.metrics {
                metrics.insert((*label).to_string(), json!(value));
            }
            anomaly_obj.insert("metrics".into(), serde_json::Value::Object(metrics));
        }

        obj.insert("anomaly".into(), serde_json::Value::Object(anomaly_obj));
        obj.insert("severity".into(), json!(severity));
        self.write_line(&obj)
    }

    // ── Per-variant emit ────────────────────────────────────

    fn write_anomaly<K>(
        &mut self,
        key: Option<&K>,
        kind: &AnomalyKind,
        ts: crate::Timestamp,
    ) -> io::Result<()>
    where
        K: KeyFields,
    {
        self.ts_buf.clear();
        let _ = ts.write_iso8601(&mut self.ts_buf);
        let flow_id = self.next_flow_id();
        let severity = (self.options.severity_numeric)(kind.severity());

        let mut obj = serde_json::Map::with_capacity(12);
        obj.insert("timestamp".into(), json!(self.ts_buf));
        obj.insert("flow_id".into(), json!(flow_id));
        obj.insert("event_type".into(), json!("anomaly"));
        if !self.options.in_iface.is_empty() {
            obj.insert("in_iface".into(), json!(self.options.in_iface));
        }
        if let Some(k) = key {
            insert_5tuple(&mut obj, k);
        }
        obj.insert(
            "anomaly".into(),
            json!({
                "type": kind.anomaly_type(),
                "event": kind.anomaly_event(),
                "code": 0u32,
            }),
        );
        obj.insert("severity".into(), json!(severity));
        self.write_line(&obj)
    }

    fn write_flow_ended<K>(
        &mut self,
        key: &K,
        reason: EndReason,
        stats: &FlowStats,
    ) -> io::Result<()>
    where
        K: KeyFields,
    {
        // EVE convention: `timestamp` is the close time.
        self.ts_buf.clear();
        let _ = stats.last_seen.write_iso8601(&mut self.ts_buf);
        let end_ts = self.ts_buf.clone();

        self.ts_buf.clear();
        let _ = stats.started.write_iso8601(&mut self.ts_buf);
        let start_ts = self.ts_buf.clone();

        let flow_id = self.next_flow_id();
        let mut obj = serde_json::Map::with_capacity(10);
        obj.insert("timestamp".into(), json!(end_ts));
        obj.insert("flow_id".into(), json!(flow_id));
        obj.insert("event_type".into(), json!("flow"));
        if !self.options.in_iface.is_empty() {
            obj.insert("in_iface".into(), json!(self.options.in_iface));
        }
        insert_5tuple(&mut obj, key);
        obj.insert(
            "flow".into(),
            json!({
                "pkts_toserver": stats.packets_initiator,
                "pkts_toclient": stats.packets_responder,
                "bytes_toserver": stats.bytes_initiator,
                "bytes_toclient": stats.bytes_responder,
                "start": start_ts,
                "end": end_ts,
                "age": stats.duration().as_secs(),
                "reason": reason.as_str(),
                "alerted": false,
            }),
        );
        self.write_line(&obj)
    }

    fn write_stats<K>(&mut self, key: &K, stats: &FlowStats, ts: crate::Timestamp) -> io::Result<()>
    where
        K: KeyFields,
    {
        self.ts_buf.clear();
        let _ = ts.write_iso8601(&mut self.ts_buf);
        let flow_id = self.next_flow_id();
        let mut obj = serde_json::Map::with_capacity(8);
        obj.insert("timestamp".into(), json!(self.ts_buf));
        obj.insert("flow_id".into(), json!(flow_id));
        obj.insert("event_type".into(), json!("stats"));
        if !self.options.in_iface.is_empty() {
            obj.insert("in_iface".into(), json!(self.options.in_iface));
        }
        insert_5tuple(&mut obj, key);
        obj.insert(
            "stats".into(),
            json!({
                "pkts_toserver": stats.packets_initiator,
                "pkts_toclient": stats.packets_responder,
                "bytes_toserver": stats.bytes_initiator,
                "bytes_toclient": stats.bytes_responder,
            }),
        );
        self.write_line(&obj)
    }

    fn write_line(&mut self, obj: &serde_json::Map<String, serde_json::Value>) -> io::Result<()> {
        serde_json::to_writer(&mut self.sink, obj).map_err(io::Error::other)?;
        self.sink.write_all(b"\n")
    }

    fn next_flow_id(&mut self) -> u64 {
        self.flow_id_counter += 1;
        self.flow_id_counter
    }
}

fn insert_5tuple<K: KeyFields>(obj: &mut serde_json::Map<String, serde_json::Value>, key: &K) {
    if let Some(ip) = key.src_ip() {
        obj.insert("src_ip".into(), json!(ip.to_string()));
    }
    if let Some(p) = key.src_port() {
        obj.insert("src_port".into(), json!(p));
    }
    if let Some(ip) = key.dest_ip() {
        obj.insert("dest_ip".into(), json!(ip.to_string()));
    }
    if let Some(p) = key.dest_port() {
        obj.insert("dest_port".into(), json!(p));
    }
    if let Some(p) = key.proto_str() {
        obj.insert("proto".into(), json!(p));
    }
    if let Some(p) = key.app_proto_str() {
        obj.insert("app_proto".into(), json!(p));
    }
    if let Some(h) = flow_hash(key) {
        obj.insert("flow_hash".into(), json!(format!("{h:016x}")));
    }
}

/// Stable 64-bit hash over the canonical 5-tuple. Returns
/// `None` if any of (proto, src ip/port, dest ip/port) is
/// unknown.
///
/// Algorithm: FNV-1a over
/// `proto.as_bytes() || lo_ip.octets() || lo_port_be ||
/// hi_ip.octets() || hi_port_be`, where `(lo_ip, lo_port)` is
/// the lexicographically smaller endpoint. Deterministic
/// across runs and across direction (A→B and B→A produce the
/// same hash). 64-bit FNV at flowscope scales: collision
/// probability ~5e-8 at 1 M flows.
fn flow_hash<K: KeyFields>(key: &K) -> Option<u64> {
    let proto = key.proto_str()?;
    let src_ip = key.src_ip()?;
    let src_port = key.src_port()?;
    let dest_ip = key.dest_ip()?;
    let dest_port = key.dest_port()?;

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
    for &b in proto.as_bytes() {
        feed(b, &mut h);
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
    feed_ip(lo_ip, &mut h);
    feed_port(lo_port, &mut h);
    feed_ip(hi_ip, &mut h);
    feed_port(hi_port, &mut h);
    Some(h)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_severity_mapping_matches_suricata_convention() {
        assert_eq!(default_severity_numeric(Severity::Critical), 1);
        assert_eq!(default_severity_numeric(Severity::Error), 2);
        assert_eq!(default_severity_numeric(Severity::Warning), 3);
        assert_eq!(default_severity_numeric(Severity::Info), 4);
    }

    #[test]
    fn flow_hash_direction_invariant() {
        use crate::L4Proto;
        use crate::extract::FiveTupleKey;
        let a = FiveTupleKey {
            proto: L4Proto::Tcp,
            a: "10.0.0.1:33000".parse().unwrap(),
            b: "10.0.0.2:80".parse().unwrap(),
        };
        let b = FiveTupleKey {
            proto: L4Proto::Tcp,
            a: "10.0.0.2:80".parse().unwrap(),
            b: "10.0.0.1:33000".parse().unwrap(),
        };
        assert_eq!(flow_hash(&a), flow_hash(&b));
        assert!(flow_hash(&a).is_some());
    }
}

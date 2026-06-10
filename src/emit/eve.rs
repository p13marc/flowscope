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

use serde_json::json;

use crate::AnomalyFields;
use crate::event::{AnomalyKind, EndReason, FlowEvent, FlowStats, Severity};

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
}

impl Default for EveOptions {
    fn default() -> Self {
        Self {
            in_iface: String::new(),
            include_flow: true,
            include_anomalies: true,
            include_stats: false,
            severity_numeric: default_severity_numeric,
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
        K: AnomalyFields,
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

    // ── Per-variant emit ────────────────────────────────────

    fn write_anomaly<K>(
        &mut self,
        key: Option<&K>,
        kind: &AnomalyKind,
        ts: crate::Timestamp,
    ) -> io::Result<()>
    where
        K: AnomalyFields,
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
        K: AnomalyFields,
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
        K: AnomalyFields,
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

fn insert_5tuple<K: AnomalyFields>(obj: &mut serde_json::Map<String, serde_json::Value>, key: &K) {
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
}

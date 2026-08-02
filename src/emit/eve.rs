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

use crate::{
    AnomalyFields, KeyFields,
    event::{AnomalyKind, EndReason, FlowEvent, FlowStats, Severity},
};

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
    /// Include `event_type: "flow"` records for `Ended`
    /// (default `true`).
    pub include_flow: bool,
    /// Include `event_type: "anomaly"` for `FlowAnomaly` +
    /// `TrackerAnomaly` (default `true`).
    pub include_anomalies: bool,
    /// Include `event_type: "stats"` for `Tick`. Default
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

    /// Emit any [`LifecycleEvent`](crate::emit::LifecycleEvent) — both
    /// the tracker's [`FlowEvent`] and the typed
    /// driver's [`Event`](crate::driver::Event) (issue #97). Events
    /// with no flow-record projection (e.g.
    /// [`Event::ParserClosed`](crate::driver::Event::ParserClosed)) are
    /// skipped.
    pub fn write_lifecycle<T, K>(&mut self, ev: &T) -> io::Result<()>
    where
        T: crate::emit::LifecycleEvent<K>,
        K: KeyFields + Clone,
    {
        match ev.as_flow_event() {
            Some(fe) => self.write_event(fe.as_ref()),
            None => Ok(()),
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
                key, reason, stats, ..
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
    /// Write one finalised [`crate::FlowRecord`] as an
    /// `event_type: "flow"` EVE JSON record. Same schema
    /// shape as a `FlowEvent::Ended`-derived flow event;
    /// the per-direction byte/packet counts come from the
    /// `octet_delta_count_*` / `packet_delta_count_*` IEs
    /// and the protocol slug from the IPFIX
    /// `protocolIdentifier`.
    ///
    /// Timestamps are converted from
    /// `flowStartMilliseconds` / `flowEndMilliseconds` (IEs
    /// 152/153) to ISO-8601 strings.
    ///
    /// `flow_id` is auto-incremented as for `write_event`.
    /// The cross-tool `community_id` (read from
    /// [`FlowRecord::community_id`](crate::FlowRecord::community_id),
    /// populated when the `community-id` feature is on) is emitted as the
    /// canonical flow identifier — matching the event-driven path.
    ///
    /// Issue #16 — emitter unification at the FlowRecord
    /// layer. Requires the `ipfix` feature.
    #[cfg(feature = "ipfix")]
    pub fn write_flow_record(&mut self, rec: &crate::FlowRecord) -> io::Result<()> {
        let start_ts = ms_to_iso8601(rec.flow_start_milliseconds);
        let end_ts = ms_to_iso8601(rec.flow_end_milliseconds);
        let flow_id = self.next_flow_id();
        let mut obj = serde_json::Map::with_capacity(10);
        obj.insert("timestamp".into(), json!(end_ts));
        obj.insert("flow_id".into(), json!(flow_id));
        obj.insert("event_type".into(), json!("flow"));
        if !self.options.in_iface.is_empty() {
            obj.insert("in_iface".into(), json!(self.options.in_iface));
        }
        insert_flow_record_5tuple(&mut obj, rec);
        let age_secs = rec
            .flow_end_milliseconds
            .saturating_sub(rec.flow_start_milliseconds)
            / 1000;
        let reason = super::csv::flow_record_reason_str(rec);
        obj.insert(
            "flow".into(),
            json!({
                "pkts_toserver": rec.packet_delta_count_initiator,
                "pkts_toclient": rec.packet_delta_count_responder,
                "bytes_toserver": rec.octet_delta_count_initiator,
                "bytes_toclient": rec.octet_delta_count_responder,
                "start": start_ts,
                "end": end_ts,
                "age": age_secs,
                "reason": reason,
                "alerted": false,
            }),
        );
        // Canonical cross-tool flow identifier. `None` unless the
        // FlowRecord was built with the `community-id` feature.
        if let Some(cid) = rec.community_id.as_deref() {
            obj.insert("community_id".into(), json!(cid));
        }
        self.write_line(&obj)
    }

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

        let mut anomaly_obj = serde_json::Map::with_capacity(5);
        anomaly_obj.insert("type".into(), json!(anomaly_type));
        anomaly_obj.insert("event".into(), json!(a.kind.as_str()));
        anomaly_obj.insert("code".into(), json!(0u32));
        // MITRE ATT&CK technique tag (issue #133) — additive field;
        // schema-permissive for EVE consumers.
        if let Some(technique) = a.kind.attack_technique() {
            anomaly_obj.insert("attack_technique".into(), json!(technique));
        }

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

    /// Emit an enriched [`crate::AnalyzedFlow`] as an EVE `flow`
    /// event — the SIEM-ready single-pass record. Carries the
    /// standard 5-tuple (+ `community_id`), the flow
    /// counters, the observed L7 facts (`tls` / `http` / `dns`
    /// objects), and a `flowscope` extension object with the
    /// computed risk (slug array + aggregate `score` + `severity`)
    /// and any threat-intel `ioc` hits. `flow.alerted` reflects
    /// [`crate::AnalyzedFlow::is_clean`].
    ///
    /// Issue #83. Available with the `analysis` feature.
    #[cfg(feature = "analysis")]
    pub fn write_analyzed_flow<K>(&mut self, af: &crate::AnalyzedFlow<K>) -> io::Result<()>
    where
        K: KeyFields,
    {
        let stats = &af.stats;
        self.ts_buf.clear();
        let _ = stats.last_seen.write_iso8601(&mut self.ts_buf);
        let end_ts = self.ts_buf.clone();
        self.ts_buf.clear();
        let _ = stats.started.write_iso8601(&mut self.ts_buf);
        let start_ts = self.ts_buf.clone();

        let flow_id = self.next_flow_id();
        let mut obj = serde_json::Map::with_capacity(12);
        obj.insert("timestamp".into(), json!(end_ts));
        obj.insert("flow_id".into(), json!(flow_id));
        obj.insert("event_type".into(), json!("flow"));
        if !self.options.in_iface.is_empty() {
            obj.insert("in_iface".into(), json!(self.options.in_iface));
        }
        insert_5tuple(&mut obj, &af.key);
        // The detected app proto is more accurate than the port-based
        // label insert_5tuple derives — prefer it when observed.
        if let Some(ap) = af.l7.app_proto {
            obj.insert("app_proto".into(), json!(ap));
        }

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
                "alerted": !af.is_clean(),
            }),
        );

        // L7 app-layer objects (Suricata-shaped where it maps cleanly).
        let l7 = &af.l7;
        if l7.ja3.is_some()
            || l7.ja4.is_some()
            || l7.tls_version.is_some()
            || l7.tls_cipher.is_some()
        {
            let mut tls = serde_json::Map::with_capacity(5);
            if let Some(sni) = &l7.server_name {
                tls.insert("sni".into(), json!(sni));
            }
            if let Some(j) = &l7.ja3 {
                tls.insert("ja3".into(), json!({ "hash": j }));
            }
            if let Some(j) = &l7.ja4 {
                tls.insert("ja4".into(), json!(j));
            }
            if let Some(v) = l7.tls_version {
                tls.insert("version_raw".into(), json!(format!("0x{v:04x}")));
            }
            if let Some(c) = l7.tls_cipher {
                tls.insert("cipher_raw".into(), json!(format!("0x{c:04x}")));
            }
            obj.insert("tls".into(), serde_json::Value::Object(tls));
        }
        if l7.http_method.is_some() || l7.http_uri.is_some() || l7.user_agent.is_some() {
            let mut http = serde_json::Map::with_capacity(4);
            if let Some(h) = &l7.server_name {
                http.insert("hostname".into(), json!(h));
            }
            if let Some(m) = &l7.http_method {
                http.insert("http_method".into(), json!(m));
            }
            if let Some(u) = &l7.http_uri {
                http.insert("url".into(), json!(u));
            }
            if let Some(ua) = &l7.user_agent {
                http.insert("http_user_agent".into(), json!(ua));
            }
            obj.insert("http".into(), serde_json::Value::Object(http));
        }
        if !l7.dns_queries.is_empty() {
            obj.insert("dns".into(), json!({ "queries": l7.dns_queries }));
        }

        // The `flowscope` enrichment extension: risk + IOC hits.
        let mut fs = serde_json::Map::with_capacity(4);
        if !af.risk.is_empty() {
            let slugs: Vec<&str> = af.risk.as_slugs().collect();
            fs.insert("risk".into(), json!(slugs));
            fs.insert("risk_score".into(), json!(af.score()));
            if let Some(sev) = af.severity() {
                fs.insert("risk_severity".into(), json!(sev.as_str()));
            }
        }
        if !af.ioc_hits.is_empty() {
            let hits: Vec<serde_json::Value> = af
                .ioc_hits
                .iter()
                .map(|m| {
                    json!({
                        "kind": m.kind.as_str(),
                        "value": m.value,
                        "reputation": m.reputation,
                        "source": m.source,
                    })
                })
                .collect();
            fs.insert("ioc".into(), json!(hits));
        }
        if !fs.is_empty() {
            obj.insert("flowscope".into(), serde_json::Value::Object(fs));
        }

        self.write_line(&obj)
    }

    /// Emit an [`HttpAccessRecord`](crate::http::HttpAccessRecord) as
    /// a Suricata-shaped `event_type: "http"` line.
    ///
    /// This is what puts an inline proxy's access log in the same
    /// pipeline as passive telemetry: the record comes from the
    /// streaming parser, which never retained a body, but the JSON is
    /// the same shape a SIEM already ingests. Byte counts are wire
    /// bytes as framed.
    ///
    /// `Refused` and `Switched` outcomes are reported too — a
    /// connection refused for a framing violation is exactly the
    /// event an operator wants to see, and dropping it would make the
    /// log say nothing happened.
    ///
    /// Issue #168. Available with the `http` feature.
    #[cfg(feature = "http")]
    pub fn write_http_access(
        &mut self,
        rec: &crate::http::HttpAccessRecord,
        ts: crate::Timestamp,
    ) -> io::Result<()> {
        use crate::http::HttpAccessOutcome;

        self.ts_buf.clear();
        let _ = ts.write_iso8601(&mut self.ts_buf);
        let flow_id = self.next_flow_id();

        let mut http = serde_json::Map::with_capacity(8);
        if let Some(host) = rec.authority.as_deref() {
            http.insert("hostname".into(), json!(host));
        }
        if let Some(m) = rec.method_str() {
            http.insert("http_method".into(), json!(m));
        }
        if let Some(p) = rec.path_str() {
            http.insert("url".into(), json!(p));
        }
        if let Some(s) = rec.status {
            http.insert("status".into(), json!(s));
        }
        http.insert("request_body_len".into(), json!(rec.request_body_bytes));
        http.insert("response_body_len".into(), json!(rec.response_body_bytes));
        http.insert(
            "protocol".into(),
            json!(match rec.version {
                crate::http::HttpVersion::Http1_0 => "HTTP/1.0",
                crate::http::HttpVersion::Http1_1 => "HTTP/1.1",
            }),
        );

        // Why the exchange ended the way it did — the part a plain
        // access log leaves out and an operator needs most.
        let (outcome, refused): (&str, Option<&str>) = match &rec.outcome {
            HttpAccessOutcome::Completed => ("completed", None),
            HttpAccessOutcome::NoResponse => ("no_response", None),
            HttpAccessOutcome::Switched => ("switched", None),
            HttpAccessOutcome::Refused { reason } => ("refused", Some(reason.as_str())),
        };

        let mut obj = serde_json::Map::with_capacity(8);
        obj.insert("timestamp".into(), json!(self.ts_buf));
        obj.insert("flow_id".into(), json!(flow_id));
        obj.insert("event_type".into(), json!("http"));
        if !self.options.in_iface.is_empty() {
            obj.insert("in_iface".into(), json!(self.options.in_iface));
        }
        obj.insert("app_proto".into(), json!("http"));
        obj.insert("http".into(), serde_json::Value::Object(http));

        let mut fs = serde_json::Map::with_capacity(2);
        fs.insert("outcome".into(), json!(outcome));
        if let Some(reason) = refused {
            fs.insert("refused_reason".into(), json!(reason));
        }
        obj.insert("flowscope".into(), serde_json::Value::Object(fs));

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
        // Issue #16 close — when the ipfix feature is on, route
        // through the canonical FlowRecord so the two emit paths
        // can't drift. The shadow `original_end_reason` field
        // preserves the 8-variant EndReason fidelity that IPFIX
        // IE 136 would otherwise collapse.
        #[cfg(feature = "ipfix")]
        {
            let rec = crate::FlowRecord::from_key_fields(stats, key, Some(reason));
            self.write_flow_record(&rec)
        }
        #[cfg(not(feature = "ipfix"))]
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
            self.write_line(&obj)?;
            Ok(())
        }
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

/// Same shape as [`insert_5tuple`] but populating from a
/// [`crate::FlowRecord`] instead of a `KeyFields`-impl
/// key. Used by [`EveJsonWriter::write_flow_record`].
#[cfg(feature = "ipfix")]
fn insert_flow_record_5tuple(
    obj: &mut serde_json::Map<String, serde_json::Value>,
    rec: &crate::FlowRecord,
) {
    let src_ip = super::csv::flow_record_src_ip(rec);
    if !src_ip.is_empty() {
        obj.insert("src_ip".into(), json!(src_ip));
    }
    obj.insert("src_port".into(), json!(rec.source_transport_port));
    let dst_ip = super::csv::flow_record_dst_ip(rec);
    if !dst_ip.is_empty() {
        obj.insert("dest_ip".into(), json!(dst_ip));
    }
    obj.insert("dest_port".into(), json!(rec.destination_transport_port));
    let proto = super::csv::flow_record_proto_str(rec);
    if !proto.is_empty() {
        obj.insert("proto".into(), json!(proto.to_uppercase()));
    }
    if let Some(app) = rec.application_name.as_deref() {
        obj.insert("app_proto".into(), json!(app));
    }
}

/// Convert Unix milliseconds → ISO 8601 string by going via
/// [`crate::Timestamp`].
#[cfg(feature = "ipfix")]
fn ms_to_iso8601(ms: u64) -> String {
    use crate::Timestamp;
    let secs = (ms / 1000) as u32;
    let nsec = ((ms % 1000) as u32) * 1_000_000;
    let ts = Timestamp::new(secs, nsec);
    let mut buf = String::new();
    let _ = ts.write_iso8601(&mut buf);
    buf
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
    // Cross-tool Community ID (Zeek / Suricata / Security Onion pivot) —
    // the canonical, portable flow identifier in EVE output since 0.19.
    // `None` unless built with the `community-id` feature. (The legacy
    // proprietary FNV-1a `flow_hash` was dropped from default output in
    // 0.19, issue #88; `KeyFields::stable_hash()` is still available for
    // callers that want a non-portable in-process hash.)
    if let Some(cid) = key.community_id() {
        obj.insert("community_id".into(), json!(cid));
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

    /// The canonical EVE flow identifier (`community_id`) is
    /// direction-invariant — both orientations of the same flow hash
    /// to the same value. (Replaces the pre-0.19 `flow_hash` test;
    /// the proprietary FNV `flow_hash` was dropped from EVE output in
    /// issue #88.)
    #[cfg(feature = "community-id")]
    #[test]
    fn community_id_direction_invariant() {
        use crate::{L4Proto, extract::FiveTupleKey};
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
        // `FiveTupleKey::community_id()` is the infallible inherent method.
        assert_eq!(a.community_id(), b.community_id());
        assert!(a.community_id().starts_with("1:"));
    }

    #[cfg(all(feature = "analysis", feature = "extractors"))]
    #[test]
    fn analyzed_flow_emits_enriched_flow_event() {
        use crate::analysis::L7Summary;
        use crate::detect::{FlowRisk, IocKind, IocMatch};
        use crate::{AnalyzedFlow, FlowStats, L4Proto, extract::FiveTupleKey};

        let key = FiveTupleKey {
            proto: L4Proto::Tcp,
            a: "10.0.0.1:50000".parse().unwrap(),
            b: "93.184.216.34:443".parse().unwrap(),
        };
        let l7 = L7Summary {
            app_proto: Some("tls"),
            server_name: Some("evil.example".into()),
            ja4: Some("t13d1516h2_x_y".into()),
            tls_version: Some(0x0301),
            ..Default::default()
        };
        let af = AnalyzedFlow {
            key,
            stats: FlowStats::default(),
            l7,
            risk: FlowRisk::TLS_OBSOLETE_VERSION | FlowRisk::SUSPICIOUS_JA4,
            ioc_hits: vec![IocMatch {
                kind: IocKind::Ja4,
                value: "t13d1516h2_x_y".into(),
                reputation: Some(95),
                source: Some("intel".into()),
            }],
        };

        let mut buf = Vec::new();
        EveJsonWriter::new(&mut buf)
            .write_analyzed_flow(&af)
            .unwrap();
        let v: serde_json::Value = serde_json::from_slice(&buf).unwrap();

        assert_eq!(v["event_type"], "flow");
        assert_eq!(v["app_proto"], "tls");
        assert_eq!(v["flow"]["alerted"], true);
        assert_eq!(v["tls"]["sni"], "evil.example");
        assert_eq!(v["tls"]["ja4"], "t13d1516h2_x_y");
        assert_eq!(v["tls"]["version_raw"], "0x0301");
        let risks = v["flowscope"]["risk"].as_array().unwrap();
        assert!(risks.iter().any(|s| s == "tls_obsolete_version"));
        assert!(risks.iter().any(|s| s == "suspicious_ja4"));
        assert_eq!(v["flowscope"]["risk_severity"], "high");
        assert_eq!(v["flowscope"]["ioc"][0]["kind"], "ja4");
        assert_eq!(v["flowscope"]["ioc"][0]["source"], "intel");
        // Every line is valid JSON ending in newline.
        assert!(buf.ends_with(b"\n"));
    }
}

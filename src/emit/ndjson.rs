//! [`FlowEventNdjsonWriter`] — newline-delimited JSON sink.
//!
//! Each [`FlowEvent`] becomes one JSON object on one line, using
//! flowscope's existing serde wire format (snake_case + adjacent
//! tagging — locked since 0.8). Suitable for direct ingest into
//! Elasticsearch / Loki / ClickHouse / DuckDB without any
//! transformation.

use std::io::{self, Write};

use serde::Serialize;

use crate::FlowEvent;

/// Newline-delimited JSON writer for [`FlowEvent`] streams.
pub struct FlowEventNdjsonWriter<W: Write> {
    sink: W,
    options: NdjsonOptions,
}

/// Options for [`FlowEventNdjsonWriter`].
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct NdjsonOptions {
    /// Pretty-print one indented JSON per event (default `false`).
    ///
    /// NOTE: pretty-printed output is NOT valid NDJSON — each
    /// record spans multiple lines. Use only for human inspection.
    pub pretty: bool,
    /// Include `FlowEvent::Packet` rows (high volume; off by
    /// default).
    pub include_packets: bool,
    /// Include `FlowEvent::Started` rows (default `false`).
    pub include_started: bool,
    /// Include `FlowEvent::FlowAnomaly` / `TrackerAnomaly` rows
    /// (default `true`).
    pub include_anomalies: bool,
    /// Include `FlowEvent::Established` rows (default `false`).
    pub include_established: bool,
    /// Include `FlowEvent::Tick` rows (default `false`).
    pub include_ticks: bool,
}

impl<W: Write> FlowEventNdjsonWriter<W> {
    /// Construct with default options.
    pub fn new(sink: W) -> Self {
        Self::with_options(sink, NdjsonOptions::default_anomalies_on())
    }

    /// Construct with custom options.
    pub fn with_options(sink: W, options: NdjsonOptions) -> Self {
        Self { sink, options }
    }

    /// Emit any [`LifecycleEvent`](crate::emit::LifecycleEvent) — both
    /// the tracker's [`FlowEvent`] and the typed
    /// driver's [`Event`](crate::driver::Event) (issue #97). The
    /// `Event` is projected to its `FlowEvent` form first, so NDJSON
    /// output keeps one schema regardless of source. Events with no
    /// projection (e.g.
    /// [`Event::ParserClosed`](crate::driver::Event::ParserClosed)) are
    /// skipped.
    pub fn write_lifecycle<T, K>(&mut self, ev: &T) -> io::Result<()>
    where
        T: crate::emit::LifecycleEvent<K>,
        K: Serialize + Clone,
    {
        match ev.as_flow_event() {
            Some(fe) => self.write_event(fe.as_ref()),
            None => Ok(()),
        }
    }

    /// Write one event to the sink. Skipped variants (per
    /// [`NdjsonOptions`]) produce no output.
    pub fn write_event<K>(&mut self, ev: &FlowEvent<K>) -> io::Result<()>
    where
        K: Serialize,
    {
        if !self.should_emit(ev) {
            return Ok(());
        }
        let result = if self.options.pretty {
            serde_json::to_string_pretty(ev)
        } else {
            serde_json::to_string(ev)
        };
        let s = result.map_err(io::Error::other)?;
        self.sink.write_all(s.as_bytes())?;
        self.sink.write_all(b"\n")?;
        Ok(())
    }

    /// Write a canonical [`crate::OwnedAnomaly`] as one NDJSON
    /// record.
    ///
    /// Requires the `serde` feature on flowscope; `OwnedAnomaly`
    /// derives `Serialize` behind that feature. Output shape:
    ///
    /// ```json
    /// {
    ///   "kind": "PortScanTRW",
    ///   "severity": "warning",
    ///   "ts": { "sec": 1700000000, "nsec": 0 },
    ///   "src_ip": "10.0.0.1",
    ///   "src_port": 33000,
    ///   ...,
    ///   "observations": [["verdict", "scanner"]],
    ///   "metrics": [["log_likelihood", 3.7]],
    ///   "flowscope_kind": null
    /// }
    /// ```
    pub fn write_owned_anomaly(&mut self, a: &crate::OwnedAnomaly) -> io::Result<()> {
        let result = if self.options.pretty {
            serde_json::to_string_pretty(a)
        } else {
            serde_json::to_string(a)
        };
        let s = result.map_err(io::Error::other)?;
        self.sink.write_all(s.as_bytes())?;
        self.sink.write_all(b"\n")?;
        Ok(())
    }

    fn should_emit<K>(&self, ev: &FlowEvent<K>) -> bool {
        match ev {
            FlowEvent::Ended { .. } => true,
            FlowEvent::Started { .. } => self.options.include_started,
            FlowEvent::Packet { .. } => self.options.include_packets,
            FlowEvent::Established { .. } => self.options.include_established,
            FlowEvent::Tick { .. } => self.options.include_ticks,
            FlowEvent::FlowAnomaly { .. } | FlowEvent::TrackerAnomaly { .. } => {
                self.options.include_anomalies
            }
            FlowEvent::StateChange { .. } => false,
        }
    }

    /// Write one finalised [`crate::FlowRecord`] as a JSON
    /// line. The serialization is whatever `FlowRecord`'s
    /// `#[derive(Serialize)]` produces — the full IPFIX IE
    /// field set, IE-named keys.
    ///
    /// Issue #16 — emitter unification at the FlowRecord
    /// layer. Pairs with `write_event` for the FlowEvent
    /// shape. The two outputs have different schemas:
    /// `write_event(FlowEnded)` emits the flowscope
    /// `FlowEvent::Ended` JSON shape; `write_flow_record`
    /// emits the IPFIX-keyed shape that downstream
    /// IPFIX-consuming pipelines expect.
    ///
    /// Requires the `ipfix` feature.
    #[cfg(feature = "ipfix")]
    pub fn write_flow_record(&mut self, rec: &crate::FlowRecord) -> io::Result<()> {
        let result = if self.options.pretty {
            serde_json::to_string_pretty(rec)
        } else {
            serde_json::to_string(rec)
        };
        let s = result.map_err(io::Error::other)?;
        self.sink.write_all(s.as_bytes())?;
        self.sink.write_all(b"\n")?;
        Ok(())
    }

    /// Flush buffered output to the sink.
    pub fn flush(&mut self) -> io::Result<()> {
        self.sink.flush()
    }

    /// Flush and recover the underlying sink.
    pub fn finish(mut self) -> io::Result<W> {
        self.flush()?;
        Ok(self.sink)
    }
}

impl NdjsonOptions {
    fn default_anomalies_on() -> Self {
        Self {
            include_anomalies: true,
            ..Self::default()
        }
    }
}

//! `flowscope::emit` — structured event sinks.
//!
//! Built-in writers for the three log formats every flow-analysis
//! pipeline ends up emitting:
//!
//! - [`FlowEventCsvWriter`] — `flows.csv` for spreadsheets,
//!   DuckDB, pandas. RFC-4180 quoting. No extra deps.
//! - [`FlowEventNdjsonWriter`] — newline-delimited JSON for
//!   Elasticsearch / Loki / ClickHouse. Gated on the
//!   `emit-ndjson` feature (pulls in `serde_json` and requires
//!   `serde`).
//! - [`ZeekConnLogWriter`] — Zeek-style `conn.log` rows
//!   (tab-separated). Drop-in for existing Zeek pipelines via
//!   `zeek-cut`.
//!
//! Each writer takes a [`std::io::Write`] sink and a single
//! `FlowEvent<FiveTupleKey>` per call. By default they emit only
//! [`FlowEvent::Ended`](crate::FlowEvent::Ended); use the per-
//! writer options struct to opt into `Started` / `Packet` /
//! anomaly rows.
//!
//! ```no_run
//! use std::fs::File;
//! use std::io::BufWriter;
//! use flowscope::emit::FlowEventCsvWriter;
//! use flowscope::extract::FiveTuple;
//! use flowscope::pcap::PcapFlowSource;
//! use flowscope::FlowTracker;
//!
//! # fn ex() -> Result<(), Box<dyn std::error::Error>> {
//! let f = File::create("flows.csv")?;
//! let mut csv = FlowEventCsvWriter::new(BufWriter::new(f))?;
//! let mut tracker = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
//!
//! for owned in PcapFlowSource::open("trace.pcap")?.views() {
//!     for ev in tracker.track(&owned?) {
//!         csv.write_event(&ev)?;
//!     }
//! }
//! for ev in tracker.finish() {
//!     csv.write_event(&ev)?;
//! }
//! csv.finish()?;
//! # Ok(()) }
//! ```
//!
//! New in 0.10.0 (plan 101).

mod csv;
#[cfg(feature = "emit-eve")]
mod eve;
#[cfg(feature = "emit-ndjson")]
mod ndjson;
mod zeek;

pub use csv::{CsvOptions, FlowEventCsvWriter};
#[cfg(feature = "emit-eve")]
pub use eve::{EveJsonWriter, EveOptions};
#[cfg(feature = "emit-ndjson")]
pub use ndjson::{FlowEventNdjsonWriter, NdjsonOptions};
pub use zeek::{ZeekConnLogWriter, ZeekOptions};

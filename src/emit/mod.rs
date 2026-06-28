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
//! [`FlowEvent::Ended`]; use the per-
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

use std::borrow::Cow;

use crate::event::FlowEvent;

/// A lifecycle event the [`emit`](crate::emit) writers can consume —
/// implemented by both [`FlowEvent`] (the tracker
/// primitive) and the typed driver's
/// [`Event`](crate::driver::Event) (issue #97).
///
/// Lets every `write_lifecycle` accept either, so a consumer driving
/// the typed [`Driver<E>`](crate::driver::Driver) can emit its
/// `Event<K>` stream through the same CSV / Zeek / NDJSON / EVE writers
/// the raw `FlowTracker` uses — without hand-converting first.
///
/// The `FlowEvent` projection is borrowed for `FlowEvent` itself
/// (zero-copy) and produced by conversion for `Event` (see
/// [`Event::to_flow_event`](crate::driver::Event::to_flow_event)).
/// [`Event::ParserClosed`](crate::driver::Event::ParserClosed) has no
/// flow-record projection and is skipped.
pub trait LifecycleEvent<K: Clone> {
    /// Borrow (or produce) this event's `FlowEvent` projection, or
    /// `None` if it has none.
    fn as_flow_event(&self) -> Option<Cow<'_, FlowEvent<K>>>;
}

impl<K: Clone> LifecycleEvent<K> for FlowEvent<K> {
    fn as_flow_event(&self) -> Option<Cow<'_, FlowEvent<K>>> {
        Some(Cow::Borrowed(self))
    }
}

#[cfg(all(feature = "extractors", feature = "reassembler", feature = "session"))]
impl<K: Clone> LifecycleEvent<K> for crate::driver::Event<K> {
    fn as_flow_event(&self) -> Option<Cow<'_, FlowEvent<K>>> {
        self.to_flow_event().map(Cow::Owned)
    }
}

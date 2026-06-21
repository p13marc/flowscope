//! [`ZeekConnLogWriter`] — Zeek-style `conn.log` rows.
//!
//! Output is tab-separated with the canonical `conn.log` column
//! order:
//!
//! ```text
//! ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto duration
//! orig_bytes resp_bytes conn_state history orig_pkts resp_pkts
//! ```
//!
//! Compatible with `zeek-cut` and downstream pipelines that
//! already consume Zeek logs. UIDs are auto-generated as
//! `{uid_prefix}{16-hex-digit sequence}`.

use std::io::{self, Write};

use crate::{FlowEvent, KeyFields};

/// Best-effort Zeek `conn_state` derivation from the
/// IPFIX-reduced `FlowEndReason`. Mirrors
/// `EndReason::as_zeek_state()` for the cases we can
/// recover; everything else falls back to `OTH`.
#[cfg(feature = "ipfix")]
fn flow_record_zeek_state(rec: &crate::FlowRecord) -> &'static str {
    if let Some(reason) = rec.original_end_reason {
        return reason.as_zeek_state();
    }
    use crate::ipfix::FlowEndReason as R;
    match rec.flow_end_reason {
        Some(R::EndOfFlowDetected) => "SF",
        Some(R::IdleTimeout) | Some(R::ActiveTimeout) => "OTH",
        Some(R::ForcedEnd) => "OTH",
        Some(R::LackOfResources) => "OTH",
        None => "OTH",
    }
}

/// Tab-separated Zeek `conn.log` writer for
/// [`FlowEvent`](crate::FlowEvent) streams.
pub struct ZeekConnLogWriter<W: Write> {
    sink: W,
    options: ZeekOptions,
    uid_seq: u64,
}

/// Options for [`ZeekConnLogWriter`].
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct ZeekOptions {
    /// Emit the `#fields` / `#types` headers (default `true`).
    /// Disable when appending to an existing log.
    pub emit_headers: bool,
    /// UID prefix (default `"C"`). Each emitted UID is
    /// `{uid_prefix}{16-hex-digit sequence}`.
    pub uid_prefix: &'static str,
}

impl Default for ZeekOptions {
    fn default() -> Self {
        Self {
            emit_headers: true,
            uid_prefix: "C",
        }
    }
}

impl<W: Write> ZeekConnLogWriter<W> {
    /// Construct with default options and emit the header block.
    pub fn new(sink: W) -> io::Result<Self> {
        Self::with_options(sink, ZeekOptions::default())
    }

    /// Construct with custom options. Headers are emitted iff
    /// [`ZeekOptions::emit_headers`] is `true`.
    pub fn with_options(sink: W, options: ZeekOptions) -> io::Result<Self> {
        let mut writer = Self {
            sink,
            options,
            uid_seq: 0,
        };
        if writer.options.emit_headers {
            writer.write_headers()?;
        }
        Ok(writer)
    }

    fn write_headers(&mut self) -> io::Result<()> {
        writeln!(self.sink, "#separator \\x09")?;
        writeln!(self.sink, "#set_separator\t,")?;
        writeln!(self.sink, "#empty_field\t(empty)")?;
        writeln!(self.sink, "#unset_field\t-")?;
        writeln!(self.sink, "#path\tconn")?;
        writeln!(
            self.sink,
            "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tduration\torig_bytes\tresp_bytes\tconn_state\thistory\torig_pkts\tresp_pkts"
        )?;
        writeln!(
            self.sink,
            "#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tinterval\tcount\tcount\tstring\tstring\tcount\tcount"
        )?;
        Ok(())
    }

    /// Write one event. Only `FlowEvent::Ended` emits a row; all
    /// other variants are skipped silently.
    pub fn write_event<K>(&mut self, ev: &FlowEvent<K>) -> io::Result<()>
    where
        K: KeyFields,
    {
        let FlowEvent::Ended {
            key,
            reason,
            stats,
            history,
            ..
        } = ev
        else {
            return Ok(());
        };

        self.uid_seq += 1;
        let uid = format!("{}{:016x}", self.options.uid_prefix, self.uid_seq);
        let ts = stats.started.to_unix_f64();
        let duration = stats.duration_secs();
        let proto = key.proto_str().unwrap_or("").to_lowercase();
        let conn_state = reason.as_zeek_state();
        let src_ip = key.src_ip().map(|ip| ip.to_string()).unwrap_or_default();
        let src_port = key.src_port().unwrap_or(0);
        let dst_ip = key.dest_ip().map(|ip| ip.to_string()).unwrap_or_default();
        let dst_port = key.dest_port().unwrap_or(0);

        writeln!(
            self.sink,
            "{ts:.6}\t{uid}\t{src_ip}\t{src_port}\t{dst_ip}\t{dst_port}\t{proto}\t{duration:.6}\t{}\t{}\t{conn_state}\t{}\t{}\t{}",
            stats.bytes_initiator,
            stats.bytes_responder,
            history.as_str(),
            stats.packets_initiator,
            stats.packets_responder,
        )?;
        Ok(())
    }

    /// Write one finalised `FlowRecord` as a Zeek conn.log row
    /// in the same schema as a `FlowEvent::Ended`-derived row.
    ///
    /// **Limit:** the `history` column is emitted as `-` (unset)
    /// because `FlowRecord` doesn't carry the per-packet TCP-
    /// state-transition string. Consumers that need history
    /// should keep using [`Self::write_event`] until FlowRecord
    /// grows a history field.
    ///
    /// Issue #16 — emitter unification at the FlowRecord layer.
    /// Requires the `ipfix` feature.
    #[cfg(feature = "ipfix")]
    pub fn write_flow_record(&mut self, rec: &crate::FlowRecord) -> io::Result<()> {
        self.uid_seq += 1;
        let uid = format!("{}{:016x}", self.options.uid_prefix, self.uid_seq);
        let ts = (rec.flow_start_milliseconds as f64) / 1000.0;
        let duration = ((rec
            .flow_end_milliseconds
            .saturating_sub(rec.flow_start_milliseconds)) as f64)
            / 1000.0;
        let proto = super::csv::flow_record_proto_str(rec);
        let conn_state = flow_record_zeek_state(rec);
        let src_ip = super::csv::flow_record_src_ip(rec);
        let src_port = rec.source_transport_port;
        let dst_ip = super::csv::flow_record_dst_ip(rec);
        let dst_port = rec.destination_transport_port;

        writeln!(
            self.sink,
            "{ts:.6}\t{uid}\t{src_ip}\t{src_port}\t{dst_ip}\t{dst_port}\t{proto}\t{duration:.6}\t{}\t{}\t{conn_state}\t-\t{}\t{}",
            rec.octet_delta_count_initiator,
            rec.octet_delta_count_responder,
            rec.packet_delta_count_initiator,
            rec.packet_delta_count_responder,
        )?;
        Ok(())
    }

    /// Flush buffered output.
    pub fn flush(&mut self) -> io::Result<()> {
        self.sink.flush()
    }

    /// Flush, write the `#close` footer if headers were emitted,
    /// and recover the underlying sink.
    pub fn finish(mut self) -> io::Result<W> {
        if self.options.emit_headers {
            writeln!(self.sink, "#close\t(end)")?;
        }
        self.flush()?;
        Ok(self.sink)
    }
}

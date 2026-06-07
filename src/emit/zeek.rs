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

use crate::FlowEvent;
use crate::extract::FiveTupleKey;

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
    pub fn write_event(&mut self, ev: &FlowEvent<FiveTupleKey>) -> io::Result<()> {
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
        let proto = format!("{:?}", key.proto).to_lowercase();
        let conn_state = reason.as_zeek_state();

        writeln!(
            self.sink,
            "{ts:.6}\t{uid}\t{}\t{}\t{}\t{}\t{proto}\t{duration:.6}\t{}\t{}\t{conn_state}\t{}\t{}\t{}",
            key.a.ip(),
            key.a.port(),
            key.b.ip(),
            key.b.port(),
            stats.bytes_initiator,
            stats.bytes_responder,
            history.as_str(),
            stats.packets_initiator,
            stats.packets_responder,
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

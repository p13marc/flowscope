//! [`FlowEventCsvWriter`] — RFC-4180-quoted CSV sink for
//! `FlowEvent<FiveTupleKey>`.

use std::io::{self, Write};

use crate::FlowEvent;
use crate::extract::FiveTupleKey;

/// CSV writer for [`FlowEvent`] streams.
///
/// Output schema (per [`FlowEvent::Ended`](FlowEvent::Ended)
/// row):
///
/// ```text
/// start_sec, end_sec, duration_sec, proto, src_ip, src_port,
/// dst_ip, dst_port, pkts_init, pkts_resp, bytes_init, bytes_resp,
/// retransmits_init, retransmits_resp, end_reason
/// ```
///
/// When [`CsvOptions::emit_started`] is `true`, every emitted row
/// is prefixed with a `flow_event_kind` column whose values are
/// `"started"` / `"ended"`. Other event variants are skipped.
///
/// The writer takes ownership of the sink and writes the header
/// on construction. Call [`Self::finish`] to flush and recover
/// the underlying sink.
pub struct FlowEventCsvWriter<W: Write> {
    sink: W,
    options: CsvOptions,
}

/// Options for [`FlowEventCsvWriter`].
///
/// Construct via `CsvOptions::default()` then mutate; the struct
/// is `#[non_exhaustive]` so additions stay non-breaking.
#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct CsvOptions {
    /// Emit a `Started` row per flow start (default `false`).
    ///
    /// When `true`, the row schema gains a leading
    /// `flow_event_kind` column (`"started"` / `"ended"`).
    pub emit_started: bool,
    /// Use tabs instead of commas as the field separator
    /// (default `false`).
    pub tab_separated: bool,
}

impl CsvOptions {
    /// Separator character — `'\t'` or `','`.
    fn sep(&self) -> char {
        if self.tab_separated { '\t' } else { ',' }
    }
}

impl<W: Write> FlowEventCsvWriter<W> {
    /// Construct with default options and write the header line.
    pub fn new(sink: W) -> io::Result<Self> {
        Self::with_options(sink, CsvOptions::default())
    }

    /// Construct with custom options and write the header line.
    pub fn with_options(sink: W, options: CsvOptions) -> io::Result<Self> {
        let mut writer = Self { sink, options };
        writer.write_header()?;
        Ok(writer)
    }

    fn write_header(&mut self) -> io::Result<()> {
        let sep = self.options.sep();
        if self.options.emit_started {
            write!(self.sink, "flow_event_kind{sep}")?;
        }
        writeln!(
            self.sink,
            "start_sec{sep}end_sec{sep}duration_sec{sep}proto{sep}src_ip{sep}src_port{sep}\
             dst_ip{sep}dst_port{sep}pkts_init{sep}pkts_resp{sep}bytes_init{sep}bytes_resp{sep}\
             retransmits_init{sep}retransmits_resp{sep}end_reason",
        )?;
        Ok(())
    }

    /// Write one event to the sink. Skips event variants that
    /// don't match the configured schema (per [`CsvOptions`]).
    pub fn write_event(&mut self, ev: &FlowEvent<FiveTupleKey>) -> io::Result<()> {
        match ev {
            FlowEvent::Ended {
                key, reason, stats, ..
            } => {
                let sep = self.options.sep();
                if self.options.emit_started {
                    write!(self.sink, "ended{sep}")?;
                }
                let start = stats.started.to_unix_f64();
                let end = stats.last_seen.to_unix_f64();
                let dur = stats.duration_secs();
                let proto = format!("{:?}", key.proto).to_lowercase();
                writeln!(
                    self.sink,
                    "{start:.6}{sep}{end:.6}{sep}{dur:.6}{sep}{}{sep}{}{sep}{}{sep}{}{sep}{}{sep}\
                     {}{sep}{}{sep}{}{sep}{}{sep}{}{sep}{}{sep}{}",
                    quote(&proto, sep),
                    quote(&key.a.ip().to_string(), sep),
                    key.a.port(),
                    quote(&key.b.ip().to_string(), sep),
                    key.b.port(),
                    stats.packets_initiator,
                    stats.packets_responder,
                    stats.bytes_initiator,
                    stats.bytes_responder,
                    stats.retransmits_initiator,
                    stats.retransmits_responder,
                    reason.as_str(),
                )?;
            }
            FlowEvent::Started { key, ts, .. } if self.options.emit_started => {
                let sep = self.options.sep();
                let start = ts.to_unix_f64();
                let proto = format!("{:?}", key.proto).to_lowercase();
                writeln!(
                    self.sink,
                    "started{sep}{start:.6}{sep}{start:.6}{sep}0.000000{sep}{}{sep}{}{sep}{}{sep}{}{sep}{}{sep}\
                     0{sep}0{sep}0{sep}0{sep}0{sep}0{sep}",
                    quote(&proto, sep),
                    quote(&key.a.ip().to_string(), sep),
                    key.a.port(),
                    quote(&key.b.ip().to_string(), sep),
                    key.b.port(),
                )?;
            }
            _ => {}
        }
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

/// RFC-4180 quoting. Fields containing the separator, a double
/// quote, a carriage return, or a newline are wrapped in double
/// quotes; embedded double quotes are doubled.
fn quote(field: &str, sep: char) -> String {
    let needs_quoting =
        field.contains(sep) || field.contains('"') || field.contains('\n') || field.contains('\r');
    if !needs_quoting {
        return field.to_string();
    }
    let mut out = String::with_capacity(field.len() + 2);
    out.push('"');
    for c in field.chars() {
        if c == '"' {
            out.push('"');
        }
        out.push(c);
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_passthrough_when_no_special_chars() {
        assert_eq!(quote("plain", ','), "plain");
        assert_eq!(quote("10.0.0.1", ','), "10.0.0.1");
    }

    #[test]
    fn quote_wraps_when_separator_in_field() {
        assert_eq!(quote("a,b", ','), "\"a,b\"");
    }

    #[test]
    fn quote_doubles_internal_quotes() {
        assert_eq!(quote("hi \"there\"", ','), "\"hi \"\"there\"\"\"");
    }

    #[test]
    fn quote_wraps_when_newline_or_cr() {
        assert_eq!(quote("a\nb", ','), "\"a\nb\"");
        assert_eq!(quote("a\rb", ','), "\"a\rb\"");
    }

    #[test]
    fn quote_respects_tab_separator() {
        assert_eq!(quote("a\tb", '\t'), "\"a\tb\"");
        // Comma is not a separator under tab mode.
        assert_eq!(quote("a,b", '\t'), "a,b");
    }
}

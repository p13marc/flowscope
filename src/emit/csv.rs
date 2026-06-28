//! [`FlowEventCsvWriter`] — RFC-4180-quoted CSV sink for
//! `FlowEvent<K>` where `K: KeyFields`.

use std::io::{self, Write};

use crate::{FlowEvent, KeyFields};

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

    /// Write one event to the sink. Skips event variants that
    /// don't match the configured schema (per [`CsvOptions`]).
    pub fn write_event<K>(&mut self, ev: &FlowEvent<K>) -> io::Result<()>
    where
        K: KeyFields,
    {
        match ev {
            FlowEvent::Ended {
                key, reason, stats, ..
            } => {
                // Issue #16 close — route through the canonical
                // FlowRecord so emit writers can't drift from
                // the IE-keyed shape. The shadow
                // `original_end_reason` field preserves the
                // 8-variant EndReason fidelity that IPFIX IE
                // 136 would otherwise collapse.
                #[cfg(feature = "ipfix")]
                {
                    let rec = crate::FlowRecord::from_key_fields(stats, key, Some(*reason));
                    return self.write_flow_record(&rec);
                }
                #[cfg(not(feature = "ipfix"))]
                {
                    let sep = self.options.sep();
                    if self.options.emit_started {
                        write!(self.sink, "ended{sep}")?;
                    }
                    let start = stats.started.to_unix_f64();
                    let end = stats.last_seen.to_unix_f64();
                    let dur = stats.duration_secs();
                    let proto = key.proto_str().unwrap_or("").to_lowercase();
                    let src_ip = key.src_ip().map(|ip| ip.to_string()).unwrap_or_default();
                    let src_port = key.src_port().unwrap_or(0);
                    let dst_ip = key.dest_ip().map(|ip| ip.to_string()).unwrap_or_default();
                    let dst_port = key.dest_port().unwrap_or(0);
                    writeln!(
                        self.sink,
                        "{start:.6}{sep}{end:.6}{sep}{dur:.6}{sep}{}{sep}{}{sep}{}{sep}{}{sep}{}{sep}\
                         {}{sep}{}{sep}{}{sep}{}{sep}{}{sep}{}{sep}{}",
                        quote(&proto, sep),
                        quote(&src_ip, sep),
                        src_port,
                        quote(&dst_ip, sep),
                        dst_port,
                        stats.packets_initiator,
                        stats.packets_responder,
                        stats.bytes_initiator,
                        stats.bytes_responder,
                        stats.retransmits_initiator,
                        stats.retransmits_responder,
                        reason.as_str(),
                    )?;
                }
            }
            FlowEvent::Started { key, ts, .. } if self.options.emit_started => {
                let sep = self.options.sep();
                let start = ts.to_unix_f64();
                let proto = key.proto_str().unwrap_or("").to_lowercase();
                let src_ip = key.src_ip().map(|ip| ip.to_string()).unwrap_or_default();
                let src_port = key.src_port().unwrap_or(0);
                let dst_ip = key.dest_ip().map(|ip| ip.to_string()).unwrap_or_default();
                let dst_port = key.dest_port().unwrap_or(0);
                writeln!(
                    self.sink,
                    "started{sep}{start:.6}{sep}{start:.6}{sep}0.000000{sep}{}{sep}{}{sep}{}{sep}{}{sep}{}{sep}\
                     0{sep}0{sep}0{sep}0{sep}0{sep}0{sep}",
                    quote(&proto, sep),
                    quote(&src_ip, sep),
                    src_port,
                    quote(&dst_ip, sep),
                    dst_port,
                )?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Write one finalised `FlowRecord` as a CSV row in the
    /// same schema as a `FlowEvent::Ended`-derived row. Use
    /// this when the consumer already has a `FlowRecord`
    /// in hand (e.g. from `FlowRecord::from_parts` or an
    /// upstream IPFIX-compatible producer).
    ///
    /// Issue #16 — emitter unification at the FlowRecord
    /// layer. Pairs `write_flow_record` with `write_event`;
    /// both produce identical rows for the same flow data.
    ///
    /// Requires the `ipfix` feature.
    #[cfg(feature = "ipfix")]
    pub fn write_flow_record(&mut self, rec: &crate::FlowRecord) -> io::Result<()> {
        let sep = self.options.sep();
        if self.options.emit_started {
            write!(self.sink, "ended{sep}")?;
        }
        let start = (rec.flow_start_milliseconds as f64) / 1000.0;
        let end = (rec.flow_end_milliseconds as f64) / 1000.0;
        let dur = (end - start).max(0.0);
        let proto = flow_record_proto_str(rec).to_string();
        let src_ip = flow_record_src_ip(rec);
        let src_port = rec.source_transport_port;
        let dst_ip = flow_record_dst_ip(rec);
        let dst_port = rec.destination_transport_port;
        let reason = flow_record_reason_str(rec);
        writeln!(
            self.sink,
            "{start:.6}{sep}{end:.6}{sep}{dur:.6}{sep}{}{sep}{}{sep}{}{sep}{}{sep}{}{sep}\
             {}{sep}{}{sep}{}{sep}{}{sep}{}{sep}{}{sep}{}",
            quote(&proto, sep),
            quote(&src_ip, sep),
            src_port,
            quote(&dst_ip, sep),
            dst_port,
            rec.packet_delta_count_initiator,
            rec.packet_delta_count_responder,
            rec.octet_delta_count_initiator,
            rec.octet_delta_count_responder,
            rec.retransmits_initiator,
            rec.retransmits_responder,
            reason,
        )?;
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

/// Map an IPFIX `protocolIdentifier` to the lowercase
/// protocol slug the emitters use. Same vocabulary as
/// `L4Proto::proto_str` but lowercased and inlined to keep
/// the emit module independent of the extract layer.
#[cfg(feature = "ipfix")]
pub(super) fn flow_record_proto_str(rec: &crate::FlowRecord) -> &'static str {
    match rec.protocol_identifier {
        6 => "tcp",
        17 => "udp",
        1 => "icmp",
        58 => "icmpv6",
        132 => "sctp",
        _ => "",
    }
}

#[cfg(feature = "ipfix")]
pub(super) fn flow_record_src_ip(rec: &crate::FlowRecord) -> String {
    rec.source_ipv4_address
        .map(|ip| ip.to_string())
        .or_else(|| rec.source_ipv6_address.map(|ip| ip.to_string()))
        .unwrap_or_default()
}

#[cfg(feature = "ipfix")]
pub(super) fn flow_record_dst_ip(rec: &crate::FlowRecord) -> String {
    rec.destination_ipv4_address
        .map(|ip| ip.to_string())
        .or_else(|| rec.destination_ipv6_address.map(|ip| ip.to_string()))
        .unwrap_or_default()
}

/// Map a [`crate::FlowRecord`] back to the flowscope
/// `EndReason::as_str()` slug. When the record carries a
/// `original_end_reason` shadow field (set by
/// `from_key_fields` / `from_parts`), full 8-variant
/// fidelity is preserved. Otherwise falls back to the
/// lossy IPFIX 5→8 mapping.
///
/// Issue #16 close.
#[cfg(feature = "ipfix")]
pub(super) fn flow_record_reason_str(rec: &crate::FlowRecord) -> &'static str {
    if let Some(reason) = rec.original_end_reason {
        return reason.as_str();
    }
    use crate::ipfix::FlowEndReason as R;
    match rec.flow_end_reason {
        Some(R::IdleTimeout) => "idle_timeout",
        Some(R::ActiveTimeout) => "idle_timeout",
        Some(R::EndOfFlowDetected) => "fin",
        Some(R::ForcedEnd) => "force_closed",
        Some(R::LackOfResources) => "evicted",
        None => "",
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

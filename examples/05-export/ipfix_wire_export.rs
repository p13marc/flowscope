//! Export ended flows as RFC 7011 IPFIX Message bytes.
//!
//! Demonstrates the [`flowscope::ipfix::wire`] binary
//! encoder shipped under issue #28. Uses
//! [`flowscope::ipfix::FlowRecord::from_parts`] (issue #16
//! type) to convert the tracker's `FlowEvent::Ended` into the
//! IPFIX IE-keyed canonical record, then packs records into
//! one or more IPFIX Messages via
//! [`flowscope::ipfix::wire::MessageBuilder`].
//!
//! No socket I/O — the encoder emits byte buffers; this
//! example writes them to stdout (where you'd typically pipe
//! to `nc -u collector 4739` or similar). The transport
//! layer is intentionally out of scope for the encoder.
//!
//! ```bash
//! cargo run --features pcap,ipfix-export --example ipfix_wire_export \
//!     -- trace.pcap > flows.ipfix
//! ```
//!
//! Verify the output with the `tshark` IPFIX decoder:
//!
//! ```bash
//! cat flows.ipfix | tshark -V -i - -O cflow
//! ```

use std::io::{BufWriter, Write, stdout};

use flowscope::extract::FiveTuple;
use flowscope::ipfix::FlowRecord;
use flowscope::ipfix::wire::{
    FLOWSCOPE_TEMPLATE_FLOW_IPV4, FLOWSCOPE_TEMPLATE_FLOW_IPV6, MessageBuilder,
    TEMPLATE_ID_FLOW_IPV4, TEMPLATE_ID_FLOW_IPV6, TemplateRegistry,
};
use flowscope::pcap::PcapFlowSource;
use flowscope::{EndReason, FlowEvent, FlowTracker};

const OBSERVATION_DOMAIN_ID: u32 = 0x0001_0000;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    let mut tracker = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
    let mut sink = BufWriter::new(stdout().lock());

    // Register the IPv4 + IPv6 default templates.
    let mut registry = TemplateRegistry::new(OBSERVATION_DOMAIN_ID);
    registry.register(FLOWSCOPE_TEMPLATE_FLOW_IPV4.clone());
    registry.register(FLOWSCOPE_TEMPLATE_FLOW_IPV6.clone());

    // Round 1: emit the template definitions so a collector
    // can decode subsequent data records.
    let mut msg = MessageBuilder::new(&registry, 0, export_time_now());
    msg.add_template_set(&[TEMPLATE_ID_FLOW_IPV4, TEMPLATE_ID_FLOW_IPV6])?;
    sink.write_all(&msg.finalize()?)?;

    // Round 2: drive the tracker; emit one Data Record per
    // ended flow.
    let mut sequence_number: u32 = 0;
    let mut pending_records: Vec<(FlowRecord, u16)> = Vec::new();

    let emit_records = |pending: &mut Vec<(FlowRecord, u16)>,
                        seq: &mut u32,
                        sink: &mut BufWriter<_>|
     -> Result<(), Box<dyn std::error::Error>> {
        if pending.is_empty() {
            return Ok(());
        }
        let mut msg = MessageBuilder::new(&registry, *seq, export_time_now());
        for (rec, tid) in pending.iter() {
            msg.add_data_record(rec, *tid)?;
        }
        let record_count = msg.data_record_count();
        sink.write_all(&msg.finalize()?)?;
        *seq = seq.wrapping_add(record_count);
        pending.clear();
        Ok(())
    };

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        for ev in tracker.track(&owned) {
            if let Some(rec) = flow_event_to_record(&ev) {
                let tid = if rec.source_ipv4_address.is_some() {
                    TEMPLATE_ID_FLOW_IPV4
                } else {
                    TEMPLATE_ID_FLOW_IPV6
                };
                pending_records.push((rec, tid));
                // Batch up to 32 records per Message to keep
                // under typical MTU.
                if pending_records.len() >= 32 {
                    emit_records(&mut pending_records, &mut sequence_number, &mut sink)?;
                }
            }
        }
    }
    for ev in tracker.finish() {
        if let Some(rec) = flow_event_to_record(&ev) {
            let tid = if rec.source_ipv4_address.is_some() {
                TEMPLATE_ID_FLOW_IPV4
            } else {
                TEMPLATE_ID_FLOW_IPV6
            };
            pending_records.push((rec, tid));
        }
    }
    emit_records(&mut pending_records, &mut sequence_number, &mut sink)?;
    sink.flush()?;
    Ok(())
}

fn flow_event_to_record(ev: &FlowEvent<flowscope::extract::FiveTupleKey>) -> Option<FlowRecord> {
    match ev {
        FlowEvent::Ended {
            key, stats, reason, ..
        } => Some(FlowRecord::from_parts(
            stats,
            key,
            Some(reason_to_owned(*reason)),
        )),
        _ => None,
    }
}

fn reason_to_owned(r: EndReason) -> EndReason {
    r
}

fn export_time_now() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

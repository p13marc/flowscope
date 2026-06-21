//! Ship RFC 7011 IPFIX Messages to a collector over UDP.
//!
//! Companion to `ipfix_wire_export.rs` — that example writes
//! the encoded Messages to stdout; this one wraps the same
//! pipeline in a `std::net::UdpSocket::send_to` loop so the
//! bytes actually reach a netflow collector
//! (`nfcapd` / `softflowd` / `flow-collector`).
//!
//! ## IANA registration
//!
//! IPFIX uses **UDP port 4739** (and SCTP 4739) per IANA
//! Service Name and Transport Protocol Port Number Registry.
//! See <https://www.iana.org/assignments/service-names-port-numbers>.
//!
//! ## SCTP-preferred caveat
//!
//! RFC 7011 §10.3 strongly recommends **SCTP-PR-EXP** over UDP
//! for production IPFIX export — UDP loses templates, which
//! invalidates downstream Data Records (the collector can't
//! decode them). For production:
//!
//! - Use SCTP transport (covered by RFC 6526 IPFIX over SCTP).
//! - If UDP is unavoidable, re-export the template set
//!   periodically (every N seconds or every M Data records) so
//!   newly-restarted collectors can resync. The Cisco /
//!   Juniper / pmacct defaults are every 30s or every 64 Data
//!   records.
//!
//! This example does the second: re-emits the template set
//! every 64 Data records.
//!
//! ## Verification
//!
//! ```bash
//! # In one terminal — start tshark on the loopback to decode
//! # the stream:
//! tshark -i lo -O cflow -V port 4739
//!
//! # In another — run this example, defaults to 127.0.0.1:4739:
//! cargo run --features "pcap,ipfix-export,extractors,tracker" \
//!     --example ipfix_udp_collector -- trace.pcap
//!
//! # Override the destination:
//! IPFIX_DEST=collector.lab:4739 cargo run ... --example ipfix_udp_collector
//! ```
//!
//! Closes #50.

use std::net::UdpSocket;

use flowscope::extract::FiveTuple;
use flowscope::ipfix::FlowRecord;
use flowscope::ipfix::wire::{
    FLOWSCOPE_TEMPLATE_FLOW_IPV4, FLOWSCOPE_TEMPLATE_FLOW_IPV6, MessageBuilder,
    TEMPLATE_ID_FLOW_IPV4, TEMPLATE_ID_FLOW_IPV6, TemplateRegistry,
};
use flowscope::pcap::PcapFlowSource;
use flowscope::{FlowEvent, FlowTracker};

const OBSERVATION_DOMAIN_ID: u32 = 0x0001_0000;
const DEFAULT_DEST: &str = "127.0.0.1:4739";
const TEMPLATE_REFRESH_RECORDS: u32 = 64;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());
    let dest = std::env::var("IPFIX_DEST").unwrap_or_else(|_| DEFAULT_DEST.to_string());

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(&dest)?;
    eprintln!("[ipfix-udp] sending to {dest}");

    let mut registry = TemplateRegistry::new(OBSERVATION_DOMAIN_ID);
    registry.register(FLOWSCOPE_TEMPLATE_FLOW_IPV4.clone());
    registry.register(FLOWSCOPE_TEMPLATE_FLOW_IPV6.clone());

    let mut sequence_number: u32 = 0;
    let mut records_since_template = 0u32;

    let emit_template_set =
        |seq: &mut u32, socket: &UdpSocket| -> Result<(), Box<dyn std::error::Error>> {
            let mut msg = MessageBuilder::new(&registry, *seq, export_time_now());
            msg.add_template_set(&[TEMPLATE_ID_FLOW_IPV4, TEMPLATE_ID_FLOW_IPV6])?;
            let bytes = msg.finalize()?;
            socket.send(&bytes)?;
            Ok(())
        };

    // Initial template emission.
    emit_template_set(&mut sequence_number, &socket)?;

    let mut tracker = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
    let mut pending: Vec<(FlowRecord, u16)> = Vec::new();

    let emit_data = |pending: &mut Vec<(FlowRecord, u16)>,
                     seq: &mut u32,
                     socket: &UdpSocket|
     -> Result<u32, Box<dyn std::error::Error>> {
        if pending.is_empty() {
            return Ok(0);
        }
        let mut msg = MessageBuilder::new(&registry, *seq, export_time_now());
        for (rec, tid) in pending.iter() {
            msg.add_data_record(rec, *tid)?;
        }
        let n = msg.data_record_count();
        let bytes = msg.finalize()?;
        socket.send(&bytes)?;
        *seq = seq.wrapping_add(n);
        pending.clear();
        Ok(n)
    };

    let mut total_records = 0u64;
    for view in PcapFlowSource::open(&path)?.views() {
        let view = view?;
        for ev in tracker.track(&view) {
            if let Some(rec) = flow_event_to_record(&ev) {
                let tid = if rec.source_ipv4_address.is_some() {
                    TEMPLATE_ID_FLOW_IPV4
                } else {
                    TEMPLATE_ID_FLOW_IPV6
                };
                pending.push((rec, tid));
                if pending.len() >= 32 {
                    let n = emit_data(&mut pending, &mut sequence_number, &socket)?;
                    total_records += n as u64;
                    records_since_template += n;
                    if records_since_template >= TEMPLATE_REFRESH_RECORDS {
                        emit_template_set(&mut sequence_number, &socket)?;
                        records_since_template = 0;
                    }
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
            pending.push((rec, tid));
        }
    }
    let n = emit_data(&mut pending, &mut sequence_number, &socket)?;
    total_records += n as u64;

    eprintln!("[ipfix-udp] sent {total_records} Data Record(s)");
    Ok(())
}

fn flow_event_to_record(ev: &FlowEvent<flowscope::extract::FiveTupleKey>) -> Option<FlowRecord> {
    match ev {
        FlowEvent::Ended {
            key, stats, reason, ..
        } => Some(FlowRecord::from_parts(stats, key, Some(*reason))),
        _ => None,
    }
}

fn export_time_now() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as u32)
        .unwrap_or(0)
}

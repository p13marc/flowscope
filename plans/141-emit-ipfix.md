# Plan 141 — `flowscope::emit::ipfix` (IPFIX / NetFlow v9 exporter)

## Summary

Ship an IPFIX (RFC 7011) exporter for `FlowEvent::Ended` records,
with a documented NetFlow v9 (RFC 3954) compatibility mode.
Opens the entire NetFlow-collector consumer ecosystem (nfdump,
Elastiflow, Vector, Splunk Stream, ntopng, nProbe, Logstash
NetFlow input) to flowscope-driven traffic data without a
translation layer.

Uses variable-length IEs (IPFIX-only) to carry flowscope's
enriched fields: SNI, JA3 / JA4 / JA4+, HTTP host, DNS qname.
Falls back to a fixed-template subset in v9 mode (no varlen, no
enterprise IEs).

Output is `impl Write` only — `BufWriter<File>`, `TcpStream`,
or anything implementing `Write` works. Live UDP / SCTP
collector push is a thin wrapper consumers build over the
writer; not bundled.

## Status

Not started.

## Prerequisites

- **Plan 130** (KeyFields trait) — IPFIX template population
  reads `KeyFields::src_ip` / `dest_ip` / `proto_str` etc.
- **Plan 131** (feature graph documented) — new `emit-ipfix`
  feature gates the writer.

## Out of scope

- **Live collector push (UDP / SCTP).** Bundling a UDP socket
  manager is netring's territory. Consumers wrap
  `IpfixWriter<UdpSink>` themselves.
- **Bi-directional flow records (RFC 5103).** Optional. The
  baseline template carries one-direction byte/packet totals;
  reverse-direction fields are an opt-in template variant.
- **IPFIX file format (RFC 5655).** The writer emits IPFIX
  Message Headers + Sets directly; the on-disk file format
  is a thin wrapper.
- **IPFIX Mediation (RFC 6183).** Single-source exporter only.
- **Options Templates beyond basic exporter metadata.**

## Pre-1.0 breaks

None. Additive — new feature, new module.

## Files

| Action | Path | Purpose |
|---|---|---|
| New | `src/emit/ipfix/mod.rs` | `IpfixWriter<W>`, `IpfixOptions`, public API |
| New | `src/emit/ipfix/template.rs` | Template management; sequence/observation IDs; refresh timing |
| New | `src/emit/ipfix/ie.rs` | Information Element definitions; standard IE catalog; ntop PEN-6871 enterprise IEs |
| New | `src/emit/ipfix/encoder.rs` | Wire-format encoder (Message header + Sets + records) |
| Modify | `src/emit/mod.rs` | `pub use ipfix::{IpfixWriter, IpfixOptions};` |
| Modify | `Cargo.toml` | `emit-ipfix = ["emit", "extractors", "dep:bytes"]`; CI matrix entry |
| New | `tests/emit_ipfix.rs` | Wire-format golden fixtures (round-trip decode via `netgauze-flow-pkt`) |
| New | `tests/fixtures/ipfix/` | Hand-validated reference bytes |
| New | `examples/05-export/ipfix_writer.rs` | Pcap → IPFIX file end-to-end |
| New | `docs/ipfix-schema.md` | IE catalog + ntop PEN-6871 IEs used + v9 compat caveats |
| Modify | `CHANGELOG.md` | 0.12 entry |

## API

### `IpfixWriter<W>`

```rust
// src/emit/ipfix/mod.rs

use std::io::{self, Write};

use crate::KeyFields;
use crate::event::FlowEvent;

/// IPFIX (RFC 7011) exporter for [`FlowEvent::Ended`] records.
///
/// Emits IPFIX Messages per the configured refresh policy:
/// template-record refresh every N flows or every T seconds,
/// data records in between. Variable-length IEs carry
/// enriched fields (SNI, JA4, HTTP host) when present.
///
/// For NetFlow v9 compat, set `IpfixOptions::v9_compat = true`
/// — drops varlen IEs and emits v9 Templates / Data FlowSets
/// instead.
pub struct IpfixWriter<W>
where W: Write
{
    sink: W,
    options: IpfixOptions,
    observation_domain_id: u32,
    sequence_number: u32,
    template_id_next: u16,
    flows_since_template_refresh: u32,
    /// Active template ID for our flow record. Established on
    /// first write_event.
    template_id: Option<u16>,
    /// Boot time for sysUptime computation (v9 only).
    boot_time: std::time::Instant,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct IpfixOptions {
    /// Observation Domain ID — exporter-chosen identifier
    /// for this flow stream. Default 0.
    pub observation_domain_id: u32,
    /// Refresh template every N data records. Default 1000.
    pub template_refresh_records: u32,
    /// Refresh template every T seconds regardless of count.
    /// Default 600.
    pub template_refresh_secs: u32,
    /// Include enriched IEs (SNI, JA4, HTTP host) under ntop
    /// PEN-6871 when the corresponding `FlowStats` /
    /// `AnomalyFields` accessors return Some. Default true.
    pub include_enriched_ies: bool,
    /// Emit NetFlow v9 wire format instead of IPFIX. Drops
    /// varlen + enterprise IEs. Default false.
    pub v9_compat: bool,
}

impl Default for IpfixOptions {
    fn default() -> Self { … }
}

impl<W: Write> IpfixWriter<W> {
    pub fn new(sink: W) -> Self {
        Self::with_options(sink, IpfixOptions::default())
    }

    pub fn with_options(sink: W, options: IpfixOptions) -> Self { … }

    /// Write one `FlowEvent::Ended` as an IPFIX Data Record.
    /// Skipped variants (`FlowStarted`, `FlowAnomaly`, etc.)
    /// return `Ok(())` without output.
    pub fn write_event<K>(&mut self, ev: &FlowEvent<K>) -> io::Result<()>
    where K: KeyFields { … }

    /// Force a template-record refresh on the next write.
    pub fn refresh_template(&mut self) { … }

    pub fn flush(&mut self) -> io::Result<()> { self.sink.flush() }
    pub fn finish(mut self) -> io::Result<W> {
        self.flush()?;
        Ok(self.sink)
    }
}
```

### Information Element catalog

Standard IEs from IANA (RFC 7012 § 5):

| IE Name | IE ID | Type | Use |
|---|---|---|---|
| `octetDeltaCount` | 1 | u64 | total bytes |
| `packetDeltaCount` | 2 | u64 | total packets |
| `protocolIdentifier` | 4 | u8 | TCP / UDP / ICMP code |
| `sourceTransportPort` | 7 | u16 | src port |
| `sourceIPv4Address` | 8 | u32 | IPv4 src (if v4) |
| `destinationTransportPort` | 11 | u16 | dst port |
| `destinationIPv4Address` | 12 | u32 | IPv4 dst |
| `tcpControlBits` | 6 | u16 | TCP flags |
| `sourceIPv6Address` | 27 | 16B | IPv6 src |
| `destinationIPv6Address` | 28 | 16B | IPv6 dst |
| `flowEndReason` | 136 | u8 | mapped from `EndReason` |
| `flowStartMilliseconds` | 152 | u64 | started |
| `flowEndMilliseconds` | 153 | u64 | last_seen |

ntop PEN-6871 enterprise IEs (varlen, IPFIX only):

| IE Name | IE ID + PEN | Type | Use |
|---|---|---|---|
| `TLS_SERVER_NAME` | 391+6871 | string | SNI |
| `JA3_HASH` | 642+6871 | string | JA3 |
| `JA4_HASH` | (allocated) | string | JA4 |
| `HTTP_HOST` | 459+6871 | string | HTTP Host header |
| `DNS_QNAME` | (allocated) | string | DNS query name |

Exact ntop PEN-6871 numbers for JA4 and DNS_QNAME need final
verification against ntop's published IE list at plan-lock
time; document under `docs/ipfix-schema.md` with the source
URL.

### `EndReason` → `flowEndReason` mapping

| `EndReason` | `flowEndReason` (RFC 5102 §5.11) |
|---|---|
| `IdleTimeout` | 0x01 (idle timeout) |
| `Fin` / `Rst` | 0x03 (end of flow) |
| `ForceClosed` | 0x04 (forced end) |
| `Evicted` | 0x05 (lack of resources) |
| `BufferOverflow` | 0x05 (lack of resources) |
| `ParseError` | 0x05 |
| `ParserDone` | 0x03 |

## Implementation steps

### Phase 1: Encoder skeleton

1. `Cargo.toml`: add `emit-ipfix` feature pulling `bytes`.
   Defer `netgauze` dep decision until phase 4.
2. `src/emit/ipfix/encoder.rs`: IPFIX Message Header (16 bytes:
   version, length, exportTime, sequenceNumber, ODID). Hand-
   rolled — ~50 LoC.
3. Template Set (Set ID 2): IE definitions per the catalog
   above.
4. Data Set: per-record encoding.

### Phase 2: `IpfixWriter` lifecycle

5. `src/emit/ipfix/mod.rs`: `IpfixWriter::new` /
   `with_options`. State: sequence number, template-refresh
   counter, observation domain.
6. `write_event`: dispatches on `FlowEvent` variant. Only
   `FlowEnded` produces output by default. Maintains template
   refresh policy: refresh after N records or T seconds, or
   on explicit `refresh_template()`.

### Phase 3: IE population

7. `src/emit/ipfix/ie.rs`: standard IE definitions + ntop
   enterprise IE definitions.
8. `KeyFields` accessors → IPFIX IEs: `src_ip` / `dest_ip` to
   `sourceIPv4/6Address` / `destinationIPv4/6Address` based
   on address family; ports; proto from `proto_str` parsing
   (or directly from `L4Proto` when key is `FiveTupleKey`).
9. `FlowStats` → byte/packet counts + start / end ms.
10. `EndReason` → `flowEndReason` mapping.

### Phase 4: Enriched-IE plumbing

11. `KeyFields::app_proto_str` → `applicationName` (IE 96).
12. ntop varlen IEs: SNI from `TlsClientHello` /
    `TlsHandshake` events — but those don't flow into
    `FlowEvent::Ended`. Decision: enriched IEs come from a
    separate `IpfixWriter::record_enrichment(key, enrichment)`
    side-channel API consumers populate from their session-
    parser drains. Documented in `docs/ipfix-schema.md` and
    `examples/05-export/ipfix_writer.rs`.
13. v9 compat mode: skip every varlen and enterprise IE; emit
    v9 Template / Data FlowSets (slightly different format
    headers: `Set ID 0` for Template, `Set ID 1` for Options
    Template, data with Set ID = template ID).

### Phase 5: Tests

14. Hand-validated wire bytes: encode a known FlowEvent::Ended,
    compare to a reference hex string. Includes byte-by-byte
    inspection of Message header, Template Set, Data Set.
15. Round-trip decode via the `netgauze-flow-pkt` decoder (dev-
    dep only — not pulled into the runtime path). Confirms the
    output is parseable by a third-party decoder.
16. v9 compat round-trip via a v9 decoder.

### Phase 6: Example + docs

17. `examples/05-export/ipfix_writer.rs`: pcap → `flows.ipfix`,
    print template + record counts.
18. `docs/ipfix-schema.md`: IE catalog, template ID layout,
    enriched-field recipes, v9 compat caveats, link to RFC 7011
    + RFC 7012 + ntop IE list.

## Tests

### Unit (`src/emit/ipfix/*::tests`)

- `encoder::tests::message_header_16_bytes_with_correct_version`
- `encoder::tests::template_set_layout_matches_rfc7011`
- `encoder::tests::data_record_layout_matches_template`
- `ie::tests::ipv4_address_encoded_big_endian_u32`
- `ie::tests::flow_end_reason_maps_per_rfc5102`

### Integration (`tests/emit_ipfix.rs`)

- `ipfix_one_record_decodes_via_netgauze`
- `ipfix_template_refreshes_after_n_records`
- `ipfix_template_refreshes_after_t_seconds`
- `ipfix_v9_compat_drops_varlen_ies`
- `ipfix_enrichment_side_channel_populates_sni_field`
- `ipfix_ipv6_flow_uses_ipv6_address_ies`
- `ipfix_custom_key_via_key_fields_works`
- `ipfix_flow_end_reason_idle_maps_to_0x01`

### Wire-format golden fixtures

- `tests/fixtures/ipfix/single_tcp_flow.ipfix.hex` — known-good
  bytes for a single TCP `FlowEnded`, with a template + data
  record. Diffable.

## Acceptance criteria

- `cargo build --features emit-ipfix,extractors` clean.
- `cargo test --features emit-ipfix,extractors,pcap` clean.
- `cargo clippy --features emit-ipfix --all-targets -- -D warnings`
  clean.
- New `emit-ipfix` CI matrix entry clean.
- `examples/05-export/ipfix_writer.rs` runs end-to-end on
  `tests/data/mixed_short.pcap` producing a file that
  `netgauze-flow-pkt` decodes cleanly.
- `docs/ipfix-schema.md` complete.
- v9 compat mode round-trips via `nfdump -r` (manual
  verification noted in the docs).

## Risks

- **R1: ntop PEN-6871 IE number drift.** ntop occasionally
  renumbers enterprise IEs. Mitigation: pin the IE numbers in
  `docs/ipfix-schema.md` against a specific commit of the ntop
  reference; gate against hand-validated bytes that fail loud
  if a number was wrong.
- **R2: `netgauze-flow-pkt` dev-dep size.** ~500 KB compiled,
  brings the full IPFIX codec for round-trip tests only.
  Acceptable as dev-dep; not pulled into the runtime path.
- **R3: Enriched-IE side-channel ergonomics.** Consumers must
  call `record_enrichment(key, sni)` after their session parser
  drains and before the `FlowEnded` event comes through. If
  they get the ordering wrong, enriched IEs go missing.
  Mitigation: document the pattern in `docs/ipfix-schema.md`
  + the example; provide a `with_enrichment_buffer(usize)`
  option that buffers enrichments per-key keyed until the
  matching `FlowEnded` arrives.
- **R4: v9 compat round-trip fragility.** Some v9 collectors
  are picky about template set ordering. Mitigation: hand-
  validated against `nfcapd` from `nfdump`.

## Effort

| Step | LoC | Hours |
|---|---|---|
| Encoder skeleton (Message + Set headers) | 150 | 3 |
| `IpfixWriter` lifecycle + refresh policy | 200 | 4 |
| IE catalog + standard IE population | 250 | 5 |
| Enriched-IE side-channel + ntop IEs | 180 | 4 |
| v9 compat mode | 120 | 3 |
| Tests (5 unit + 8 integration + golden hex) | 350 | 6 |
| Example + docs/ipfix-schema.md | 180 | 3 |
| CHANGELOG | 40 | 1 |
| **Total** | **~1470** | **~29 hours (~4 days)** |

## Provenance

netring 0.21 wishlist (Phase E §"IPFIX exporter"). The 0.12
audit ranked this Tier-1 second-highest-ROI ("opens entire
NetFlow-collector consumer base"). nfdump, Elastiflow, Vector,
Splunk Stream, ntopng all ingest IPFIX natively in 2026;
shipping IPFIX makes flowscope data immediately consumable by
the existing observability pipeline ecosystem without a
translation step. Higher payoff than yet-another text format
because the consumer base is already there.

References:
- RFC 7011 (IPFIX Protocol)
- RFC 7012 (Information Model)
- RFC 5102 (Flow Information Element Specifications)
- RFC 3954 (NetFlow Services v9)
- ntop PEN-6871 IE list: `ntop.org/guides/nProbe/Custom%20IPFIX%20Information%20Elements.html`
- `github.com/NetGauze/NetGauze` (`netgauze-flow-pkt`)

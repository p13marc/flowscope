# Migrating from 0.19 to 0.20

The 0.20 cycle is mostly additive (NSM primitives + a 1.0-prep
issue batch). There is **one breaking output-schema change** —
the EVE `flow_hash` field — plus a feature-umbrella fix that may
change what `--features full` pulls in.

## Breaking change — EVE `flow_hash` removed; `community_id` is canonical (#88)

`EveJsonWriter` no longer emits the proprietary 64-bit FNV-1a
`flow_hash` field. The standard Corelight **Community ID**
(`community_id`) is now the sole, portable flow identifier in EVE
output. This applies to both the event-driven path
(`write_event`) and the FlowRecord path (`write_flow_record`).

`community_id` is emitted **only when the crate is built with the
`community-id` feature** (it needs SHA-1 + base64). If you relied
on `flow_hash` being present unconditionally, enable the feature:

```diff
  # Cargo.toml
- flowscope = { version = "0.20", features = ["emit-eve"] }
+ flowscope = { version = "0.20", features = ["emit-eve", "community-id"] }
```

**Dashboard / pipeline migration.** Re-key any correlation on the
new field:

```diff
- | where flow_hash="9f3c0bb2a17f5048"
+ | where community_id="1:wCb3Oy8JZ7qWp0pXm1mUg6yQ7sE="
```

`community_id` is direction-invariant and deterministic (same
guarantees `flow_hash` had) and additionally interoperable with
Zeek / Suricata / Security Onion / Arkime, which all key on it.

**Still need the FNV hash in-process?** It remains available — it
just isn't serialized:

```rust
use flowscope::KeyFields;
let h: Option<u64> = key.stable_hash();      // generic, Option
let h: u64        = five_tuple.stable_hash(); // FiveTupleKey, infallible
```

Treat it as a non-portable sharding / in-memory keying value, not
a cross-tool identifier.

**`FlowRecord` gains `community_id`.** `FlowRecord` now carries a
`community_id: Option<String>` field, populated by `from_parts` /
`from_key_fields` when the `community-id` feature is on. This is
additive (the struct is `#[non_exhaustive]`) and means the
NDJSON / CSV / EVE FlowRecord paths all surface the id.

## Behavior change — `l7` / `full` feature umbrellas corrected (#87)

Before 0.20, `full` carried *fewer* parsers than `l7` and was not
a superset (a long-standing bug masked by `--all-features`).

- **`l7`** now enables **every license-clean protocol parser**
  (the previous 15 plus quic / smb / ldap / kerberos / smtp / ftp
  / snmp / radius / modbus / dnp3 / stun / rdp / wireguard /
  netbios-ns).
- **`full`** is now `l7` + every license-clean capability
  (`tcp_fingerprint`, `asset`, `analysis`, `ml-features`,
  `ml-features-nprint`, `ipfix`, `ipfix-export`, plus the existing
  observability / emit / aggregate / file-hash / fingerprint /
  community-id / pcap / serde / chrono groups). It deliberately
  **excludes** the FoxIO-licensed `ja4plus` suite so `full` stays
  royalty-free-clean.

If you built with `--features full` and want the old, smaller set,
pin the specific parser features you actually use instead of the
umbrella. If you relied on `full` and were silently *missing* the
Tier-2 parsers, they now build in — no action needed.

Compile-time guards in `src/feature_umbrellas.rs` plus new `l7` /
`full` CI matrix entries keep the invariant (`full ⊇ l7`, every
parser in an umbrella) from regressing.

## Additive — per-packet `source_idx` builders (#69)

New one-call builders for the most common live-capture metadata
field (no behavior change):

```rust
use flowscope::{PacketView, RxMetadata, Timestamp};

// On a view (hot path):
let view = PacketView::new(frame, ts).with_source_idx(nic_index);

// Constructing RxMetadata cross-crate (RxMetadata is #[non_exhaustive]):
let meta = RxMetadata::from_source_idx(nic_index);
```

These replace the old three-step
`let mut m = RxMetadata::default(); m.source_idx = n; view.with_rx_metadata(m)`.

## Breaking change — 16 `parse()` parsers now return `Result` (#85)

The remaining hand-rolled wire parsers' free `parse*()` functions changed
from `Option<T>` to `Result<T, ParseError>`, with a per-module,
`#[non_exhaustive]` `ParseError` enum — the same shape the 0.18 binary
parsers (dnp3 / smb / ldap / kerberos / quic) adopted in #65. This lets a
caller distinguish "not my protocol" from "truncated / malformed".

Affected free functions (re-exported `ParseError` per module):

| Module | Function | New return |
| ------ | -------- | ---------- |
| `arp` | `parse`, `parse_frame` | `Result<ArpMessage, arp::ParseError>` |
| `ndp` | `parse`, `parse_icmpv6` | `Result<NdpMessage, ndp::ParseError>` |
| `lldp` | `parse`, `parse_frame` | `Result<LldpMessage, lldp::ParseError>` |
| `cdp` | `parse`, `parse_frame` | `Result<CdpMessage, cdp::ParseError>` |
| `dhcp` | `parse` | `Result<DhcpMessage, dhcp::ParseError>` |
| `ssdp` | `parse` | `Result<SsdpMessage, ssdp::ParseError>` |
| `netbios_ns` | `parse` | `Result<NbnsMessage, netbios_ns::ParseError>` |
| `stun` | `parse` | `Result<StunMessage, stun::ParseError>` |
| `ssh` | `parse_kexinit_payload` | `Result<SshKexInit, ssh::ParseError>` |
| `ntp` | `parse` | `Result<NtpMessage, ntp::ParseError>` |
| `tftp` | `parse` | `Result<TftpMessage, tftp::ParseError>` |
| `wireguard` | `parse` | `Result<WireGuardMessage, wireguard::ParseError>` |
| `modbus` | `parse_one` | `Result<(ModbusMessage, usize), modbus::ParseError>` |
| `rdp` | `parse_frame` | `Result<RdpMessage, rdp::ParseError>` |
| `snmp` | `parse` | `Result<SnmpMessage, snmp::ParseError>` |
| `radius` | `parse` | `Result<RadiusMessage, radius::ParseError>` |

**Migration recipe.** Most call sites are a one-token change — `Option`
combinators map straight onto `Result`:

```diff
- if let Some(msg) = flowscope::arp::parse(payload) {
+ if let Ok(msg) = flowscope::arp::parse(payload) {
      handle(msg);
  }

- let Some(msg) = flowscope::arp::parse_frame(frame) else { continue };
+ let Ok(msg) = flowscope::arp::parse_frame(frame) else { continue };
```

`.unwrap()` / `.expect(...)` work unchanged. To branch on *why* a parse
failed, match the typed `ParseError`:

```rust
match flowscope::stun::parse(datagram) {
    Ok(msg) => handle(msg),
    Err(flowscope::stun::ParseError::NotStun) => {}        // not STUN — ignore
    Err(e) => log::debug!("malformed STUN: {e}"),          // truncated etc.
}
```

**Unified error bridge.** Every per-module `ParseError` (the 16 above and
the 5 from #65) now implements `From<ParseError> for flowscope::Error` and
has a matching `flowscope::Module` variant, so it bubbles through `?` into a
`flowscope::Result` while keeping its typed form:

```rust
fn handle(payload: &[u8]) -> flowscope::Result<()> {
    let msg = flowscope::dhcp::parse(payload)?; // ParseError -> flowscope::Error
    // ...
    Ok(())
}
```

**Not affected:** the `SessionParser` / `DatagramParser` trait methods
(`feed_*` / `parse(&mut Vec<…>)`) and the `*_from_pcap` helpers keep their
signatures — only the free `parse*()` functions changed.

## Breaking change — 43 public types are now `#[non_exhaustive]` (#78)

The pre-1.0 API-stability sweep brought the remaining growable public
structs/enums into line with the project rule (`#[non_exhaustive]` on
everything that may grow). This affects only code in **other crates**
(your code, integration tests, examples) that **constructed these types
with a struct literal** or **matched an enum exhaustively** — reading
their public fields is unchanged.

Affected types include the DNS / HTTP / TLS / ICMP wire records and
message enums (`DnsQuery`, `DnsResponse`, `DnsQuestion`, `DnsRecord`,
`DnsRdata`, `DnsParseResult`, `HttpRequest`, `HttpResponse`, `HttpMessage`,
`HttpVersion`, `TlsAlert`, `TlsMessage`, `IcmpMessage`, `IcmpInner`), the
`DnsConfig` / `HttpConfig` / `TlsConfig` structs, the flow keys
(`FiveTupleKey`, `IpPairKey`, `FlowLabelKey`, `TaggedKey`), the encap
combinators (`InnerVxlan`, `InnerGtpU`, `InnerGre`, `FlowLabel`, `Tagged`,
`AutoDetectEncap`, `AutoEncapVariants`), the JA4 `Ja4Parts` / `Ja4sParts` /
`Ja4tParts`, `event::OverflowPolicy` / `event::FlowState`, `Extracted`,
`correlate::BurstHit`, `detect::FlowFingerprint`, `detect::RiskSeverity`,
`FlowEntry`, `FlowTrackerStats`, `tcp_state::Transition`, and the IPFIX
`InformationElement` / `FieldSpec` / `TemplateDefinition`.

### Recipe 1 — construct via the new `new()` constructors

Records and keys gained `new()` constructors:

```rust
// before (0.19)
let key = FiveTupleKey { proto: L4Proto::Tcp, a, b };
let rec = DnsRecord { name: "example.com".into(), rtype, rclass, ttl, data };

// after (0.20)
let key = FiveTupleKey::new(L4Proto::Tcp, a, b);
let rec = DnsRecord::new("example.com", rtype, rclass, ttl, data);
```

New constructors: `DnsQuery::new`, `DnsResponse::new`, `DnsQuestion::new`,
`DnsRecord::new`, `HttpRequest::new`, `HttpResponse::new`, `TlsAlert::new`,
`IcmpMessage::new`, `IcmpInner::new`, `Extracted::new`,
`FiveTupleKey::new`, `IpPairKey::new`, `FlowLabelKey::new`,
`TaggedKey::new`. The encap combinators already had `new()` / `with_*`.

### Recipe 2 — configs: `default()` + field mutation

```rust
// before
let cfg = DnsConfig { max_pending: 1024, ..Default::default() };
// after
let mut cfg = DnsConfig::default();
cfg.max_pending = 1024;
```

### Recipe 3 — add a wildcard arm to exhaustive matches

```rust
match msg {
    HttpMessage::Request(_) => { /* … */ }
    HttpMessage::Response(_) => { /* … */ }
    _ => { /* required: the enum is now #[non_exhaustive] */ }
}
```

**Not affected:** field *reads* (`key.proto`, `rec.ttl`, …) work exactly
as before; only construction and exhaustive matching from outside the
crate change.

## Additive — generic pcap iterators alongside the typed helpers (#86)

**No migration needed.** The per-parser `*_from_pcap` helpers are **kept**
— they are the strongly-typed, high-level front door and return the
*specific* message type (`Box<TlsClientHello>`, `QuicInitial`,
`HttpRequest`). 0.20 adds two generic, registration-free building blocks
*underneath* them for parsers without a bespoke helper (or with non-`Default`
config):

```rust
// The typed helper — unchanged, still the recommended path:
for (key, hello) in flowscope::tls::client_hellos_from_pcap("trace.pcap")? { … }

// New generic building block — any SessionParser / DatagramParser:
use flowscope::stun::StunParser;
for (key, msg) in flowscope::pcap::session_messages::<StunParser>("trace.pcap")? { … }
```

- `session_messages::<P>` drives a TCP `SessionParser`; `datagram_messages::<P>`
  drives a UDP `DatagramParser`. Both key by `FiveTupleKey`, use the
  bidirectional 5-tuple extractor, and require `P: Default`.
- The only deprecation: `flow_summaries_from_pcap` → **`flow_summaries`**
  (a pure rename; the old name is a `#[deprecated]` alias).
- The multi-parser case stays `Driver::run_pcap` + per-parser slot drain.

## Breaking change — `parser_kind()` returns `ParserKind`, not `&'static str` (#109)

`SessionParser::parser_kind` / `DatagramParser::parser_kind` now return the
typed [`ParserKind`] enum (default `ParserKind::Unspecified`, was `""`). The
same lift applies to `driver::Event::ParserClosed::parser_kind`,
`SlotHandle::parser_kind` / `SlotDrain::parser_kind`, `BroadcastSlotHandle`,
and the `AccumulatingSessionParser::new` / `PerDatagramParser::new` /
`test_helpers::events::parser_closed` constructors.

Only **direct callers** and **downstream parser impls** are affected — the
typed driver, slots, and `*_from_pcap` helpers are unchanged.

```rust
// before (0.19) — downstream parser impl
fn parser_kind(&self) -> &'static str { "my-proto" }

// after (0.20)
fn parser_kind(&self) -> flowscope::ParserKind {
    flowscope::ParserKind::Other("my-proto")  // or a built-in variant
}
```

```rust
// before — reading the kind off a slot / event
let label: &str = slot.parser_kind();
match ev { Event::ParserClosed { parser_kind, .. } if parser_kind == "tls" => … }

// after — match the variant, or `.as_str()` for the slug
let label: &str = slot.parser_kind().as_str();
match ev { Event::ParserClosed { parser_kind, .. }
    if parser_kind == flowscope::ParserKind::Tls => … }
```

- **Built-in parsers** return a dedicated variant (`ParserKind::Http1`,
  `ParserKind::DnsUdp`, `ParserKind::Quic`, …). `parser_kind().as_str()`
  yields the identical slug the `&'static str` did, so metric labels and
  emitted JSON are byte-for-byte unchanged (the `parser_kind` field still
  serializes as a plain string).
- **Custom parsers** wrap a stable slug in `ParserKind::Other("crate/proto")`.
- `ParserKind::from_slug(s)` is the inverse for built-in slugs; the
  `parser_kinds::*` `&str` constants are still available for raw slug
  comparison.

[`ParserKind`]: https://docs.rs/flowscope/latest/flowscope/enum.ParserKind.html

## Breaking change — driver/event convergence: removed driver types (#98 / #99 / #100)

The public driver surface converges on the single typed
`driver::Driver<E>`. Three older shapes are gone:

**1. `FlowSessionDriver` / `FlowDatagramDriver` removed (#99).** The
per-parser session/datagram engines are now crate-private. Register the
parser as a slot on the typed driver instead:

```rust
// before (0.19) — one engine per parser
let mut driver = FlowSessionDriver::new(FiveTuple::bidirectional(), HttpParser::default());
for ev in driver.handle(view) { /* SessionEvent */ }

// after (0.20) — one typed Driver, one slot per parser
let mut builder = Driver::builder(FiveTuple::bidirectional());
let http = builder.session_on_ports(HttpParser::default(), [80, 8080]);
let mut driver = builder.build();
let mut events = Vec::new();
driver.track_into(view, &mut events);   // flow lifecycle Event<K>
let mut msgs = Vec::new();
http.drain(&mut msgs);                   // typed HttpParser messages
```

For the common offline case, the per-parser `*_from_pcap` helpers and
the generic `pcap::session_messages::<P>` / `datagram_messages::<P>`
building blocks (see the #86 section above) cover most former
`FlowSessionDriver`/`FlowDatagramDriver` uses without touching the
driver at all.

**2. `Driver::deferred()` / `DeferredDriverBuilder` / `build_with()`
removed (#98).** The deferred-builder split is gone; build the driver
directly with `Driver::builder(extractor)` and register slots before
`build()`. If you previously deferred slot registration until an
extractor was available, restructure so the extractor is known at
`builder(...)` time (it almost always is).

**3. `SessionEvent` retired from the public API (#100).** The internal
engine carrier is no longer exported. Consume flow lifecycle via
`Event<K>` from the typed driver (`track_into` / `run_pcap`), and typed
messages via the parser's `SlotHandle` (`drain` / `drain_n`). For the
offline single-parser case, `pcap::session_pulses::<P>` / `Pulse<K, M>`
(#111) deliver both lifecycle and messages in one ordered stream.

The low-level `FlowDriver` (the sync reassembly wrapper) is unchanged.

## Breaking change — `Event<K>` variants drop the `Flow` prefix (#110)

`driver::Event<K>` variants are renamed to match `event::FlowEvent<K>`
(which never had the prefix). Mechanical rename at every match / construct
site:

```rust
// before (0.19)
match ev {
    Event::FlowStarted { key, .. }   => …,
    Event::FlowPacket { len, .. }    => …,
    Event::FlowEnded { reason, .. }  => …,
    _ => {}
}

// after (0.20)
match ev {
    Event::Started { key, .. }   => …,
    Event::Packet { len, .. }    => …,
    Event::Ended { reason, .. }  => …,
    _ => {}
}
```

Full mapping: `FlowStarted → Started`, `FlowEstablished → Established`,
`FlowStateChange → StateChange`, `FlowPacket → Packet`,
`FlowEnded → Ended`, `FlowTick → Tick`. `FlowAnomaly`, `TrackerAnomaly`,
and `ParserClosed` are unchanged.

- If you serialize `Event` directly, the `type` tag for these variants
  changes from `"flow_started"` &c. to `"started"` &c. (now identical to
  `FlowEvent`'s tags). The shipped CSV / EVE / NDJSON emitters serialize
  `FlowEvent`, not `Event`, so their output is unchanged.

## Breaking change — `orientation` on `Started` / `Packet` events (#118)

`FlowEvent::{Started, Packet}` and `driver::Event::{Started, Packet}`
gain an `orientation: Orientation` field next to the existing `side`.
`side` ([`FlowSide`]) is the **logical role** (who started the flow),
inferred from arrival order; `orientation` ([`Orientation`]) is the
**deterministic, address-sorted** direction (`Forward` = the packet's
src→dst matches the canonical key's `a→b`, `Reverse` = swapped). Unlike
`side`, `orientation` does not depend on which packet of the flow was
seen first, so it is stable across a tap-merge / two-NIC race. See
`docs/concepts.md` → "Direction, orientation, and capture leg" for the
full model (issue #71).

**Patterns** — add the field or a trailing `..`:

```rust
// before (0.19)
match ev {
    FlowEvent::Packet { key, side, len, ts } => …,
    _ => {}
}

// after (0.20) — bind it …
match ev {
    FlowEvent::Packet { key, side, orientation, len, ts } => …,
    _ => {}
}
// … or ignore it
match ev {
    FlowEvent::Packet { key, side, .. } => …,
    _ => {}
}
```

**Construction** — production code never builds these events (the
tracker does). For synthetic events in tests, prefer the blessed
constructors:

```rust
use flowscope::test_helpers::events; // needs the `test-helpers` feature
let started = events::started(key, ts);
let pkt     = events::packet_side(key, FlowSide::Responder, 100, ts);
```

If you construct the struct directly, add `orientation`:

```rust
FlowEvent::Packet {
    key, side: FlowSide::Initiator,
    orientation: Orientation::Forward, // NEW
    len: 100, ts,
};
```

**serde** — the wire gains an additive `"orientation": "forward"` /
`"reverse"` field on `started` / `packet` records. Existing fields are
unchanged; a reader that ignores unknown fields is unaffected.

**New companions** (additive, no migration needed):

- `FlowStats::initiator_orientation` — which `Orientation` the flow's
  initiator had; available on `Ended` / `Tick` / snapshots.
- `FlowStats::side_for(orientation)` / `orientation_for(side)` —
  translate between the two axes for that flow.
- `FlowEntry::initiator_orientation()` — same, on a live snapshot.
- `Orientation::flipped()` / `as_str()` + `Default` (`Forward`).

[`FlowSide`]: https://docs.rs/flowscope/latest/flowscope/enum.FlowSide.html
[`Orientation`]: https://docs.rs/flowscope/latest/flowscope/enum.Orientation.html

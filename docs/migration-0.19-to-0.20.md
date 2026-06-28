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

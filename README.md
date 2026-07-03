# flowscope

[![crates.io](https://img.shields.io/crates/v/flowscope.svg)](https://crates.io/crates/flowscope)
[![docs.rs](https://img.shields.io/docsrs/flowscope)](https://docs.rs/flowscope)
[![CI](https://github.com/p13marc/flowscope/actions/workflows/rust.yml/badge.svg)](https://github.com/p13marc/flowscope/actions)
[![MSRV 1.88](https://img.shields.io/badge/MSRV-1.88-blue.svg)](https://blog.rust-lang.org/2025/03/05/Rust-1.88.0/)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

**Passive network telemetry as a library.** A runtime-free Rust
crate that turns raw frames into typed flow records, L7
sessions, and security signals — without spinning up a tokio
runtime, without rebuilding a Suricata.

Bring your own bytes (pcap, AF_XDP, eBPF, tun/tap, embedded);
flowscope gives you back biflow accounting, TCP reassembly,
per-protocol parsers, and structured output ready for SIEM
ingest.

---

## Pick your output

```rust,no_run
// Suricata-compatible EVE JSON for your existing Filebeat /
// Splunk / Tenzir pipeline.
use flowscope::emit::EveJsonWriter;
let mut eve = EveJsonWriter::new(std::io::stdout());
# fn ex(ev: &flowscope::FlowEvent<flowscope::extract::FiveTupleKey>) -> std::io::Result<()> {
eve.write_event(ev)?;
# Ok(()) }
```

```rust,no_run
// RFC 7011 binary IPFIX, no nProbe needed.
use flowscope::ipfix::wire::{MessageBuilder, FLOWSCOPE_TEMPLATE_FLOW_IPV4};
# fn ex(rec: &flowscope::FlowRecord) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
let mut m = MessageBuilder::new(1, 12345);
m.add_template(&FLOWSCOPE_TEMPLATE_FLOW_IPV4)?;
m.add_data_record(&FLOWSCOPE_TEMPLATE_FLOW_IPV4, rec)?;
Ok(m.finish())
# }
```

```rust,no_run
// CICFlowMeter-shaped ML feature vector for IDS training.
# #[cfg(feature = "ml-features")]
# fn ex(rec: &flowscope::FlowRecord, stats: &flowscope::FlowStats)
#   -> flowscope::ml_features::CicFlowFeatures {
flowscope::ml_features::CicFlowFeatures::from_flow_record(rec).with_iat(stats)
# }
```

Or write your own consumer over `FlowEvent` + typed L7 messages.
That's the whole shape.

## From pcap to SNI in five lines

```rust,no_run
# fn main() -> flowscope::Result<()> {
for (key, hello) in flowscope::tls::client_hellos_from_pcap("trace.pcap")? {
    let sni = hello.sni.as_deref().unwrap_or("(none)");
    println!("{key:?} → SNI={sni}");
}
# Ok(()) }
```

Same one-call shape for the marquee parsers:

```rust,no_run
# fn main() -> flowscope::Result<()> {
// HTTP/3 + DoQ ClientHello via RFC 9001 §5.2 passive decrypt.
for (key, init) in flowscope::quic::initials_from_pcap("trace.pcap")? {
    println!("{key:?} {} sni={:?}", init.version, init.sni);
}

// SMB lateral-movement events with the typed admin-share /
// admin-pipe predicates and DCE-RPC bind UUIDs.
for (key, msg) in flowscope::smb::messages_from_pcap("trace.pcap")? {
    if msg.tree_connect_is_admin_share {
        println!("{key:?} admin-share TREE_CONNECT to {:?}", msg.tree_connect_path);
    }
    for uuid in &msg.dcerpc_bind_uuids {
        if let Some(name) = uuid.well_known_name() {
            println!("{key:?} DCE-RPC bind to {name} ({uuid})");
        }
    }
}
# Ok(()) }
```

The per-parser `*_from_pcap` helpers are the strongly-typed front
door over a generic building block: for any protocol — including
parsers without a dedicated helper — use
`flowscope::pcap::session_messages::<P>(path)` /
`datagram_messages::<P>(path)`, which yield `(FiveTupleKey, P::Message)`
for any `SessionParser` / `DatagramParser`. To interleave flow
lifecycle **and** typed messages from one parser in wire order, use
`flowscope::pcap::session_pulses::<P>(path)` / `datagram_pulses::<P>`,
which yield a single ordered `Pulse<K, M>` stream.

For per-port filtering, multiple parsers per pcap, or live
NIC capture, drop down to `Driver::builder(ext)` — the typed
low-level driver with one `SlotHandle<M, K>` per parser and the
flow-lifecycle `Event<K>` stream. See
[`examples/07-multi-protocol/`](examples/07-multi-protocol/).

---

## What you can do with it

flowscope ships 30+ feature-gated parsers and analytics modules.
Highlights:

- **Web & encrypted traffic.** TLS handshake + ECH +
  [JA3 / JA4](https://github.com/FoxIO-LLC/ja4) client
  fingerprints. **QUIC Initial** passive decrypt → ClientHello
  SNI / ALPN — the only L7 visibility you have on HTTP/3 +
  DoQ. **Post-quantum ClientHello reassembly** (X25519MLKEM768
  splits the CH across segments / Initials) so SNI + fingerprints
  survive. **Encrypted-DNS + HTTP/2·3 identification** from
  ALPN / SNI / port (`app_proto` — DoH / DoT / DoQ, h2 / h3),
  no decryption.
- **Evasion-hardening.** IP-fragment reassembly
  (`ip_fragment` — RFC 5722 overlap-drop) so a fragmented
  payload can't slip past an L4/L7 parser.
- **AD recon & lateral movement.** Kerberos
  (Kerberoast / RC4 downgrade signal), LDAP
  (`servicePrincipalName` queries =
  [GetUserSPNs](https://attack.mitre.org/techniques/T1558/003/) /
  BloodHound enum), SMB2/3 (admin shares, admin pipes —
  `svcctl` / `lsarpc` / `spoolss`, NTLM identity, DCE-RPC
  bind UUIDs).
- **OT / ICS.** Modbus/TCP, DNP3 (IEEE 1815-2012), passive
  WireGuard.
- **Asset discovery.** ARP / NDP / DHCP (with Fingerbank-style
  fingerprint) / LLDP / CDP / mDNS / NetBIOS-NS / SSDP, unified
  in a MAC-keyed `Inventory` via the `asset` feature — now
  **correlating TLS / SSH / p0f fingerprints** (JA3 / JA4 / JA4X
  / HASSH / p0f) and x509 subject / SAN into the same record, with
  a derived device `role()`.
- **Anomaly detectors.** Beaconing (RITA-style CV), port-scan
  (TRW / Jung 2004), DGA (bigram log-likelihood with embedded
  English baseline), entropy + n-gram primitives.
- **Traffic accounting.** Throughput grouped by an opaque owner
  key — PID / cgroup / security identity — via `BandwidthByKey`,
  so you get bandwidth-by-process without flowscope ever learning
  what a process is.
- **Structured output.** Suricata-compatible EVE JSON, Zeek
  `conn.log`, NDJSON, CSV, binary IPFIX (RFC 7011/7012),
  CICFlowMeter ML feature vectors, nPrint per-packet bit
  matrices.

Full feature list and stability notes: [CHANGELOG.md](CHANGELOG.md).
Each feature gates a module on its own Cargo flag — pick what
you need; pay for nothing else.

## The shape

```
                  ┌─ asset discovery (arp/dhcp/lldp/mdns/...)
PacketView        │
   │              ├─ TCP/UDP flow tracking (FlowTracker)
   ▼              │     │
extract key       │     ▼
   │              │  reassembled byte stream
   ▼              │     │
biflow + L4 ──────┘     ▼
                     SessionParser / DatagramParser
                           │  one typed message per slot
                           ▼
                     your consumer  →  EVE / IPFIX / ML / your sink
```

Four traits, one driver loop:

| Trait | Role |
|---|---|
| `FlowExtractor` | frame → flow key (5-tuple, IP pair, MAC pair, …) + decap combinators (VLAN, MPLS, VXLAN, GTP-U, GRE) |
| `FlowTracker` | bidirectional accounting, TCP state machine, idle timeout, LRU eviction |
| `Reassembler` | sync per-(flow, side) hook on the byte stream |
| `SessionParser` / `DatagramParser` | typed L7 messages |

Always-on guarantees: **no tokio in the core**, no global state, bounded memory
(every queue has a cap), `#[non_exhaustive]` on every public struct/enum that
may grow, deterministic state machines, no `unsafe` outside justified zero-copy
spots. `Driver<E>` and `SlotHandle<M, K>` are `Send + Sync` —
`tokio::spawn(driver_task)` just works.

Every flow event also carries a **deterministic `Orientation`** (address-sorted
`Forward`/`Reverse`) next to the arrival-order `FlowSide` — stable across a
tap-merge race, so Community ID ordering, biflow keys and cross-sensor dedup
agree between captures. Merged flows even remember which NIC each direction
arrived on (`FlowStats::source_idx_for`). See
[`docs/concepts.md`](docs/concepts.md) → "Direction, orientation, and capture
leg".

## Where flowscope sits

- vs. **Suricata / Zeek**: same protocol coverage, library-shaped. Embed in a
  Rust binary or tokio service instead of running an IDS sidecar.
- vs. **libpcap / pnet**: those give you frames; flowscope gives you flows +
  sessions + typed L7. Use them together.
- vs. **netflow exporters**: flowscope produces IPFIX with `ipfix-export`,
  no separate daemon.
- vs. **CICFlowMeter / nPrint**: parity for both ML feature vocabularies, in
  one Rust crate, no Java / Python.
- vs. **building it yourself**: TCP reassembly, biflow canonicalisation, idle
  timeouts, ICMP error → flow correlation, NTLM identity extraction, QUIC
  Initial decrypt — all the parts that aren't glamorous to re-implement.

For tokio integration over a live NIC capture, pair with
[`netring`](https://crates.io/crates/netring) (Linux AF_PACKET /
AF_XDP) which consumes flowscope's traits.

## Install

```toml
[dependencies]
flowscope = { version = "0.22", features = ["full"] }
```

MSRV is Rust 1.88. The `full` feature pulls in everything; for production
builds, name the parsers you actually use to minimise compile time and binary
size. Coarse umbrellas sit between "one parser" and `full`: `l7` (all
license-clean wire parsers), the `parsers-core` / `parsers-l2l3` /
`parsers-tier2` tiers, and the capability bundles `nsm`, `ml`, and `export`.
Per-feature dependency tree is documented inline in
[`Cargo.toml`](Cargo.toml).

## Going further

| Doc | What's there |
|---|---|
| [`docs/getting-started.md`](docs/getting-started.md) | install + three minimal pipelines |
| [`docs/concepts.md`](docs/concepts.md) | the four layers + event model |
| [`docs/recipes.md`](docs/recipes.md) | picking an API, custom parsers, multi-protocol monitoring, cross-protocol correlation, structured output |
| [`docs/observability.md`](docs/observability.md) | `metrics` + `tracing` vocabulary, cardinality budget, severity routing |
| [`docs/eve-format.md`](docs/eve-format.md) | Suricata EVE JSON schema mapping |
| [`docs/sharded.md`](docs/sharded.md) | per-CPU sharded capture pattern |
| [`docs/discoverability.md`](docs/discoverability.md) | one-page prelude tour grouped by use case |
| [`docs/performance.md`](docs/performance.md) | criterion bench methodology + numbers |
| [`docs/design.md`](docs/design.md) | why flowscope is shaped the way it is |
| [`docs/migration-0.21-to-0.22.md`](docs/migration-0.21-to-0.22.md) | the 0.22 breaks — stateful `QuicUdpParser::new()` (PQ ClientHello reassembly) + `parser_kinds` removal — plus the additive 0.22 surface |
| [`docs/migration-0.20-to-0.21.md`](docs/migration-0.20-to-0.21.md) | the 0.21 detection-architecture breaks — typed `DetectorKind`, `DetectorScore::kind()`, opt-in per-packet `source_idx` |
| [`docs/migration-0.19-to-0.20.md`](docs/migration-0.19-to-0.20.md) | the 0.20 driver/event convergence — one typed `Driver<E>`, removal of `Flow{Session,Datagram}Driver` + `SessionEvent`, with migration recipes |
| [`docs/migration-0.17-to-0.18.md`](docs/migration-0.17-to-0.18.md) | the two BREAKING 0.18 changes (`parse() → Result<T, ParseError>` across new parsers + primitive→enum lifts for LDAP / Kerberos / nPrint / DNP3) with migration recipes |
| [`examples/`](examples/) | 70+ runnable examples grouped by use case (l7 logging, forensics, detection, observability, export, custom protocols, multi-protocol, performance, low-level) |
| [`CHANGELOG.md`](CHANGELOG.md) | release history + migration recipes |

## License

MIT **OR** Apache-2.0 at your option — with **one** opt-in exception.

The off-by-default `ja4plus` feature compiles the FoxIO-licensed
half of the JA4+ suite — **JA4S, JA4X, JA4H, JA4SSH, JA4T,
JA4L/LS** — under the [**FoxIO License 1.1**](LICENSE-FoxIO-1.1)
(source-available, non-commercial; **patent pending**). Commercial
use of `ja4plus` needs a FoxIO OEM license. It is deliberately
excluded from the `l7` and `full` umbrellas, so those builds stay
license-clean.

The `tls-fingerprints` feature (**JA3 + JA4 *client* +
JA4-over-QUIC**) is royalty-free — BSD-3 (JA3) plus FoxIO's
patent-free grant for plain JA4 — and *is* in `l7` / `full`.

The whole family is surfaced under one namespace,
[`flowscope::fingerprint`](https://docs.rs/flowscope/latest/flowscope/fingerprint/index.html),
with the license split documented in one place.

JA4+ methods are patent pending. "JA4+" is a trademark of FoxIO,
LLC. See [NOTICE](NOTICE) for the third-party-crate license map.

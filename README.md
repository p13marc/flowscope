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
# fn ex(rec: &flowscope::FlowRecord, stats: &flowscope::correlate::WelfordStats)
#   -> flowscope::ml_features::CicFlowFeatures {
flowscope::ml_features::CicFlowFeatures::from_flow_record(rec).with_iat(stats)
# }
```

Or write your own consumer over `FlowEvent` + typed L7 messages.
That's the whole shape.

## From pcap to SNI in 20 lines

```rust,no_run
use flowscope::driver::{Driver, Event, SlotMessage};
use flowscope::extract::{FiveTuple, FiveTupleKey};
use flowscope::pcap::PcapFlowSource;
use flowscope::tls::{TlsMessage, TlsParser};

# fn main() -> flowscope::Result<()> {
let mut builder = Driver::builder(FiveTuple::bidirectional());
let mut tls = builder.session_on_ports(TlsParser::default(), [443, 8443]);
let mut driver = builder.build();

let mut events: Vec<Event<FiveTupleKey>> = Vec::new();
let mut msgs:   Vec<SlotMessage<TlsMessage, FiveTupleKey>> = Vec::new();

for view in PcapFlowSource::open("trace.pcap")?.views() {
    let view = view?;
    events.clear(); msgs.clear();
    driver.track_into(&view, &mut events);
    tls.drain(&mut msgs);
    for m in &msgs {
        if let TlsMessage::ClientHello(h) = &m.message {
            println!("{:?} → SNI={:?} ALPN={:?}", m.key, h.sni, h.alpn);
        }
    }
}
# Ok(()) }
```

Run `cargo run --features tls,pcap --example tls_observer -- trace.pcap`.
For QUIC ClientHello visibility (RFC 9001 §5.2 passive decrypt — same shape, UDP/443),
swap `TlsParser` for `QuicUdpParser` and `session_on_ports` for
`datagram_on_ports`.

---

## What you can do with it

flowscope ships 30+ feature-gated parsers and analytics modules.
Highlights:

- **Web & encrypted traffic.** TLS handshake + ECH +
  [JA3 / JA4](https://github.com/FoxIO-LLC/ja4) client
  fingerprints. **QUIC Initial** passive decrypt → ClientHello
  SNI / ALPN — the only L7 visibility you have on HTTP/3 +
  DoQ.
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
  in a MAC-keyed `Inventory` via the `asset` feature.
- **Anomaly detectors.** Beaconing (RITA-style CV), port-scan
  (TRW / Jung 2004), DGA (bigram log-likelihood with embedded
  English baseline), entropy + n-gram primitives.
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
flowscope = { version = "0.18", features = ["full"] }
```

MSRV is Rust 1.88. The `full` feature pulls in everything; for production
builds, name the parsers you actually use to minimise compile time and binary
size. Per-feature dependency tree is documented inline in
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
| [`examples/`](examples/) | 40+ runnable examples grouped by use case (l7 logging, forensics, detection, observability, export, custom protocols, multi-protocol, performance, low-level) |
| [`CHANGELOG.md`](CHANGELOG.md) | release history + migration recipes |

## License

MIT **OR** Apache-2.0 at your option — with **one** opt-in exception.

The off-by-default `ja4plus` feature compiles JA4S
(`src/tls/ja4s.rs`), which is part of the JA4+ suite and is
licensed under the [**FoxIO License
1.1**](LICENSE-FoxIO-1.1) (source-available, non-commercial;
**patent pending**). Commercial use of `ja4plus` needs a FoxIO
OEM license. The default build and the `tls-fingerprints`
feature (JA3 + JA4 *client*) are royalty-free.

JA4+ methods are patent pending. "JA4+" is a trademark of FoxIO,
LLC. See [NOTICE](NOTICE) for the third-party-crate license map.

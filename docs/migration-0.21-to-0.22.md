# Migrating from 0.21 to 0.22

The 0.22 cycle is the fingerprinting & encrypted-traffic frontier
(the #140 roadmap group). Most of it is additive; this doc collects
the handful of compile-time breaks.

> **Note.** 0.21.0 was never published to crates.io, so a consumer
> upgrading from the last published release (**0.20.0**) should read
> [`migration-0.20-to-0.21.md`](migration-0.20-to-0.21.md) first,
> then this document.

## 1. `QuicUdpParser` is now a stateful struct (#135)

To reassemble a ClientHello split across multiple QUIC Initial
packets (the post-quantum case), `QuicUdpParser` changed from a
unit struct to one holding per-connection reassembly state. It
still derives `Default` and `Clone`.

```rust
// Before — unit struct, usable as a bare value:
let parser = QuicUdpParser;

// After — construct it:
let parser = QuicUdpParser::new();      // or QuicUdpParser::default()
```

Registration on the driver (`datagram_on_ports(QuicUdpParser::new(),
[443])`) and the `datagram_messages::<QuicUdpParser>(path)` pcap
helper are unaffected — they already construct via `Default`. Only
code using the bare `QuicUdpParser` name as a value needs the
`::new()`.

## 2. The deprecated `parser_kinds` module was removed (#139)

`flowscope::parser_kinds` (the `&str` constant umbrella,
soft-deprecated since 0.18) is gone. Use the typed
[`flowscope::ParserKind`] enum — its `.as_str()` yields the exact
same slug vocabulary.

```rust
// Before:
use flowscope::parser_kinds;
if kind == parser_kinds::DNS_UDP { /* … */ }

// After — match the typed enum:
use flowscope::ParserKind;
if kind == ParserKind::DnsUdp { /* … */ }

// …or compare slugs if you have a &str:
if kind_str == ParserKind::DnsUdp.as_str() { /* … */ }
```

The per-module `PARSER_KIND` / `PARSER_KIND_UDP` / `PARSER_KIND_TCP`
constants (e.g. `flowscope::http::PARSER_KIND`) are **unchanged** —
only the `parser_kinds` re-export umbrella was removed.

## Additive — no migration needed

- **Post-quantum key-share signal** — `TlsClientHello` gained
  `key_share_groups` / `pq_key_share`, `TlsHandshake` gained
  `pq_key_share` (both `#[non_exhaustive]`). New
  `tls::is_pq_hybrid_group` / `pq_hybrid_group_name`.
- **`flowscope::app_proto`** — `AppProtocol` / `classify` /
  `is_known_doh_host` for h2/h3 + DoT/DoQ/DoH identification.
- **`flowscope::ip_fragment::IpFragmentReassembler`** — IP
  fragment reassembly.
- **`flowscope::fingerprint`** — unified JA4+ facade; new
  `tls::ja3_fingerprint` / `ja3_canonical`.
- **Asset correlation** — `Asset::from_tls_handshake` /
  `from_ssh_kexinit` / `from_tcp_fingerprint`, `x509_subject` /
  `x509_sans` / `hostnames` / `first_seen` fields, `role()` /
  `source_count()`, `AssetRole`, new `AssetSourceSet` bits.
- **Throughput-by-owner** — `correlate::BandwidthByKey<K>` +
  `ByteSemantics` + `Attribution`.

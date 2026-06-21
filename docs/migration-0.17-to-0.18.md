# Migrating from 0.17 to 0.18

The 0.18 cycle ships every Tier-2 protocol parser, every ML feature
piece, the IPFIX binary encoder, and a sweep of API quality
changes. Most of it is additive — new features behind new gates.
The two BREAKING changes are isolated to the 0.18-cycle parsers
(no impact on consumers of HTTP / TLS / DNS / ICMP / ARP /
NDP / DHCP / LLDP / CDP / SSH / TCP-fingerprint / NTP / SSDP /
TFTP / mDNS / NBNS / FTP / SMTP / WireGuard / Modbus / STUN /
RDP / SNMP / RADIUS — those shapes are unchanged).

## Breaking change 1 — `parse()` returns `Result<T, ParseError>`

The 5 new wire parsers shipped in 0.18 each gained a per-module
`ParseError` enum, replacing the old `Option<T>` return type:

| Module     | Old signature                              | New signature                                         |
| ---------- | ------------------------------------------ | ----------------------------------------------------- |
| `dnp3`     | `pub fn parse(&[u8]) -> Option<DnpMessage>`     | `pub fn parse(&[u8]) -> Result<DnpMessage, ParseError>`       |
| `kerberos` | `pub fn parse(&[u8]) -> Option<KerberosMessage>` | `pub fn parse(&[u8]) -> Result<KerberosMessage, ParseError>` |
| `ldap`     | `pub fn parse(&[u8]) -> Option<LdapMessage>`    | `pub fn parse(&[u8]) -> Result<LdapMessage, ParseError>`     |
| `smb`      | `pub fn parse(&[u8]) -> Option<SmbMessage>`     | `pub fn parse(&[u8]) -> Result<SmbMessage, ParseError>`       |
| `quic`     | `pub fn parse(&[u8]) -> Option<QuicInitial>`    | `pub fn parse(&[u8]) -> Result<QuicInitial, ParseError>`     |

Each `ParseError` is per-module and `#[non_exhaustive]`. Variants
spell the operationally-distinct failure modes — `BadStartBytes` /
`Truncated { need, have }` / `InvalidLength(u8)` for DNP3,
`Empty` / `UnknownTag(u8)` / `AsnDecode` for Kerberos,
`NotInitial` / `AeadDecryptFailed` / `CryptoFrameDecode` for QUIC,
etc.

**Migration recipe.** Replace `Option` plumbing with `Result`:

```diff
- if let Some(msg) = flowscope::dnp3::parse(payload) {
-     handle(msg);
- }
+ if let Ok(msg) = flowscope::dnp3::parse(payload) {
+     handle(msg);
+ }
```

If you want to route on the failure mode:

```rust
match flowscope::quic::parse(datagram) {
    Ok(init) => log_quic_initial(&init),
    Err(flowscope::quic::ParseError::NotInitial) => { /* skip */ }
    Err(flowscope::quic::ParseError::AeadDecryptFailed) => {
        // QUIC version we don't know how to decrypt
        // — bump the unknown-version metric.
    }
    Err(_) => tracing::warn!("quic parse failure"),
}
```

The `SessionParser` / `DatagramParser` impls on the bundled
parsers handle this internally — **users of the typed-driver
path (`Driver<E>` + `session_on_ports` / `datagram_on_ports`)
or the `*_from_pcap` helpers see no behavioral change**.

## Breaking change 2 — primitive→enum lifts

Four fields graduated from raw `bool` / `u32` / `i32` / `i8` to
dedicated `#[non_exhaustive]` enums. Each enum follows the same
shape as the existing 0.18 `KerberosEtype` / `QuicVersion` /
`DceRpcInterfaceUuid` strong-types: `from_raw(value)` +
`as_raw()` / `as_bit()` round-trip + `as_str()` stable lowercase
slug + `Display`.

| Field                                       | Old type          | New type                                                            |
| ------------------------------------------- | ----------------- | ------------------------------------------------------------------- |
| `LdapMessage::result_code`                  | `Option<u32>`     | `Option<LdapResultCode>` (14 spelled-out RFC 4511 §4.1.9 codes)     |
| `LdapMessage::search_scope`                 | `Option<u32>`     | `Option<LdapSearchScope>` (BaseObject / SingleLevel / WholeSubtree) |
| `KerberosMessage::error_code`               | `Option<i32>`     | `Option<KerberosErrorCode>` (8 spelled-out RFC 4120 §7.5.9 codes)   |
| `NPrintRow::bits`                           | `Vec<i8>`         | `Vec<NPrintBit>` (`Absent` / `Zero` / `One`; per-row footprint unchanged) |
| `DnpMessage::link_dir`                      | `bool`            | `DnpLinkDirection` (`ToOutstation` / `ToMaster`)                    |
| `DnpMessage::link_prm`                      | `bool`            | `DnpLinkRole` (`Primary` / `Secondary`)                             |

**Migration recipes.**

```diff
- if msg.result_code == Some(0) {
+ if msg.result_code == Some(flowscope::ldap::LdapResultCode::Success) {
      // bind succeeded
  }

- if bit == 0 {
+ if matches!(bit, flowscope::nprint::NPrintBit::Zero) {
      // bit observed and clear
  }

- if msg.link_dir {  // true = master → outstation
+ if matches!(msg.link_dir, flowscope::dnp3::DnpLinkDirection::ToOutstation) {
      // master-bound
  }
```

The `Other(raw)` variants on each enum preserve the original wire
value for forensic plumbing. Round-trip is exact:

```rust
let code = flowscope::kerberos::KerberosErrorCode::from_raw(9999);
assert_eq!(code.as_raw(), 9999);  // preserved
assert!(matches!(code, flowscope::kerberos::KerberosErrorCode::Other(_)));
```

## Additive — `Driver::run_pcap()`

One-call iterator over a pcap file on the typed driver. Yields the
unified `Event<K>` stream; per-parser typed messages still flow
through registered `SlotHandle`s.

```rust
use flowscope::driver::Driver;
use flowscope::extract::FiveTuple;

let mut builder = Driver::builder(FiveTuple::bidirectional());
// Register parsers as usual...
let driver = builder.build();
for ev in driver.run_pcap("trace.pcap")? {
    let _ev = ev?;
    // Drain typed slots between iterations if you need the messages.
}
```

## Additive — per-parser `*_from_pcap` helpers

The high-level one-call pcap iterators added in 0.17 grew siblings
for every shipped session/datagram parser:

```rust
for (key, req)  in flowscope::http::requests_from_pcap("trace.pcap")? { /* ... */ }
for (key, resp) in flowscope::http::responses_from_pcap("trace.pcap")? { /* ... */ }
for (key, ex)   in flowscope::http::exchanges_from_pcap("trace.pcap")? { /* ... */ }
for (key, msg)  in flowscope::dns::messages_from_pcap("trace.pcap")? { /* ... */ }
for (key, msg)  in flowscope::kerberos::messages_from_pcap("trace.pcap")? { /* ... */ }
for (key, msg)  in flowscope::ldap::messages_from_pcap("trace.pcap")? { /* ... */ }
for (key, msg)  in flowscope::ssh::messages_from_pcap("trace.pcap")? { /* ... */ }
// ... and so on for smb / smtp / ftp / modbus / quic / tls
```

Plus a tracker-shaped sibling:

```rust
for (key, stats, reason) in flowscope::pcap::flow_summaries_from_pcap("trace.pcap")? {
    println!("{key:?}  bytes={} reason={:?}", stats.bytes_initiator + stats.bytes_responder, reason);
}
```

## Reference

- Per-issue migration notes: `CHANGELOG.md` 0.18.0 section under
  "Changed (pre-1.0 breaking)".
- Recipes for the new examples (composite_c2, tcp_evasion_detector,
  client_fingerprint_catalog, prometheus_exporter, etc.) live in
  `examples/README.md`.

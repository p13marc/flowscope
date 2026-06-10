# Plan 144 — ECH (Encrypted Client Hello) signal extraction

## Summary

Surface the ECH (Encrypted Client Hello) wire signal on
`TlsClientHello` and `TlsHandshake` events. ECH is widely
deployed in 2026 (Chrome / Firefox / BoringSSL / rustls 0.23+);
without surfacing the signal, flowscope reports SNIs that may
be the cover domain rather than the real one, silently.

What we can extract passively (no ECH keys):

- **`ech_present: bool`** — extension 0xfe0d observed in
  ClientHello.
- **`ech_config_id: Option<u8>`** — the HPKE config ID byte
  (useful for clustering clients by ECH config rotation).
- **`sni_is_outer: bool`** — when ECH is present, the SNI we
  parsed is the outer (public) cover domain, not the inner
  one. Inner SNI is opaque.
- **`ech_retry_configs: bool`** — server's EncryptedExtensions
  carries `retry_configs` → ECH was rejected.

This is purely additive — no new parser, no new dep, no new
event variant.

## Status

Not started.

## Prerequisites

None.

## Out of scope

- **ECH key import / private decryption.** Out of scope —
  passive observation only.
- **Inner SNI extraction.** Cryptographically impossible
  without ECH config private keys.
- **`ECHClientHello` inner detection.** Outer-only.
- **Active ECH probing / config discovery.** Pure passive.

## Pre-1.0 breaks

None. Additive — new fields on `#[non_exhaustive]` types.

## Files

| Action | Path | Purpose |
|---|---|---|
| Modify | `src/tls/types.rs` | `TlsClientHello` grows `ech_present`, `ech_config_id`, `sni_is_outer` fields; `TlsServerHello` grows `ech_retry_configs` |
| Modify | `src/tls/parser.rs` | Detect extension 0xfe0d in ClientHello + EncryptedExtensions; populate new fields |
| Modify | `src/tls/handshake.rs` | `TlsHandshake` event grows `ech_present`, `ech_retry_configs`, `ech_outcome` fields |
| Modify | `tests/tls_parser.rs` | Add ECH fixture cases |
| New | `tests/fixtures/tls/ech_chrome.pcap` | Chrome ECH ClientHello fixture |
| New | `tests/fixtures/tls/ech_retry.pcap` | Server retry-config rejection fixture |
| Modify | `examples/02-forensics/tls_inventory.rs` | Surface ECH in the aggregation |
| New | `docs/tls-ech.md` | What ECH looks like on the wire + what flowscope can / can't extract |
| Modify | `CHANGELOG.md` | 0.12 entry |

## API

```rust
// src/tls/types.rs

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct TlsClientHello {
    // … existing fields …
    pub sni: Option<Bytes>,
    pub alpn: Vec<Bytes>,
    // …

    // ── ECH (plan 144, 0.12.0) ──
    /// Extension 0xfe0d observed.
    pub ech_present: bool,
    /// HPKE config_id byte from the outer ECHClientHello,
    /// or `None` if ECH is absent.
    pub ech_config_id: Option<u8>,
    /// When `ech_present == true`, the parsed `sni` is the
    /// outer cover domain, not the real target. When false,
    /// `sni` is the canonical real value.
    pub sni_is_outer: bool,
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct TlsServerHello {
    // … existing fields …

    // ── ECH (plan 144, 0.12.0) ──
    /// Server's EncryptedExtensions carries `retry_configs`,
    /// signalling ECH rejection.
    pub ech_retry_configs: bool,
}
```

```rust
// src/tls/handshake.rs

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EchOutcome {
    /// ECH not offered.
    NotOffered,
    /// ECH offered + accepted (no retry_configs in
    /// EncryptedExtensions).
    Accepted,
    /// ECH offered + rejected (retry_configs present).
    Rejected,
    /// ECH offered; outcome indeterminate (handshake didn't
    /// reach EncryptedExtensions).
    Unknown,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TlsHandshake {
    // … existing fields …

    // ── ECH (plan 144, 0.12.0) ──
    pub ech_outcome: EchOutcome,
    pub ech_config_id: Option<u8>,
}
```

### EVE writer extension

Out of scope for this plan. `EveJsonWriter` doesn't emit a
`"tls"` event_type yet (no per-protocol EVE shapes shipped).
ECH state surfaces on `TlsClientHello` / `TlsHandshake`
events; consumers wanting it in EVE output drain the
handshake aggregator and write their own line. Add a
`"tls"` event_type to `EveJsonWriter` in a future cycle if a
consumer asks.

## Implementation steps

### Phase 1: Parser changes

1. `src/tls/parser.rs`: scan ClientHello extensions for type
   0xfe0d. Parse the `ECHClientHello` outer struct (RFC draft
   §5.1):
   - 1 byte `ECHClientHelloType` (0 = outer, 1 = inner —
     skip inner).
   - 1 byte `HPKE config_id`.
   - 2 bytes HPKE KDF.
   - 2 bytes HPKE AEAD.
   - 2 bytes `enc.len`, then `enc` bytes.
   - 2 bytes `payload.len`, then opaque `payload`.
2. Populate `TlsClientHello::ech_present` + `ech_config_id`.
3. When ECH is present, mark `sni_is_outer = true`.
4. ServerHello EncryptedExtensions scan — but
   EncryptedExtensions sits inside the encrypted handshake.
   For TLS 1.3 with ECH rejected, the server sends
   `retry_configs` in the *encrypted* EncryptedExtensions —
   we can't read it without keys. **Caveat:** the
   `ech_retry_configs` field stays Default::default()=false
   for now; document the limitation. Future expansion: hook
   into rustls's accept-side ECH state machine if a consumer
   ships keys (out of scope here).

### Phase 2: Handshake aggregator

5. `src/tls/handshake.rs`: `TlsHandshakeParser` reads ECH
   state off ClientHello + ServerHello. Computes
   `EchOutcome`:
   - `NotOffered` if `client.ech_present == false`.
   - `Accepted` if client offered AND server did NOT send
     retry_configs (best-effort — we can't see encrypted
     EE).
   - `Rejected` if server's plain EncryptedExtensions
     somehow leaks retry_configs (rare; only on early
     handshake errors before encryption establishes).
   - `Unknown` otherwise.

### Phase 3: Tests + docs

6. `tests/tls_parser.rs`: ECH ClientHello fixtures
   (Chrome 121+, Firefox 120+, curl --ech, BoringSSL).
   Assert `ech_present`, `ech_config_id`,
   `sni_is_outer == true`.
7. Non-ECH ClientHello fixtures stay green —
   `ech_present == false`, `sni_is_outer == false`.
8. `docs/tls-ech.md`: explain what's extractable, what's not,
   and how to act on it (typical answer: cluster by
   `ech_config_id`; treat outer SNI as a privacy hint, not a
   target identifier).

## Tests

### Unit

- `parser::tests::ech_extension_parses_config_id` — handcrafted
  bytes.
- `parser::tests::ech_absent_leaves_fields_default`.

### Integration

- `tests/tls_parser.rs::ech_chrome_fixture_extracts_config_id`
- `tests/tls_parser.rs::ech_firefox_fixture_extracts_config_id`
- `tests/tls_parser.rs::non_ech_chrome_fixture_marks_present_false`
- `tests/tls_parser.rs::ech_pcap_handshake_aggregator_emits_outcome`

## Acceptance criteria

- `cargo build --features tls,pcap` clean.
- `cargo test --features tls,pcap` clean.
- `cargo clippy --features tls --all-targets -- -D warnings`
  clean.
- Bundled fixtures: Chrome ECH ClientHello + Firefox ECH
  ClientHello + non-ECH baseline.
- `examples/02-forensics/tls_inventory.rs` surfaces ECH-using
  vs non-ECH-using ratios.
- `docs/tls-ech.md` documents the limit (inner SNI opaque).

## Risks

- **R1: Spec drift.** ECH is still draft-ietf-tls-esni (≤22 as
  of late 2025). If the wire format changes between drafts
  before RFC publication, the bytes-level parser breaks.
  Mitigation: pin a draft version in `docs/tls-ech.md` and
  the field-level docs; use fixtures captured against
  specific browser builds; document the upgrade path.
- **R2: ECH rejection detection is best-effort.** Without
  keys we can't see encrypted EncryptedExtensions. Mitigation:
  document the limitation; suggest pairing with a server-side
  consumer if better fidelity is needed.
- **R3: `ech_config_id` clustering bias.** A single Chrome
  install may rotate config_id daily (DNS HTTPS RR refresh).
  Document the rotation semantics; suggest pairing with
  JA4 fingerprint for client identification rather than
  config_id alone.

## Effort

| Step | LoC | Hours |
|---|---|---|
| Parser extension scan + ECH outer parse | 80 | 2 |
| Field additions on TlsClientHello/TlsServerHello | 40 | 1 |
| Handshake aggregator EchOutcome | 60 | 1.5 |
| Tests + 3 fixtures | 200 | 4 |
| docs/tls-ech.md | 80 | 2 |
| Example update | 30 | 0.5 |
| CHANGELOG | 20 | 0.5 |
| **Total** | **~510** | **~12 hours (~1.5 days)** |

## Provenance

netring 0.21 wishlist (Phase H §"ECH signal"). 2026 ECH
deployment in Chrome 124 (default on for >0.5% of users) and
Firefox 119 (default on for users who opt into DNS-over-HTTPS)
means a measurable percentage of TLS handshakes flowscope sees
will carry the outer SNI. Silently mis-reporting the outer SNI
as "the SNI" is a passive-observability footgun; surfacing the
signal lets consumers cluster honestly.

References:
- `draft-ietf-tls-esni-22` (current draft at Jan 2026)
- BoringSSL ECH implementation: `boringssl/include/openssl/ssl.h`
  `SSL_set_enable_ech_grease`
- rustls 0.23+ ECH support: `github.com/rustls/rustls`
- Cloudflare ECH research:
  `blog.cloudflare.com/announcing-encrypted-client-hello`

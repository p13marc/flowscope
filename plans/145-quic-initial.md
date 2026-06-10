# Plan 145 — QUIC Initial-packet parser + JA4-QUIC

## Summary

Passively observe QUIC (RFC 9000) Initial packets, decrypt them
with the well-known version-specific Initial keys (RFC 9001
§5.2), reassemble CRYPTO frames, parse the embedded TLS
ClientHello, and emit SNI / ALPN / JA4-QUIC fingerprint.

Initial packets are the **only** decryptable part of a QUIC
flow without session keys: per RFC 9001 the Initial-packet key
schedule is derived from `(version_salt, dcid)` where the salt
is a public constant. Everything after Handshake-key
establishment is opaque to passive observers — but the
ClientHello is in the Initials, and that's what carries SNI +
ALPN + the JA4-shaped fingerprint.

By 2026 QUIC carries roughly 30-40% of web traffic via HTTP/3
(Cloudflare, Google, Facebook, Akamai all default on); without
QUIC observation flowscope ignores a substantial chunk of
modern traffic, and the ignored chunk is disproportionately
high-value (mobile, video, modern browsers).

## Status

Not started.

## Prerequisites

- **Plan 140** (JA4+ family) — JA4-QUIC reuses the JA4 client
  TLS algorithm with the transport-prefix swapped to `'q'`.
- **Plan 130** (KeyFields) — QUIC's CID-based flow key opts
  into KeyFields for the EVE path.

## Out of scope

- **Decrypting Handshake / 1-RTT packets.** Cryptographically
  impossible without session keys.
- **HTTP/3 frame parsing.** Riding atop encrypted QUIC streams
  — not passively observable.
- **QUIC connection migration tracking.** Out of scope for the
  initial implementation; connection IDs rotate post-handshake
  and we can't follow.
- **Version negotiation packet parsing.** Surface as a typed
  message but no fingerprint computation.
- **0-RTT data extraction.** 0-RTT carries early-data ClientHello
  bytes in Initials too, but the early-data payload itself is
  encrypted under 0-RTT keys derived from the resumed-session
  master secret — opaque.
- **Retry packet token analysis.** Surface raw bytes; consumers
  who want token forensics build it themselves.

## Pre-1.0 breaks

None. New module, new feature flag.

## Files

| Action | Path | Purpose |
|---|---|---|
| New | `src/quic/mod.rs` | Public API — `QuicInitialParser` (DatagramParser), `QuicMessage`, `QuicInitialDecryptor` |
| New | `src/quic/keys.rs` | Initial-key derivation per RFC 9001 — v1 + v2 salts; uses `quinn-proto::crypto::rustls::initial_keys` |
| New | `src/quic/header.rs` | Long-header packet parsing (RFC 9000 §17.2); header protection removal |
| New | `src/quic/frames.rs` | CRYPTO frame parsing (RFC 9000 §19.6); reassembly by offset |
| New | `src/quic/session.rs` | `QuicInitialParser` (DatagramParser) — feed UDP datagrams, emit messages |
| New | `src/quic/fingerprint.rs` | JA4-QUIC computation (reuses TLS ClientHello → JA4 with transport=`'q'`) |
| Modify | `src/lib.rs` | `#[cfg(feature = "quic")] pub mod quic;` + re-exports |
| Modify | `src/detect/signatures.rs` | `quic_long_header` signature (first byte ≥ 0xC0; version field non-zero) |
| Modify | `src/parser_kinds` | `QUIC = "quic"` constant |
| Modify | `src/well_known/mod.rs` | UDP/443 maps to "quic-h3" label |
| Modify | `Cargo.toml` | `quic = ["session", "extractors", "tls", "dep:quinn-proto", "dep:bytes"]` |
| New | `tests/quic_initial.rs` | Initial-packet decode tests against captured pcaps |
| New | `tests/quic_ja4.rs` | JA4-QUIC fingerprint golden tests |
| New | `tests/fixtures/quic/` | Pcap fixtures: Chrome QUIC, Firefox QUIC, curl --http3 |
| New | `examples/01-l7-logging/quic_initial_log.rs` | Pcap → per-flow SNI/ALPN/JA4-QUIC |
| New | `docs/quic-observation.md` | What QUIC initial packets carry + decryption math + observation limits |
| Modify | `CHANGELOG.md` | 0.12 entry |

## API

### `QuicInitialParser` (DatagramParser)

```rust
// src/quic/session.rs

use crate::{DatagramParser, FlowSide, Timestamp};

/// Passive QUIC Initial-packet parser.
///
/// QUIC flows over UDP; pair via:
///   `Driver::builder(ext).datagram_on_ports(
///       QuicInitialParser::default(), [443])`
///
/// or via heuristic with `detect::signatures::quic_long_header`.
///
/// State: per-flow `QuicInitialDecryptor` keyed by the
/// destination connection ID (DCID) from the first observed
/// Initial. CRYPTO frame reassembly by offset until a complete
/// ClientHello is in hand. Then emits one
/// `QuicMessage::ClientHello` per flow.
#[derive(Debug, Clone)]
pub struct QuicInitialParser {
    config: QuicConfig,
    // per-flow state lives in a HashMap keyed by DCID
    decryptors: HashMap<Bytes /* DCID */, QuicInitialDecryptor>,
    poisoned: bool,
}

impl DatagramParser for QuicInitialParser {
    type Message = QuicMessage;

    fn parse(&mut self, b: &[u8], side: FlowSide, ts: Timestamp,
             out: &mut Vec<Self::Message>) { … }
    fn parser_kind(&self) -> &'static str { "quic" }
    fn is_poisoned(&self) -> bool { self.poisoned }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum QuicMessage {
    /// Parsed ClientHello from the Initial packet(s).
    ClientHello {
        version: u32,            // QUIC version (0x00000001 = v1)
        dcid: Bytes,
        scid: Bytes,
        client_hello: TlsClientHello,
        ja4_quic: String,
    },
    /// Version-negotiation packet observed (no Initial).
    VersionNegotiation {
        supported_versions: Vec<u32>,
    },
    /// Retry packet observed (server rejects DCID).
    Retry {
        retry_token: Bytes,
    },
}
```

### Initial-key derivation

```rust
// src/quic/keys.rs

use quinn_proto::crypto::rustls::initial_keys;
use quinn_proto::Side;

/// QUIC v1 (RFC 9000) salt: `0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a`.
/// QUIC v2 (RFC 9369) salt: `0x0dede3def700a6db819381be6e269dcbf9bd2ed9`.
pub(super) fn derive_initial_keys(version: u32, dcid: &[u8])
    -> Result<Keys, QuicError> { … }
```

Implementation: use `quinn-proto::crypto::rustls::initial_keys(
    version, dcid, Side::Server)` — passing `Side::Server`
gives us the client-direction keys (we're a passive observer
on the server side of the flow). Returns `Keys` with `header`
(AES-ECB for header protection unmask) and `packet` (AES-GCM
for payload decryption).

### `QuicInitialDecryptor` (per-flow state)

```rust
// src/quic/session.rs

pub(super) struct QuicInitialDecryptor {
    /// Initial keys derived once on first packet (from version
    /// + DCID).
    keys: Keys,
    /// CRYPTO frame fragments reassembled by offset.
    crypto_buf: BTreeMap<u64 /* offset */, Bytes>,
    /// Once-only flag to avoid re-emitting ClientHello on
    /// retransmits.
    emitted: bool,
}
```

### Heuristic signature

```rust
// src/detect/signatures.rs

/// First byte high bit set (long header form) + version != 0
/// + plausible DCID length.
pub fn quic_long_header(probe: &[u8]) -> SignatureMatch { … }
```

## Implementation steps

### Phase 1: dep + key derivation

1. `Cargo.toml`: add `quinn-proto = "0.11"` (optional;
   gated under `quic`). Adds `rustls` + `ring` / `aws-lc-rs`
   transitively (~2 MB compiled).
2. `src/quic/keys.rs`: thin wrapper around
   `quinn_proto::crypto::rustls::initial_keys`. Constants for
   the two salts (v1, v2) documented in rustdoc.

### Phase 2: Header parsing + protection removal

3. `src/quic/header.rs`: long-header packet parsing per RFC
   9000 §17.2:
   - 1 byte first (form / fixed / type / RR / PNL bits).
   - 4 bytes version.
   - 1 byte DCID len + DCID.
   - 1 byte SCID len + SCID.
   - Type-specific fields (token for Initial, none for
     Handshake / 0-RTT, etc.).
4. Header protection removal per RFC 9001 §5.4: sample 16
   bytes at `header_offset + 4 + pn_length_max`, AES-ECB
   encrypt sample, XOR mask into the first byte (low 4 bits)
   + packet number bytes.

### Phase 3: AEAD decryption

5. AES-128-GCM decryption per RFC 9001 §5.3: IV = `quic iv`
   XOR `packet_number_padded`; AAD = decrypted header. Payload
   = decrypted plaintext frames.

### Phase 4: CRYPTO frame reassembly

6. `src/quic/frames.rs`: CRYPTO frame layout (RFC 9000 §19.6):
   - 1 byte frame type (0x06).
   - varint offset.
   - varint length.
   - `length` bytes data.
7. Reassemble across multiple Initials by offset (CRYPTO
   frames can be split / reordered like TCP segments).
8. When the assembled data parses cleanly as a complete TLS
   ClientHello, hand it to the existing TLS ClientHello
   parser (`tls::parser::parse_client_hello_bytes` — needs
   small refactor to be public for non-TLS-record callers).

### Phase 5: JA4-QUIC

9. `src/quic/fingerprint.rs`: compute JA4 over the parsed
   ClientHello with transport=`'q'`. Reuses
   `flowscope::tls::ja4_parts`; only the transport char
   differs.

### Phase 6: Session-parser shape

10. `src/quic/session.rs`: `QuicInitialParser` impl. Per UDP
    datagram: parse long header → if Initial-type, derive
    keys (cache by DCID) → unmask header → AEAD decrypt
    payload → extract CRYPTO frames → reassemble → emit
    `QuicMessage::ClientHello` on success.
11. Version-negotiation and Retry packets surface as their
    own variants without decryption attempts.

### Phase 7: Heuristic signature

12. `src/detect/signatures.rs::quic_long_header`: matches
    when first byte ≥ 0xC0 AND bytes 1-4 are a plausible QUIC
    version (0x00000001 = v1, 0x6b3343cf = v2, 0xFF000020+ =
    drafts).

### Phase 8: Tests + fixtures + docs

13. Capture pcap fixtures: Chrome QUIC (`chrome://flags
    Enable-QUIC`), Firefox QUIC (`network.http.http3.enable`),
    curl --http3, golang quic-go example. Embed minimal
    UDP-only pcaps under `tests/fixtures/quic/`.
14. Initial decryption tests:
    - `quic_v1_chrome_initial_decrypts_yielding_sni`
    - `quic_v2_firefox_initial_decrypts_yielding_sni`
    - `quic_retry_packet_emits_retry_variant_no_decryption`
    - `quic_version_negotiation_emits_no_decryption`
15. JA4-QUIC golden tests:
    - `chrome_ja4_quic_matches_known_value`
    - `firefox_ja4_quic_matches_known_value`
16. `examples/01-l7-logging/quic_initial_log.rs`.
17. `docs/quic-observation.md`: salts, key derivation math,
    observation limits, what flowscope can / can't see.

## Tests

### Unit

- `keys::tests::v1_salt_matches_rfc9001`
- `keys::tests::v2_salt_matches_rfc9369`
- `header::tests::long_header_parses_version_and_cids`
- `header::tests::short_header_returns_error_we_dont_handle`
- `header::tests::protection_removal_unmasks_packet_number`
- `frames::tests::crypto_frame_parses_offset_and_length`
- `frames::tests::reassembly_handles_out_of_order_offsets`
- `fingerprint::tests::ja4_quic_has_q_transport_prefix`

### Integration

- `tests/quic_initial.rs::chrome_quic_v1_pcap_yields_sni_and_alpn`
- `tests/quic_initial.rs::firefox_quic_v1_pcap_yields_sni`
- `tests/quic_initial.rs::quiche_h3_test_pcap_yields_sni`
- `tests/quic_initial.rs::retry_packet_emits_retry_variant`
- `tests/quic_initial.rs::version_negotiation_emits_no_clienthello`
- `tests/quic_ja4.rs::chrome_ja4_quic_matches_known`
- `tests/quic_ja4.rs::firefox_ja4_quic_matches_known`

## Acceptance criteria

- `cargo build --features quic,pcap` clean.
- `cargo test --features quic,pcap` clean.
- `cargo clippy --features quic --all-targets -- -D warnings`
  clean.
- New `quic` CI matrix entry.
- Golden JA4-QUIC tests match published browser fingerprints.
- `examples/01-l7-logging/quic_initial_log.rs` runs end-to-end
  on the shipped pcap fixtures producing SNI/ALPN/JA4-QUIC per
  flow.
- `docs/quic-observation.md` documents what's extractable +
  what isn't.
- Bench: QUIC Initial decode latency documented in
  `docs/performance.md`.

## Risks

- **R1: `quinn-proto` API churn.** quinn-proto is at 0.11 in
  late 2025; major versions broke the `initial_keys` API
  shape between 0.9 → 0.10 → 0.11. Mitigation: pin a specific
  minor version; semver-compatible upgrade path. Document the
  pinned version in `docs/quic-observation.md`.
- **R2: Compiled-size growth.** rustls + ring transitively =
  ~2 MB compiled. Documented; gated behind the `quic` feature
  so non-QUIC consumers pay nothing.
- **R3: Connection-ID-based flow tracking gap.** flowscope's
  existing `FiveTuple` extractor keys on UDP src/dst —
  perfect for the Initial packet but breaks after QUIC
  connection migration (new src ip:port, same connection
  conceptually). Documented limit; consumers wanting
  migration-aware tracking build a custom `FlowExtractor`
  keying on DCID.
- **R4: Initial-packet retransmissions emit duplicate
  ClientHellos.** Mitigation: `emitted: bool` flag in
  `QuicInitialDecryptor` suppresses re-emit.
- **R5: 0-RTT early-data ClientHellos in Initials.** Same
  ClientHello shape; we parse them like the 1-RTT one. Mark
  the message with `version` so consumers can filter if they
  care. Documented.
- **R6: New QUIC versions (v3, v4, drafts).** Each version
  has a new salt. Mitigation: a `QuicConfig::additional_salts`
  map for consumer-supplied salts. Default v1 + v2 only.

## Effort

| Step | LoC | Hours |
|---|---|---|
| `quinn-proto` integration + key derivation | 80 | 2 |
| Long-header parsing | 150 | 3 |
| Header protection removal + AEAD decrypt | 200 | 5 |
| CRYPTO frame parsing + reassembly | 200 | 5 |
| TLS ClientHello extraction (refactor existing parser) | 100 | 3 |
| JA4-QUIC fingerprint | 80 | 2 |
| Heuristic signature | 30 | 0.5 |
| `QuicInitialParser` session-parser shape | 200 | 5 |
| 3 pcap fixtures + 15 tests | 400 | 7 |
| Example + docs/quic-observation.md | 180 | 4 |
| CHANGELOG | 40 | 1 |
| **Total** | **~1660** | **~37.5 hours (~5 days)** |

## Provenance

netring 0.21 wishlist (Phase I §"QUIC Initial-packet
observation") + 0.12 audit Tier-3 ("growing fast as HTTP/3
share climbs"). 2026 HTTP/3 deployment via Cloudflare, Google,
Akamai, Facebook means a measurable fraction of TLS handshakes
(currently visible to flowscope) is moving to QUIC where
they're not. Initial-packet parsing is the only passively-
observable handshake stage; it carries SNI + ALPN + a JA4-
shaped fingerprint, which is exactly the data flowscope's
existing TLS pipeline yields.

References:
- RFC 9000 (QUIC)
- RFC 9001 (TLS in QUIC)
- RFC 9369 (QUIC v2)
- `quinn-proto::crypto::rustls::initial_keys` — see
  `github.com/quinn-rs/quinn`
- FoxIO JA4-QUIC test vectors —
  `github.com/FoxIO-LLC/ja4/pcap` directory
- Cloudflare blog "QUIC version 2": `blog.cloudflare.com/quic-version-2-progressive-deployment-and-the-future-of-the-internet`

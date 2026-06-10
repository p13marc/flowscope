# Plan 140 — JA4+ family completion (JA4S/JA4H/JA4T/JA4L/JA4X)

## Summary

Complete the FoxIO JA4+ fingerprint family. flowscope ships
JA3 + JA4 (client TLS) today; this plan adds the five remaining
shipped variants:

- **JA4S** — TLS ServerHello fingerprint.
- **JA4H** — HTTP/1.1 client request fingerprint.
- **JA4T / JA4TS** — TCP SYN / SYN-ACK options fingerprint.
- **JA4L / JA4LS** — one-way latency (client→server / server→client).
- **JA4X** — X.509 cert chain fingerprint.

JA4+ is the de facto post-JA3 fingerprint family in 2026 (Suricata
7.x, Zeek pkg, CrowdStrike Falcon, Cloudflare Bot Management, GreyNoise
all consume it). Without the full family flowscope is a
half-built tool for any NDR / threat-intel consumer.

JA4SSH is deferred (no SSH parser in flowscope yet — file an issue
plan when one lands); JA4DB is the database wire fingerprint family
(no shipped parsers either).

## Status

Not started.

## Prerequisites

- **Plan 130** lands first (the `tls-fingerprints` feature umbrella
  is established by plan 131; this plan ships JA4S/JA4H/JA4T/JA4L/JA4X
  under it).
- **Plan 131** lands first (`ja3` + `ja4` features collapse into
  `tls-fingerprints` so we have one feature flag for the whole family).

## Out of scope

- **JA4SSH / JA4DB.** Defer until SSH / database parsers ship.
- **Rule-engine integration.** flowscope's role is to emit the
  fingerprints; downstream consumers (their IoC feeds, NDR
  rules) own match logic.
- **Active TLS fingerprint spoofing detection.** Pure passive
  observer.
- **JA4 / JA3 rewrites.** Existing implementations stay.
- **JA4-QUIC.** Folded into plan 145 (QUIC) — needs the QUIC
  parser shipping the underlying ClientHello first.

## Pre-1.0 breaks

- **`Cargo.toml` feature gate:** every shipped JA4+ variant gates
  on `tls-fingerprints` (per plan 131). No standalone `ja4s` /
  `ja4h` features.
- **`TcpInfo` grows a `raw_options: Bytes` field** behind the
  `extractors` feature. JA4T needs raw SYN TCP options bytes; the
  existing `flags + seq + ack + payload_offset + payload_len + window`
  shape doesn't carry them. Field is `#[non_exhaustive]`-additive;
  existing struct-literal constructions break only if they used
  explicit field syntax outside the crate (very rare; documented
  in the migration note).
- **`TlsHandshakeParser`** event grows fields:
  `tls_server_hello: Option<TlsServerHello>`,
  `ja4s: Option<String>`, `ja4h: Option<String>`,
  `ja4t: Option<String>`, `ja4ts: Option<String>`,
  `ja4l: Option<String>`, `ja4ls: Option<String>`,
  `ja4x: Option<String>`. `#[non_exhaustive]` already on the type;
  additive.

## Files

| Action | Path | Purpose |
|---|---|---|
| Modify | `src/extractor.rs` | `TcpInfo::raw_options: Bytes` field (Bytes from etherparse parse output, sliced zero-copy from frame). Populated on every TCP packet. |
| Modify | `src/extract/parse.rs` | etherparse slicer captures raw TCP options bytes |
| New | `src/tls/ja4s.rs` | JA4S algorithm + `Ja4sParts` + `ja4s(sh: &TlsServerHello) -> String` |
| New | `src/tls/ja4x.rs` | JA4X algorithm + `Ja4xParts` + `ja4x(certs: &[X509Slice<'_>]) -> String`. Uses `x509-parser` (new dep, optional, behind `tls-fingerprints`) |
| New | `src/http/ja4h.rs` | JA4H algorithm + `Ja4hParts` + `ja4h(req: &HttpRequest) -> String` |
| New | `src/extract/ja4t.rs` | JA4T / JA4TS algorithms + `Ja4tParts` + `ja4t(opts: &[u8], window: u16, is_synack: bool) -> String`. Operates on `TcpInfo::raw_options`. |
| New | `src/extract/ja4l.rs` | JA4L / JA4LS algorithms — needs SYN observation timestamp + SYN-ACK observation timestamp + ACK observation timestamp. Per-flow state lives in the tracker. |
| Modify | `src/tls/parser.rs` | Parse Certificate handshake message; surface raw cert chain as `Vec<Bytes>` on `TlsHandshake` |
| Modify | `src/tls/handshake.rs` | `TlsHandshake` event grows JA4S / JA4X / cert_chain fields; the parser computes them after collecting ServerHello + Certificate |
| Modify | `src/tls/types.rs` | `TlsServerHello` gets `selected_cipher`, `selected_alpn`, `extensions_in_order` fields needed by JA4S |
| Modify | `src/tracker.rs` | Per-flow SYN observation timestamp persisted for JA4L computation (new field on `FlowEntry`) |
| Modify | `src/http/exchange.rs` | `HttpExchange` event grows `ja4h: Option<String>` field |
| Modify | `src/extractor.rs` | New `JaQuad { ja4t, ja4ts, ja4l, ja4ls }` carried on `Extracted<K>` (optional) |
| Modify | `src/lib.rs` | `pub use tls::{ja4s, Ja4sParts, ja4x, Ja4xParts};` `pub use http::{ja4h, Ja4hParts};` |
| Modify | `Cargo.toml` | `x509-parser = { version = "0.16", optional = true }`; add to `tls-fingerprints` feature deps |
| New | `tests/ja4s.rs` | Golden-fixture tests against the FoxIO reference suite |
| New | `tests/ja4h.rs` | Golden-fixture tests |
| New | `tests/ja4t.rs` | Golden-fixture tests for both JA4T and JA4TS |
| New | `tests/ja4l.rs` | Latency-computation tests |
| New | `tests/ja4x.rs` | Cert-chain golden fixtures |
| Modify | `tests/fixtures/` | Add canonical FoxIO-derived test vectors |
| New | `examples/02-forensics/ja4_family.rs` | End-to-end pcap → all-five JA4+ fingerprints |
| Modify | `CHANGELOG.md` | 0.12 entry |
| New | `docs/ja4-plus.md` | Algorithm reference: format spec per variant, links to FoxIO repo, comparison table |

## API

### JA4S (TLS ServerHello)

```rust
// src/tls/ja4s.rs

/// Components of a JA4S fingerprint.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Ja4sParts {
    /// Transport: `'t'` (TCP) or `'q'` (QUIC).
    pub transport: char,
    /// TLS version of the ServerHello (e.g. "13" for TLS 1.3).
    pub version: String,
    /// Extension count.
    pub ext_count: u16,
    /// First two chars of selected ALPN, or "00" if none.
    pub alpn: String,
    /// Selected cipher suite, hex.
    pub cipher_hex: String,
    /// SHA-256 (hex, truncated to 12) of the extension list in
    /// observed order (NOT sorted, unlike JA4 client).
    pub extension_hash: String,
}

/// Assemble the JA4S string from a [`TlsServerHello`].
///
/// Format: `<t|q><ver><extcount><alpn>_<cipher_hex>_<exthash[:12]>`
///
/// Example: `t130200h2_c02b_4e2a4dcdb5f5`
pub fn ja4s(sh: &TlsServerHello) -> String { … }

/// Compute the parts struct without joining.
pub fn ja4s_parts(sh: &TlsServerHello) -> Ja4sParts { … }
```

### JA4H (HTTP/1.1 client request)

```rust
// src/http/ja4h.rs

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Ja4hParts {
    /// 4-char method prefix lowercased (e.g. "ge11").
    pub method_version: String,
    /// 'c' if Cookie header present else 'n'.
    pub cookie_flag: char,
    /// 'r' if Referer header present else 'n'.
    pub referer_flag: char,
    /// 2-digit header count (excluding Cookie/Referer).
    pub header_count: u16,
    /// 4-char Accept-Language primary value lowercased
    /// with '-' stripped, or "0000".
    pub lang: String,
    /// SHA-256[:12] of header names in observed order
    /// (excluding Cookie / Referer).
    pub header_hash: String,
    /// SHA-256[:12] of cookie name list (sorted).
    pub cookie_names_hash: String,
    /// SHA-256[:12] of cookie `name=value` pairs (sorted).
    pub cookie_pairs_hash: String,
}

pub fn ja4h(req: &HttpRequest) -> String { … }
pub fn ja4h_parts(req: &HttpRequest) -> Ja4hParts { … }
```

Format: `<method_version><cookie_flag><referer_flag><hdrcount><lang>_<headers_hash>_<cookie_names_hash>_<cookie_pairs_hash>`

Example: `ge11nc05enus_aabbccddeeff_112233445566_99887766aabb`

### JA4T / JA4TS (TCP SYN options)

```rust
// src/extract/ja4t.rs

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Ja4tParts {
    pub window: u16,
    /// CSV of TCP option kinds in observed order (decimal).
    pub options_csv: String,
    /// MSS value or 0 if absent.
    pub mss: u16,
    /// Window scale shift or 0.
    pub window_scale: u8,
}

/// Compute JA4T over the SYN packet.
///
/// Format: `<window>_<options_csv>_<mss>_<window_scale>`
/// (kinds separated by `-`).
///
/// Example: `64240_2-4-8-1-3_1460_7`
pub fn ja4t(raw_options: &[u8], window: u16) -> String { … }

/// Compute JA4TS over the SYN-ACK packet.
pub fn ja4ts(raw_options: &[u8], window: u16) -> String { … }
```

Plain string, no hash. Parses `raw_options` per RFC 793 §3.1
(kind / length / value). Skips unknown options gracefully.

### JA4L / JA4LS (one-way latency)

```rust
// src/extract/ja4l.rs

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Ja4lParts {
    /// IP TTL (or hop limit for IPv6) of the SYN.
    pub ttl: u8,
    /// One-way latency estimate, microseconds.
    pub rtt_us: u32,
}

/// JA4L (client→server) — computed when SYN-ACK is observed:
/// `(synack_ts - syn_ts) / 2`.
pub fn ja4l(
    syn_ttl: u8,
    syn_ts: Timestamp,
    synack_ts: Timestamp,
) -> String { … }

/// JA4LS (server→client) — computed when ACK is observed:
/// `(ack_ts - synack_ts) / 2`.
pub fn ja4ls(
    synack_ttl: u8,
    synack_ts: Timestamp,
    ack_ts: Timestamp,
) -> String { … }
```

Format: `<ttl>_<rtt_us>` (e.g. `64_523`). Per-flow state held
by `FlowTracker` so the parser can call it at the right moment.

### JA4X (X.509 cert chain)

```rust
// src/tls/ja4x.rs

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Ja4xParts {
    /// SHA-256[:12] of issuer RDN OID list (comma-joined,
    /// per-cert, in chain order).
    pub issuer_hash: String,
    /// SHA-256[:12] of subject RDN OID list.
    pub subject_hash: String,
    /// SHA-256[:12] of extension OID list.
    pub extension_hash: String,
}

pub fn ja4x(certs: &[Bytes]) -> Option<String> { … }
```

Format: `<issuer_hash>_<subject_hash>_<extension_hash>`.
Returns `None` if no certs were observed (e.g., TLS 1.3 with
0-RTT skipping Certificate).

## Implementation steps

### Phase 1: `TcpInfo::raw_options` (foundation for JA4T)

1. `src/extract/parse.rs` etherparse slicer: capture raw TCP
   options bytes as a `Bytes` view zero-copy over the frame.
   Already parsed inside etherparse's TcpHeaderSlice; expose
   the slice.
2. `src/extractor.rs` `TcpInfo`: add
   `raw_options: bytes::Bytes` field. `#[non_exhaustive]`
   already covers the addition.
3. Verify `track_into_steady_state` benches still report 0
   allocs (the Bytes slice is zero-copy).

### Phase 2: JA4S

4. `src/tls/types.rs`: extend `TlsServerHello` with the four
   fields JA4S needs (`selected_cipher: u16`,
   `selected_alpn: Option<Bytes>`,
   `extensions_in_order: Vec<u16>`,
   `version_chosen: TlsVersion`).
5. `src/tls/parser.rs`: populate the new fields from
   `tls-parser`'s ServerHello parse output.
6. `src/tls/ja4s.rs` (new): implement `ja4s` + `ja4s_parts`
   matching the FoxIO spec.
7. `src/tls/handshake.rs`: compute JA4S inside
   `TlsHandshakeParser` after the ServerHello is observed.

### Phase 3: JA4H

8. `src/http/ja4h.rs` (new): implement `ja4h` + `ja4h_parts`
   per the spec. All inputs already available on `HttpRequest`.
9. `src/http/exchange.rs`: add `ja4h` to `HttpExchange` event.
10. Per-message: `HttpExchangeParser` computes JA4H on the
    request side.

### Phase 4: JA4T / JA4TS

11. `src/extract/ja4t.rs` (new): TCP options parser +
    `ja4t` / `ja4ts` builders.
12. `src/extractor.rs` `Extracted<K>`: add `ja4t: Option<String>`
    and `ja4ts: Option<String>` slots populated by extractors
    when they see a SYN / SYN-ACK.
13. Both five-tuple and inner-encap extractors compute these
    when observing TCP SYN flags.

### Phase 5: JA4L / JA4LS

14. `src/tracker.rs` `FlowEntry`: add `syn_seen_at`,
    `synack_seen_at`, `ack_seen_at`, `syn_ttl`, `synack_ttl`
    fields. Populated by the tracker on TCP state transitions.
15. `src/extract/ja4l.rs` (new): the algorithm + format.
16. Surface JA4L / JA4LS on `FlowEvent::Established` (computed
    on 3WHS completion) via new optional fields, or via a
    standalone tracker accessor `tracker.ja4l(key) -> Option<String>`.

### Phase 6: JA4X

17. New dep: `x509-parser = "0.16"`. Add to `tls-fingerprints`
    feature.
18. `src/tls/parser.rs`: parse Certificate handshake message;
    extract raw DER for each cert in chain order. Stored as
    `Vec<Bytes>` on `TlsHandshake`.
19. `src/tls/ja4x.rs` (new): `x509-parser::parse_x509_certificate`
    on each cert; OID enumeration per the spec; SHA-256 of
    comma-joined OIDs.
20. `TlsHandshakeParser` computes JA4X when Certificate is
    observed.

### Phase 7: Tests + example + doc

21. Bring in the FoxIO reference test vectors from
    `github.com/FoxIO-LLC/ja4/tree/main/pcap` — pcap files +
    expected JA4* strings.  Embed minimal pcaps under
    `tests/fixtures/ja4plus/`.
22. `tests/ja4s.rs`, `tests/ja4h.rs`, `tests/ja4t.rs`,
    `tests/ja4l.rs`, `tests/ja4x.rs` — golden assertions.
23. `examples/02-forensics/ja4_family.rs` — pcap →
    all-five fingerprints per flow.
24. `docs/ja4-plus.md` — algorithm reference + format spec +
    FoxIO link.
25. CHANGELOG 0.12 entry.

## Tests

### Unit (per file)

- `ja4s::tests::server_hello_with_alpn_matches_golden`
- `ja4s::tests::server_hello_no_alpn_yields_00`
- `ja4h::tests::get_request_no_cookies_no_referer_matches_golden`
- `ja4h::tests::post_with_cookies_hashes_pairs_sorted`
- `ja4t::tests::standard_linux_syn_options_yield_known_string`
- `ja4t::tests::synack_yields_different_string_via_ja4ts`
- `ja4l::tests::rtt_us_is_half_of_observed_delta`
- `ja4x::tests::single_cert_no_chain_returns_some`
- `ja4x::tests::missing_certs_returns_none`

### Integration

- `tests/ja4s.rs::handshake_aggregator_emits_ja4s_field` —
  end-to-end via `TlsHandshakeParser`.
- `tests/ja4h.rs::http_exchange_carries_ja4h` — end-to-end
  via `HttpExchangeParser`.
- `tests/ja4t.rs::pcap_replay_emits_ja4t_per_syn` — full
  pcap replay.
- `tests/ja4l.rs::three_way_handshake_completion_emits_ja4l` —
  fixture pcap with controlled timing.
- `tests/ja4x.rs::tls_handshake_with_cert_chain_emits_ja4x`.

### Golden fixtures

- `tests/fixtures/ja4plus/curl.pcap` (FoxIO ref) →
  exact expected fingerprints in a sibling `.txt` file.
- `tests/fixtures/ja4plus/firefox.pcap` (FoxIO ref) →
  exact expected fingerprints.
- `tests/fixtures/ja4plus/chrome.pcap` (FoxIO ref) →
  exact expected fingerprints.

## Acceptance criteria

- `cargo build --features tls-fingerprints,http,pcap` clean.
- `cargo test --features tls-fingerprints,http,pcap` clean —
  every golden fixture matches FoxIO reference output.
- `cargo clippy --features tls-fingerprints,http,pcap
  --all-targets -- -D warnings` clean.
- CI feature matrix grows by `tls-fingerprints` entry
  (already added in plan 131; this plan validates it carries
  all five variants).
- `examples/02-forensics/ja4_family.rs` runs end-to-end on
  shipped pcaps with a non-empty result for each variant.
- `docs/ja4-plus.md` documents every variant's format + a
  link to the FoxIO authoritative spec.
- Bench gate `track_into_steady_state` still reports 0
  allocs/pkt (TcpInfo grows by a Bytes view — no new
  allocation).

## Risks

- **R1: `TcpInfo::raw_options` field break.** Documented above;
  `#[non_exhaustive]` covers it but a downstream consumer
  that destructures `TcpInfo` with explicit field syntax
  needs to add `..`. Mitigation: CHANGELOG migration recipe.
- **R2: `x509-parser` dep size.** ~150 KB compiled, brings
  `der-parser` + `nom`. Feature-gated under
  `tls-fingerprints` — anyone enabling JA4 is opted in.
- **R3: JA4 spec drift.** FoxIO has revised the JA4H cookie
  hashing rule and JA4T separator conventions between mid-2024
  and late-2025. Mitigation: pin to FoxIO repo's
  `technical_details/` at a specific commit hash documented
  in `docs/ja4-plus.md`; gate behind golden fixtures so a
  spec drift surfaces as a test failure.
- **R4: JA4L per-flow state cost.** Adds 5 fields × 4-8 bytes
  per `FlowEntry`. At max_flows=100k that's ~3 MB extra. Cost
  documented in `docs/performance.md`. Acceptable.
- **R5: x509-parser allocates per-cert.** A handshake with
  3-cert chain costs ~6 allocs per JA4X computation. Only
  fires when `TlsHandshakeParser` is registered. Documented
  in `docs/performance.md`.

## Effort

| Step | LoC | Hours |
|---|---|---|
| `TcpInfo::raw_options` + etherparse plumbing | 80 | 2 |
| JA4S (parser fields + algorithm) | 120 | 3 |
| JA4H (parser + exchange wiring) | 130 | 3 |
| JA4T / JA4TS (extractor + algorithm) | 150 | 3 |
| JA4L / JA4LS (tracker timing + algorithm) | 180 | 4 |
| JA4X (cert parsing + algorithm + new dep) | 200 | 5 |
| Golden fixtures + 25 tests | 400 | 6 |
| Example + docs/ja4-plus.md | 120 | 3 |
| CHANGELOG | 40 | 1 |
| **Total** | **~1420** | **~30 hours (~4 days)** |

## Provenance

netring 0.21 wishlist (Phase D §"More TLS fingerprints").
Suricata 7.0+, Zeek's `ja4` package, CrowdStrike Falcon,
Cloudflare Bot Management, GreyNoise all consume JA4+ in
2026; passing fingerprints through the EVE writer (plan 123)
makes flowscope a drop-in source for any consumer pipeline
expecting JA4+. The 0.12 audit ranked this Tier-1 highest-ROI
(JA4+ is "2026 table stakes").

Reference: `github.com/FoxIO-LLC/ja4/tree/main/technical_details`.

## Open questions

1. **Where does the per-flow JA4L state live?** Options:
   - `FlowEntry` fields on the tracker (chosen above).
   - Separate `FlowTracker::ja4_state: HashMap<K, Ja4State>`
     side-channel — keeps `FlowEntry` lean.
   The plan picks `FlowEntry` for simplicity; revisit if
   a benchmark shows the size hit matters.
2. **Should JA4S surface on `TlsServerHello` directly or only
   via the handshake aggregator?** Plan picks aggregator-only
   (consumers using `TlsParser` directly compute via the
   exported `ja4s()` fn). Avoids field clutter on the type.

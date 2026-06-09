# Plan 120 — Bytes audit across L7 parsed-message types

## Summary

Convert every owned `Vec<u8>` / `String` in HTTP / DNS / TLS /
ICMP parsed-message types that holds wire-bytes into
`bytes::Bytes`. The parsers already produce these values from a
known source buffer; the conversion is at worst one
`Bytes::copy_from_slice` per field (a single Arc bump-allocates
its backing store; subsequent slices are zero-copy `Bytes::slice`
calls into that store).

After this plan: an HTTP/1.1 GET parse is ≤ 4 heap allocations
(down from ~24). A DNS response with 5 TXT records is ≤ 6 (down
from ~10). A TLS client-hello is ≤ 2 (down from ~3).

## Status

Not started. Independent of plan 119; can run in parallel.
Sequenced after 119 in the umbrella so the migration guide
covers parser-shape + payload-shape changes together.

## Prerequisites

- Plan 118 Phase 0 — per-protocol bench rows in place.

## Out of scope

- **`HttpMethod` / `HttpStatusCode` newtype enums.** First
  draft of this plan proposed a `HttpMethod` enum with
  `Known(&'static str) | Other(Bytes)`. Dropped on second
  pass: just `Bytes` everywhere is simpler. For the 8 standard
  methods that already live as `&'static str` literals in the
  HTTP RFC, `Bytes::from_static(b"GET")` is a stack-only
  constant in the parser — no heap. The enum was solving a
  problem the type system already solves.
- **DNS owner-name parsing.** `simple-dns` produces `String`
  owner-names from the wire's compressed labels; the labels
  point into a transient buffer the parser doesn't own past
  the call. Owner-names stay `String`.
- **HTTP body — already `Bytes` since 0.6.** No change.
- **Wire-format compatibility for serde-serialized
  payloads.** Bytes serializes as base64 by default in
  `serde_json`; `Vec<u8>` serializes as a byte-array. The
  serde feature already documents the locked format; this
  plan adds `#[serde(with = "serde_bytes")]` to every
  Bytes-typed field to keep byte-array encoding.

## Files

### HTTP

- `src/http/types.rs` — `HttpRequest` and `HttpResponse`:
  - `method: String` → `Bytes`
  - `path: String` → `Bytes`
  - `headers: Vec<(String, Vec<u8>)>` → `Vec<(Bytes, Bytes)>`
  - `reason: String` → `Bytes` (response only)
  - All internal helper fn signatures.
- `src/http/parser.rs` — switch `String::from_utf8_lossy(...)`
  / `bytes.to_vec()` constructors to `bytes::Bytes::copy_from_slice`
  (or `Bytes::slice` when the parser already holds a `Bytes`
  backing store).
- `src/http/session.rs` — no changes; the SessionParser wrapper
  is shape-agnostic.
- `src/http/exchange.rs` — exchange-aggregator field reads
  updated.

### DNS

- `src/dns/types.rs` — `DnsRdata` variants:
  - `TXT(Vec<Vec<u8>>)` → `TXT(SmallVec<[Bytes; 4]>)`
  - `Other { code, data: Vec<u8> }` → `Other { code, data:
    Bytes }`
- `src/dns/parser.rs` — wire the conversions.
- `src/dns/datagram.rs`, `src/dns/session.rs`,
  `src/dns/exchange.rs` — propagate the type changes.

### TLS

- `src/tls/types.rs`:
  - `TlsClientHello::compression: Vec<u8>` → `Bytes`
  - `TlsServerHello` — audit for any owned `Vec<u8>` payloads.
- `src/tls/parser.rs` — wire conversions.
- `src/tls/handshake.rs` — propagate.

### ICMP

- `src/icmp/types.rs` — audit `IcmpMessage` variants for any
  owned `Vec<u8>` payloads. Likely the `IcmpInner` types.
- `src/icmp/parser.rs` — convert.

### Consumers

- `src/well_known/mod.rs` — protocol_label callers that today
  format from `String` method names; update read paths.
- `src/emit/csv.rs`, `src/emit/ndjson.rs`, `src/emit/zeek.rs` —
  field reads switch from `String` to `&str` (via
  `std::str::from_utf8(bytes.as_ref())`) or pass `Bytes` to
  the writer directly.

### Tests

- `tests/http_parser.rs`, `tests/dns_parser.rs`,
  `tests/tls_parser.rs`, `tests/icmp_parser.rs` — assertions
  updated to `assert_eq!(req.method.as_ref(), b"GET")` shape
  or via a `req.method_str()` shortcut.
- `tests/http_pcap.rs`, `tests/pcap_integration.rs`,
  `tests/dns_correlator.rs` — same.
- `tests/http_exchange.rs`, `tests/dns_exchange.rs`.
- `tests/serde_wire.rs` — snapshot tests verifying the serde
  JSON shape is unchanged when `#[serde(with = "serde_bytes")]`
  is applied.

### Examples

- `examples/01-l7-logging/`, `examples/05-export/`,
  `examples/06-custom-protocols/` — sweep for any String /
  Vec<u8> field reads on parsed-message types.

### Docs

- `docs/migration-0.10-to-0.11.md` — section
  "L7 payload type changes" with 5 recipes:
  - method/path comparison: `req.method == "GET"` →
    `req.method.as_ref() == b"GET"` or use new
    `req.method_str()` accessor.
  - header lookup by name: already covered by existing
    accessors (`req.host()` etc.); for direct iteration,
    `(k, v)` is now `(Bytes, Bytes)`; deref to `&[u8]` via
    `.as_ref()`.
  - DNS TXT iteration: `for rec in &txt { /* &Bytes */ }`.
  - DNS Other rdata: `data.as_ref()` for the byte slice.
  - Serde JSON shape: unchanged (byte-array encoding preserved
    via `#[serde(with = "serde_bytes")]`).
- `docs/serde-locked.md` — document the `serde_bytes`
  attribute usage.

### Cargo.toml

- Add `serde_bytes` dep behind `serde` feature.

## API

### Before → after sketches

```rust
// HTTP
pub struct HttpRequest {
    pub method: Bytes,        // was String
    pub path: Bytes,          // was String
    pub version: HttpVersion,
    pub headers: Vec<(Bytes, Bytes)>,  // was Vec<(String, Vec<u8>)>
    pub body: Bytes,          // unchanged
}

pub struct HttpResponse {
    pub status: u16,
    pub reason: Bytes,        // was String
    pub version: HttpVersion,
    pub headers: Vec<(Bytes, Bytes)>,
    pub body: Bytes,
}

// DNS
pub enum DnsRdata {
    /* ... */
    TXT(smallvec::SmallVec<[Bytes; 4]>),    // was Vec<Vec<u8>>
    Other { code: u16, data: Bytes },        // was data: Vec<u8>
}

// TLS
pub struct TlsClientHello {
    /* ... */
    pub compression: Bytes,   // was Vec<u8>
}
```

### New convenience accessors

```rust
impl HttpRequest {
    /// Method as UTF-8 string slice. None if non-UTF-8.
    pub fn method_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.method).ok()
    }
    /// Path as UTF-8 string slice.
    pub fn path_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.path).ok()
    }
}

impl HttpResponse {
    pub fn reason_str(&self) -> Option<&str> { /* ... */ }
}
```

### Existing header accessors stay shape-compatible

`HttpRequest::host()` / `user_agent()` etc. already return
`Option<&str>`; only the internal lookup helper changes from
`String::eq_ignore_ascii_case(name)` to a one-line
`name.as_bytes().eq_ignore_ascii_case(field.0.as_ref())`.

`HttpRequest::header(name) -> Option<&[u8]>` — return type stays
`&[u8]`; backing `Bytes` derefs transparently.

## Implementation steps

1. **Add `bytes::Bytes`-typed fields on `HttpRequest`.** Update
   parser to call `Bytes::copy_from_slice(s)` where it currently
   calls `s.to_vec()` / `String::from_utf8(s).ok()`.
2. **Add `method_str` / `path_str` accessors** for the common
   case of just wanting `&str`.
3. **Same for `HttpResponse`.**
4. **Update header lookup helper.** One-line swap to byte-slice
   comparison.
5. **Update `DnsRdata` variants.**
6. **Update `TlsClientHello::compression`.** Audit
   `TlsServerHello` for any other owned Vec<u8>; convert.
7. **Update `IcmpMessage`.** Audit variants; convert any owned
   payload.
8. **Update emit writers.** Three files; mostly mechanical
   `bytes.as_ref()` / `from_utf8` insertions.
9. **Update tests + examples.** Largest mechanical work; ~30
   files touched.
10. **Add `serde_bytes` dep + attribute to every Bytes-typed
    field** under `#[cfg(feature = "serde")]`. Snapshot tests
    verify the wire format is unchanged.
11. **Migration guide section.** 5 recipes; cheat-sheet at
    bottom.
12. **Bench.** Run the per-protocol bench rows. Phase 2 of the
    umbrella's Baseline table records the post-Phase-2 numbers.

## Tests

- `tests/http_parser.rs::headers_share_backing_bytes` — two
  headers parsed from the same source produce `Bytes` that
  share the same underlying Arc (verified via
  `Bytes::ptr_eq`).
- `tests/http_parser.rs::method_str_returns_utf8_view` — the
  new accessor works on common methods.
- `tests/dns_parser.rs::txt_records_smallvec_no_alloc_for_small_n`
  — 1- to 4-record TXTs use the SmallVec inline storage, no
  heap.
- `tests/tls_parser.rs::compression_empty_no_alloc` —
  `compression.is_empty()` for the "no compression" common
  case doesn't allocate.
- `tests/serde_wire.rs::http_request_json_unchanged` —
  snapshot test: JSON shape of a parsed request matches the
  0.10.1 snapshot byte-for-byte.
- Bench (gates Phase 2 of plan 118 baseline table):
  - `benches/zero_alloc.rs::bench_http_request_parse` ≤ 4.
  - `benches/zero_alloc.rs::bench_dns_response_5_txt` ≤ 6.
  - `benches/zero_alloc.rs::bench_tls_client_hello` ≤ 2.

## Acceptance criteria

- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- All 9 CI feature-matrix entries clean.
- `cargo doc --all-features --no-deps` zero warnings.
- Per-protocol bench gate rows hit their targets.
- Migration guide section "L7 payload type changes"
  complete.
- Serde JSON snapshot tests pass — the wire format is
  preserved for downstream consumers.
- CHANGELOG 0.11.0 entry documents the type changes with one
  recipe per common field-read pattern.

## Risks

- **Existing `req.method == "GET"` callsites break.**
  Mitigation: `Bytes: PartialEq<&[u8]>` and
  `Bytes: PartialEq<str>` impls from the `bytes` crate make
  `req.method == "GET"` keep compiling but now compares bytes
  directly. Verified in the bytes 1.x docs. Migration guide
  shows both `==` and `method_str()` patterns.
- **`Bytes::copy_from_slice` is not always zero-copy.** It
  bump-allocates an Arc and copies bytes in. The win is the
  unified backing store (one Arc per parse call vs. N separate
  Vecs), not zero allocation in absolute terms.
  Mitigation: where the parser already holds a `Bytes` backing
  store (HTTP parser does, since `body: Bytes` already exists),
  switch headers / path / method to `Bytes::slice(range)` —
  truly zero-copy. Document the cost model in the rustdoc on
  each parsed-message type.
- **Serde wire format changes for `Bytes` fields.** Mitigation:
  `#[serde(with = "serde_bytes")]` keeps the byte-array
  encoding identical to today's `Vec<u8>`. Snapshot tests in
  `tests/serde_wire.rs` enforce this in CI.
- **smallvec inline size 4 wrong for TXT records.** Real-world
  TXT records sometimes carry 6+ strings (e.g. DKIM split
  records). Mitigation: 4 inline is the modal case; the
  spillover heap-allocation is one Vec, not N Bytes. Net
  improvement over today.

## Effort

~3 working days:
- 0.5d HTTP types + parser + accessors.
- 0.5d DNS / TLS / ICMP types + parsers.
- 0.5d emit writers + well-known + propagation.
- 0.5d tests + serde snapshot tests.
- 0.5d examples + migration guide.
- 0.5d bench verification + buffer.

## Provenance

- `flowscope-deps-for-netring-0.19-reanalysis-2026-06-09.md`
  §4.4 (full L7-type Bytes audit — the original audit's
  §3.3 only covered HTTP headers, and only half-way).
- The `HttpMethod` enum from the first-draft plan 121 is
  dropped here: `Bytes::from_static(b"GET")` covers the
  zero-alloc case for known methods without the enum.

# Plan 113 — `flowscope::detect::signatures` — protocol magic-byte recognizers

## Summary

Ship a small set of pure-function magic-byte recognizers for
the protocols flowscope already parses, plus a few common
non-parsed ones. Each signature has the shape:

```rust
fn http_request(bytes: &[u8]) -> SignatureMatch;
```

and returns one of `Match` / `NoMatch` / `NeedMoreData`. No
state, no allocation, suitable for hot-path dispatch.

This is the building block for plan 114 (heuristic routing
on `FlowMultiDriver`). It's also useful standalone — a
consumer that wants "is this flow's first segment HTTP-shaped?"
can call the signature directly without registering anything.

Plan 112 audit confirmed that:
- Every comparable system (Suricata, Zeek, nDPI, Wireshark)
  ships signature/pattern matching as the cheap-first stage.
- The signatures themselves are stable across decades (HTTP's
  `GET ` / `POST` / `HTTP/1.` patterns haven't changed since
  RFC 2616).
- A small curated catalog beats a giant one — Wireshark's
  advice is "strict signatures with multiple confirmation
  bytes."

## Status

**Ready to implement.** Targets 0.10.0. Sibling to plan 114
(heuristic routing); 113 ships independently and 114 builds
on it.

## Prerequisites

- Plan 104 — `flowscope::detect` module (Shannon entropy +
  light primitives). 113 extends the same module with a
  `signatures` submodule.

## Out of scope

- **Aho-Corasick multi-pattern matching.** Each signature is
  a standalone function; we don't ship a registered-pattern
  dispatcher. Plan 114 wires the signatures up to dispatch.
- **Bayesian / ML-based detection.** Deterministic functions
  only.
- **Large protocol catalog.** Ship 8-12 signatures matching
  the common-protocol set + the ones flowscope already
  parses. Adding more is a per-consumer ask.
- **Server-side / response-side signatures.** Initial cut
  focuses on initiator-direction first-packet detection
  (the cheapest and most reliable mode). Responder-direction
  signatures may follow if a consumer asks.
- **TLS server-side / Application-Layer Protocol Negotiation
  (ALPN) sniffing.** TLS's own ClientHello is signature-
  detectable; the TLS-over-X demultiplexing is downstream.

---

## API

### Signature shape

```rust
// src/detect/signatures.rs

/// Result of a signature evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureMatch {
    /// Bytes definitively match this protocol.
    Match,
    /// Bytes definitively do not match.
    NoMatch,
    /// Not enough bytes to decide — re-check with more.
    /// The signature returns this when the bytes seen so far
    /// are a valid prefix of a match but the discriminator
    /// hasn't been reached yet.
    NeedMoreData,
}
```

Each signature is a free function:

```rust
pub fn http_request(bytes: &[u8]) -> SignatureMatch;
pub fn http_response(bytes: &[u8]) -> SignatureMatch;
pub fn tls_client_hello(bytes: &[u8]) -> SignatureMatch;
pub fn tls_server_hello(bytes: &[u8]) -> SignatureMatch;
pub fn ssh_banner(bytes: &[u8]) -> SignatureMatch;
pub fn dns_message(bytes: &[u8]) -> SignatureMatch;
pub fn smtp_banner(bytes: &[u8]) -> SignatureMatch;
pub fn ftp_banner(bytes: &[u8]) -> SignatureMatch;
pub fn irc_message(bytes: &[u8]) -> SignatureMatch;
pub fn redis_resp(bytes: &[u8]) -> SignatureMatch;
pub fn mqtt_connect(bytes: &[u8]) -> SignatureMatch;
pub fn postgres_startup(bytes: &[u8]) -> SignatureMatch;
```

12 signatures. Each is a few dozen lines.

### Sample implementations

```rust
/// HTTP/1.x request line: optional whitespace + (CONNECT |
/// DELETE | GET | HEAD | OPTIONS | PATCH | POST | PUT |
/// TRACE) + space + path + space + `HTTP/1.`.
pub fn http_request(bytes: &[u8]) -> SignatureMatch {
    const METHODS: &[&[u8]] = &[
        b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ",
        b"OPTIONS ", b"PATCH ", b"TRACE ", b"CONNECT ",
    ];
    // Need at least 16 bytes ("GET / HTTP/1.0\r\n").
    if bytes.len() < 16 {
        // But even a short prefix can be ruled out.
        if !METHODS.iter().any(|m| bytes.len() < m.len() || bytes.starts_with(m) || m.starts_with(bytes)) {
            return SignatureMatch::NoMatch;
        }
        return SignatureMatch::NeedMoreData;
    }
    let starts_with_method = METHODS.iter().any(|m| bytes.starts_with(m));
    if !starts_with_method {
        return SignatureMatch::NoMatch;
    }
    // Confirm `HTTP/1.` appears within the first ~256 bytes.
    let scan_limit = bytes.len().min(256);
    if bytes[..scan_limit].windows(7).any(|w| w == b"HTTP/1.") {
        SignatureMatch::Match
    } else {
        SignatureMatch::NeedMoreData
    }
}

/// TLS ClientHello: record-layer-version + 0x16 content type.
pub fn tls_client_hello(bytes: &[u8]) -> SignatureMatch {
    // TLS record: type(1) + version(2) + length(2) + payload.
    if bytes.len() < 6 {
        if bytes[0] != 0x16 && !bytes.is_empty() {
            return SignatureMatch::NoMatch;
        }
        return SignatureMatch::NeedMoreData;
    }
    // Handshake content type.
    if bytes[0] != 0x16 { return SignatureMatch::NoMatch }
    // Record version: TLS 1.0-1.3 in the wire (1.3 uses 0x0303 for compat).
    let version = u16::from_be_bytes([bytes[1], bytes[2]]);
    if !matches!(version, 0x0301 | 0x0302 | 0x0303) {
        return SignatureMatch::NoMatch;
    }
    // Handshake message type 0x01 = ClientHello.
    if bytes[5] != 0x01 { return SignatureMatch::NoMatch }
    SignatureMatch::Match
}

/// SSH banner: `SSH-2.0-` (or `SSH-1.99-`).
pub fn ssh_banner(bytes: &[u8]) -> SignatureMatch {
    if bytes.len() < 4 {
        if !b"SSH-".starts_with(bytes) {
            return SignatureMatch::NoMatch;
        }
        return SignatureMatch::NeedMoreData;
    }
    if !bytes.starts_with(b"SSH-") {
        return SignatureMatch::NoMatch;
    }
    // SSH-N.M-…\r\n format. Need to see `-` after the version.
    if bytes.len() < 8 {
        return SignatureMatch::NeedMoreData;
    }
    // Version digits + dash.
    if !(bytes[4].is_ascii_digit() && bytes[5] == b'.') {
        return SignatureMatch::NoMatch;
    }
    SignatureMatch::Match
}
```

The other signatures follow the same shape. Each is ~15-30
lines including the comment.

### Helper: registered table

```rust
// src/detect/signatures.rs

/// Curated map of `parser_kind` → signature. The
/// `parser_kind` strings line up with the existing
/// `flowscope::parser_kinds::*` constants so signature
/// matches dispatch back to the existing parsers.
pub fn registry() -> impl Iterator<Item = (&'static str, SignatureFn)> {
    [
        ("http",          http_request as SignatureFn),
        ("tls",           tls_client_hello as SignatureFn),
        ("dns",           dns_message as SignatureFn),
        ("ssh",           ssh_banner as SignatureFn),
        ("smtp",          smtp_banner as SignatureFn),
        ("ftp",           ftp_banner as SignatureFn),
        ("irc",           irc_message as SignatureFn),
        ("redis-resp",    redis_resp as SignatureFn),
        ("mqtt",          mqtt_connect as SignatureFn),
        ("postgres",      postgres_startup as SignatureFn),
    ]
    .into_iter()
}

pub type SignatureFn = fn(&[u8]) -> SignatureMatch;
```

The registry is plain data — consumers wanting their own
catalog (proprietary protocols, threat-intel signatures)
clone it and add entries.

---

## Files

```
src/detect/signatures.rs    # 12 signature functions + registry (NEW)
src/detect/mod.rs           # re-export
tests/detect_signatures.rs  # known-good + known-bad coverage per signature
docs/recipes.md             # add "Heuristic protocol detection" section
CHANGELOG.md                # 0.10 entry
```

## Implementation steps

1. Create `src/detect/signatures.rs` with the 12 signature
   functions.
2. Add `registry()` returning the curated `(kind, fn)` table.
3. Re-export from `src/detect/mod.rs`.
4. Add `tests/detect_signatures.rs` — per-signature unit
   tests:
   - Known-good byte sequence → `Match`.
   - Known-bad sequence → `NoMatch`.
   - Truncated prefix (1-3 bytes of a known-good sequence) →
     `NeedMoreData`.
   - Random bytes → `NoMatch`.
   - Property test: any prefix of a `Match` input never returns
     `NoMatch` (only `Match` or `NeedMoreData`). [splitting
     invariance, same shape as the parser proptests]
5. Add a `docs/recipes.md` "Heuristic protocol detection"
   section showing the signatures used standalone, before
   plan 114 lands.
6. CHANGELOG entry under 0.10.0 "Added."

## Tests

`tests/detect_signatures.rs`:

```rust
fn assert_match_table(sig: fn(&[u8]) -> SignatureMatch, examples: &[(&[u8], SignatureMatch)]) {
    for (bytes, expected) in examples {
        assert_eq!(sig(bytes), *expected, "{bytes:?} expected {expected:?}");
    }
}

#[test]
fn http_request_signature() {
    assert_match_table(http_request, &[
        (b"GET / HTTP/1.1\r\n", SignatureMatch::Match),
        (b"POST /a HTTP/1.0\r\n", SignatureMatch::Match),
        (b"GET ", SignatureMatch::NeedMoreData),
        (b"GE", SignatureMatch::NeedMoreData),
        (b"XYZ", SignatureMatch::NoMatch),
        (b"\x16\x03\x01", SignatureMatch::NoMatch),  // TLS ClientHello bytes
        (b"GET /index.html ", SignatureMatch::NeedMoreData),  // no HTTP/1. yet
    ]);
}

#[test]
fn tls_client_hello_signature() {
    assert_match_table(tls_client_hello, &[
        (&[0x16, 0x03, 0x01, 0x00, 0x42, 0x01], SignatureMatch::Match),
        (&[0x16, 0x03, 0x03, 0x00, 0x42, 0x01], SignatureMatch::Match),
        (&[0x16, 0x03, 0x04, 0x00, 0x42, 0x01], SignatureMatch::NoMatch),  // bad version
        (&[0x17, 0x03, 0x01, 0x00, 0x42, 0x01], SignatureMatch::NoMatch),  // bad content type
        (&[0x16, 0x03], SignatureMatch::NeedMoreData),
        (b"GET / HTTP/1.1", SignatureMatch::NoMatch),
    ]);
}

// Per-signature tests for each of the 12, similar shape.

#[test]
fn splitting_invariance_proptest() {
    // For each signature, for each known-good input,
    // any prefix < full length returns NeedMoreData or Match
    // but never NoMatch.
    use proptest::prelude::*;
    proptest!(|(prefix_len in 1usize..=64)| {
        let bytes = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let prefix_len = prefix_len.min(bytes.len());
        let prefix = &bytes[..prefix_len];
        let result = http_request(prefix);
        prop_assert_ne!(result, SignatureMatch::NoMatch);
    });
}
```

12+ scenarios per signature × 12 signatures + 1 proptest =
~150 test cases. Manageable.

## Acceptance criteria

- 12 signature functions ship.
- `registry()` table ships.
- Per-signature unit tests pass; proptest passes.
- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- `docs/recipes.md` "Heuristic protocol detection" section
  ships.
- CHANGELOG entry under 0.10.0 "Added."

## Risks

- **Signature drift over time.** New protocols / RFC versions
  may introduce variants. Mitigation: signatures are
  intentionally lenient (e.g. accept TLS 1.0, 1.1, 1.2, 1.3
  even though we technically only handle some). Update in
  patch releases.
- **False positives on uncommon traffic.** A signature
  matches but the bytes aren't actually the protocol.
  Mitigation: per-signature confirmation requires
  multiple discriminators (HTTP needs method + `HTTP/1.`,
  TLS needs content type + version + handshake type, SSH
  needs full `SSH-N.M-`). Strict by default.
- **Signature drift vs IANA registry**. Some signatures
  rely on well-known port hints when ambiguous (e.g.
  Postgres startup looks like raw bytes). For ambiguous
  signatures we return `NoMatch` rather than guess.

## Effort

| Surface | LoC | Hours |
|---------|-----|-------|
| 12 signature functions | ~300 | 4 |
| `registry()` + types | ~40 | 0.5 |
| Per-signature tests | ~280 | 3 |
| Splitting-invariance proptest | ~40 | 0.5 |
| Docs + CHANGELOG | ~60 | 1 |
| **Total** | **~720 LoC** | **~9 hours** |

(Higher than the postmortem's "~350 LoC" estimate because
the per-signature test coverage was underbudgeted there.)

## Provenance

Plan 112 (the analysis document):

> Plan 113 — `flowscope::detect::signatures` — small module
> with magic-byte recognizers for the eight or so
> protocols flowscope ships parsers for. Each signature is
> a pure function `&[u8] -> bool` over the first 4-32
> bytes of payload.

Industry refs in the postmortem's research:
- nDPI uses Aho-Corasick magic patterns as the cheap stage.
- Wireshark's heuristic dissector contract is `bool` on a
  prefix.
- Zeek's DPD signature set is BPF-like; ours is just
  function pointers.

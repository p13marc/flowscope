# Plan 97 — TLS modernization (JA4 + handshake aggregator)

## Summary

Two TLS additions for 0.9 that share design surface and ship
together:

1. **JA4 client fingerprint** behind a `ja4` Cargo feature,
   mirroring the existing `ja3` shape. JA4 is the modern
   successor to JA3 (FoxIO, 2023): cipher-suite shuffling
   resilient, GREASE-aware, human-readable
   (`t13d1516h2_8daaf6152771_b186095e22b6` instead of an opaque
   MD5 hex). It is the format most modern traffic-classification
   stacks have moved to.
2. **`TlsHandshakeParser`** — a `SessionParser` that aggregates
   ClientHello + ServerHello + Certificate + Alert (plus
   resumption markers) into a single `TlsHandshake` message per
   TCP flow. This is the high-level shape users want when
   they're logging TLS handshakes — one event per handshake
   outcome, carrying SNI, ALPN, version, cipher, server cert
   fingerprint, JA3, JA4, and the outcome. Today they hand-roll
   correlation across three `TlsParser` messages.

Bundling these saves duplicated provenance, duplicated migration
text in the CHANGELOG, and an arbitrary "which goes first"
landing decision — JA4 is populated on the `TlsClientHello` by
the low-level `TlsParser`; `TlsHandshakeParser` reads it back
into the aggregated event. The shapes share the spec references
and the same `tls` / `ja4` feature surface.

`TlsParser` (the per-message `SessionParser` shipped today)
stays — it is for consumers wanting per-message granularity
(e.g. ClientHello-to-ServerHello round-trip timing). The new
aggregator is **additive** and stands alongside.

## Status

**Ready to implement.** Targets 0.9.0. Independent of the
breaking-change plans (94 / 96); ships as additive surface.

## Prerequisites

- Existing `tls` feature, `TlsParser`, `TlsClientHello`,
  `TlsServerHello`, `TlsAlert` types.
- Existing `ja3` feature for the JA4 shape to mirror.
- Plan 96 (error unification) — `TlsHandshakeParser` returns
  `flowscope::Error` for parse failures.

## Out of scope

- **JA4S** (server fingerprint from ServerHello). Separate
  feature; add later if a consumer asks. ServerHello fields are
  smaller, so the design is straightforward, but it's distinct
  from client fingerprinting.
- **JA4H** (HTTP fingerprint from request headers). Lives in
  the `http` module; tracked separately.
- **JA4L / JA4T / JA4X / JA4SSH** (latency / TCP / X.509 / SSH
  variants). Each is a separate fingerprinting domain.
- **A `fingerprint` umbrella feature.** Defer until users ask
  to bundle `ja3` + `ja4`.
- **Fingerprint comparison / similarity helpers.** The
  fingerprint string is the durable output.
- **Mid-session renegotiation event chaining.** `TlsHandshakeParser`
  emits one `TlsHandshake` per handshake; if a flow
  renegotiates, a second one fires. Linking the two is out of
  scope.
- **Server certificate validation.** The aggregator extracts a
  SHA-256 leaf-cert fingerprint and a SAN list (DNS + IP), but
  does not validate the chain. flowscope is passive-observation
  only.
- **TLS 1.3 0-RTT classification.** Already in `plans/INDEX.md`
  deferred list; separate plan.
- **Decryption.** Same.

---

## Surface 1 — JA4 client fingerprint

### Feature wiring

```toml
[features]
ja4 = ["tls", "dep:sha2"]

[dependencies]
sha2 = { version = "0.10", optional = true }
```

JA4 needs SHA-256 (FoxIO spec, truncated to 12 hex chars).
`sha2` is widely used and small; `md-5` is already pulled in for
JA3, so adding `sha2` is symmetric.

### Module

```rust
// src/tls/ja4.rs

/// Compute the JA4 client fingerprint from a `TlsClientHello`.
///
/// Format (FoxIO v1):
///
///   `t13d1516h2_8daaf6152771_b186095e22b6`
///
/// breaking down as:
///
///   `[t|q][version][SNI?d:i][cipher_count][ext_count][alpn] _ [hash_a] _ [hash_b]`
///
/// `t`=TCP, `q`=QUIC; `version` is the negotiated TLS version
/// (the highest supported_versions value); `hash_a` is the
/// truncated SHA-256 of the sorted cipher list (GREASE removed);
/// `hash_b` is the truncated SHA-256 of the sorted extension +
/// sig-algs list.
pub fn ja4(ch: &TlsClientHello) -> String;

/// Lower-level: return the three parts separately.
pub fn ja4_parts(ch: &TlsClientHello) -> Ja4Parts;

#[non_exhaustive]
pub struct Ja4Parts {
    pub header: String,
    pub cipher_hash: String,
    pub extension_hash: String,
}

impl std::fmt::Display for Ja4Parts {
    // Formats as the underscore-joined fingerprint.
}
```

### `TlsClientHello` field

```rust
#[non_exhaustive]
pub struct TlsClientHello {
    // … existing fields …

    /// JA3 fingerprint (MD5 hex). Set when the `ja3` feature is on.
    pub ja3_fingerprint: Option<String>,
    /// JA3 canonical string (pre-MD5). Set when `ja3` is on.
    pub ja3_string: Option<String>,

    /// JA4 fingerprint (FoxIO format). Set when `ja4` is on.
    pub ja4_fingerprint: Option<String>,
}
```

`TlsParser` populates `ja4_fingerprint` on every parsed
ClientHello when the `ja4` feature is enabled. With the feature
off the field is always `None`.

---

## Surface 2 — `TlsHandshakeParser`

A `SessionParser` that emits one `TlsHandshake` event per
handshake outcome on a TCP flow. Internally it wraps the
existing `TlsParser` state engine and accumulates state across
the message stream.

### API

```rust
// src/tls/handshake.rs

pub struct TlsHandshakeParser {
    config: TlsConfig,
}

impl TlsHandshakeParser {
    pub fn new() -> Self;
    pub fn with_config(config: TlsConfig) -> Self;
}

impl SessionParser for TlsHandshakeParser {
    type Message = TlsHandshake;
    const PARSER_KIND: &'static str = "tls-handshake";
    // standard SessionParser methods
}
```

### Event

```rust
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub struct TlsHandshake {
    /// SNI from the ClientHello.
    pub sni: Option<String>,

    /// ALPN offered by the client.
    pub client_alpn: Vec<String>,

    /// ALPN selected by the server.
    pub server_alpn: Option<String>,

    /// JA3 client fingerprint (MD5 hex). Set when `ja3` is on.
    pub ja3: Option<String>,

    /// JA4 client fingerprint (FoxIO format). Set when `ja4` is on.
    pub ja4: Option<String>,

    /// Negotiated TLS version (from ServerHello supported_versions).
    pub version: Option<TlsVersion>,

    /// Server's selected cipher suite.
    pub cipher_suite: Option<u16>,

    /// Server cert SHA-256 fingerprint (leaf only).
    pub server_cert_fingerprint: Option<String>,

    /// Server cert SAN list (DNS + IP entries, parsed but not validated).
    pub server_cert_sans: Vec<String>,

    /// True iff the client sent PSK / session-ticket extensions
    /// (resumption attempted).
    pub resumption_attempted: bool,

    /// True iff the server's response indicates the resumption
    /// succeeded (no HelloRetryRequest + matching session
    /// echo).
    pub resumption_succeeded: bool,

    /// Final outcome.
    pub outcome: HandshakeOutcome,
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum HandshakeOutcome {
    Completed,
    AlertedByServer { description: u8 },
    AlertedByClient { description: u8 },
    Truncated,
}
```

`ja4` on `TlsHandshake` reads from the upstream `TlsClientHello`'s
pre-computed `ja4_fingerprint`. No re-computation; the
aggregator is the stitching layer, not a second parser.

---

## Files

```
src/tls/ja4.rs                # new — JA4 fingerprint computation
src/tls/handshake.rs          # new — TlsHandshakeParser + state machine
src/tls/types.rs              # extend TlsClientHello with ja4_fingerprint;
                              # add TlsHandshake + HandshakeOutcome
src/tls/parser.rs             # populate ja4_fingerprint under cfg(ja4)
src/tls/mod.rs                # re-export ja4 module + TlsHandshakeParser
src/lib.rs                    # no change (re-export via tls module)
Cargo.toml                    # `ja4` feature + sha2 dep

tests/tls_ja4.rs              # FoxIO reference vectors + properties
tests/tls_handshake.rs        # five-fixture aggregator coverage

docs/concepts.md              # "JA3 vs JA4" paragraph
docs/recipes.md               # "Logging TLS handshakes" + JA4 lookup recipes
CHANGELOG.md                  # entry under 0.9.0
```

## Implementation steps

### JA4 (surface 1)

1. Add `sha2 = "0.10"` as an optional dep gated by the `ja4`
   feature in `Cargo.toml`. Add the feature row.
2. Create `src/tls/ja4.rs` implementing the FoxIO v1 spec.
   Handle GREASE skipping carefully; the reference vectors in
   `tests/tls_ja4.rs` are the unit tests.
3. Add `#[cfg(feature = "ja4")]` re-export in `src/tls/mod.rs`.
4. Extend `TlsClientHello` with the `ja4_fingerprint:
   Option<String>` field (additive; `#[non_exhaustive]` covers
   it).
5. In `src/tls/parser.rs`, populate `ja4_fingerprint` when the
   `ja4` feature is on, gated by `#[cfg(feature = "ja4")]`.
6. Add `ja4` to the `full` feature alias.

### Handshake aggregator (surface 2)

7. Add `src/tls/handshake.rs` with `TlsHandshakeParser`. Reuse
   the existing `TlsParser` as the per-message state engine
   (compose, don't replicate). The aggregator owns:
   - A `TlsParser` per side (the existing parser's normal mode
     of operation).
   - A `HandshakeAccumulator` state machine that consumes
     `TlsParser`'s emitted messages.
8. Implement the accumulator state machine:
   - On `ClientHello`: populate SNI, ALPN-offered, JA3, JA4,
     `resumption_attempted`; set state =
     `AwaitingServerHello`.
   - On `ServerHello`: populate version, cipher, ALPN-selected,
     `resumption_succeeded`; set state =
     `AwaitingCertificate` (TLS 1.2) or `Completed` (TLS 1.3
     abbreviated).
   - On `Certificate`: parse the leaf cert's SHA-256 + SAN list
     (use `tls-parser`'s SAN extraction; cert bytes' SHA-256
     via the existing `sha2` dep).
   - On `Alert`: set `outcome = AlertedBy{Server|Client}`, emit,
     reset state.
   - On `on_close`: if state ≠ Completed, emit with
     `outcome = Truncated`.
9. Wire `TlsHandshakeParser` into `src/tls/mod.rs`.

### Shared

10. Add `tests/tls_handshake.rs` (see Tests) — at least one
    fixture per outcome.
11. Add `tests/tls_ja4.rs` with at least the two FoxIO reference
    vectors (Chrome / Firefox).
12. `docs/concepts.md`: short "JA3 vs JA4" paragraph + when each
    is the right fingerprint.
13. `docs/recipes.md`: "Logging TLS handshakes" recipe (uses
    `TlsHandshakeParser` + `Pipeline`) + JA4 lookup snippet.
14. CHANGELOG entry under 0.9.0.

## Tests

`tests/tls_ja4.rs`:

- **Reference vectors.** Two known-vector ClientHellos (Chrome
  100, Firefox 100) from the FoxIO published reference; assert
  the JA4 string matches byte-for-byte.
- **Shuffle invariance (proptest).** Identical ClientHellos
  with their extension order shuffled in the wire bytes (JA4's
  whole point) yield the same fingerprint.
- **SNI flag (proptest).** ClientHello with no SNI yields `i`
  in the header; with SNI yields `d`.
- **Feature-off smoke.** `cargo build --features tls
  --no-default-features` without `ja4` — `ja4_fingerprint`
  field exists but is always `None`.

`tests/tls_handshake.rs`:

- **TLS 1.2 completed.** `tls12_handshake.pcap` (existing
  fixture) → `TlsHandshake { outcome: Completed, version:
  Tls12, … }`.
- **TLS 1.3 completed.** Existing TLS 1.3 fixture → expected
  shape (note the ServerHello + EncryptedExtensions
  interleaving).
- **TLS 1.3 resumption.** New synthetic fixture →
  `resumption_attempted && resumption_succeeded`.
- **Fatal alert.** New fixture: server fires fatal alert
  before completion → `outcome: AlertedByServer { description:
  N }`.
- **Truncated.** Flow ends mid-handshake → `outcome: Truncated`.
- **JA3 / JA4 propagation.** When features on, `ja3` /
  `ja4` populated on `TlsHandshake`; when off, `None`.

## Acceptance criteria

- `cargo test --features ja4` — JA4 tests green.
- `cargo test --features tls,ja3,ja4` — handshake tests green.
- `cargo test --features full` — full feature suite green
  (includes `ja4`).
- `cargo build --features tls --no-default-features` builds
  without `ja4`; `ja4_fingerprint` is always `None`.
- Two FoxIO JA4 reference vectors produce the expected
  fingerprint byte-for-byte.
- All five handshake-aggregator scenarios pass.
- `docs/concepts.md` JA3-vs-JA4 paragraph ships.
- `docs/recipes.md` "Logging TLS handshakes" recipe ships;
  copy-pasteable.
- CHANGELOG 0.9.0 entry under "TLS modernization" calls out
  both surfaces.

## Risks

- **JA4 spec drift.** FoxIO has iterated the algorithm
  post-publication. Pin to v1 explicitly; document the version
  in the module docstring. v2 → follow-up plan.
- **GREASE handling correctness.** JA4 explicitly skips GREASE
  cipher / extension entries. Wrong implementation silently
  produces wrong fingerprints. The reference-vector tests are
  the safety net; verify visually that the GREASE removal is
  applied to both cipher and extension lists.
- **Resumption detection complexity.** TLS 1.2 abbreviated
  handshake vs TLS 1.3 PSK resumption vs HelloRetryRequest
  follow-up are all easy to mis-detect. Mitigation: the
  fixture set covers the four observable shapes (full-1.2,
  full-1.3, 1.3-resumed, HRR-then-full); the parser is
  deterministic enough to property-test against shuffled
  segment boundaries.
- **Certificate SAN parsing.** Rely on `tls-parser` for the
  Certificate message; SAN extraction is straightforward when
  the cert is well-formed. Malformed certs →
  `server_cert_sans` is empty, no error.
- **SHA-256 performance.** SHA-256 per ClientHello — first
  measurement on a sample pcap shows < 5 µs per call on a
  2024-era laptop; acceptable.

## Effort

| Surface | LoC | Hours |
|---------|-----|-------|
| `src/tls/ja4.rs` | ~140 | 3 |
| `TlsClientHello` field + parser populating + Cargo wiring | ~40 | 1 |
| `src/tls/handshake.rs` (parser + accumulator state machine) | ~220 | 5 |
| `TlsHandshake` + `HandshakeOutcome` types | ~40 | 0.5 |
| Tests (JA4 + handshake) | ~190 | 5 |
| Docs + CHANGELOG | — | 2 |
| **Total** | **~630 LoC** | **~16 hours** |

## Provenance

JA4 and the handshake aggregator are both `plans/INDEX.md`
deferred items lifted into the 0.9 cycle:

> **JA4 fingerprint** — modern JA3 successor (weighted-by-
> popularity ordering). Ship behind a `ja4` feature mirroring
> the existing `ja3` feature; revisit when a consumer asks.

> **`TlsHandshake` aggregator parser** — more design surface
> than initially scoped (resumption / abbreviated handshake /
> failed handshake / renegotiation). Manual ClientHello +
> ServerHello correlation pattern is documented in
> `docs/SESSION_GUIDE.md`. Revisit if a second consumer asks.

The "consumer asks" gate is relaxed for 0.9 because:

1. The plan-93 audit identifies "TLS fingerprint" advice
   defaulting to JA3 as a stale recommendation. 0.9 ships JA4
   so 1.0 can recommend it.
2. The aggregator's deferred design surface (resumption /
   abbreviated / failed / truncated) is well-understood now
   that the deferred-list rationale has had a release cycle
   to clarify it.
3. JA4 + the aggregator share design surface (the aggregator
   exposes JA4 in its event). Co-shipping avoids the awkward
   "0.9 ships JA4, 0.10 ships the aggregator that
   re-exposes it" cadence.

References:

- FoxIO JA4 specification: https://github.com/FoxIO-LLC/ja4
- "JA4+ Network Fingerprinting" technical paper (2023).

# Plan 86 — `PARSER_KIND` constants per parser module

## Summary

Every netring rule that matches on a `parser_kind` slug today writes a
string literal:

```rust
let SessionEvent::Application { parser_kind: "dns-udp", .. } = evt
else { return };
```

The slugs are stable per parser (`"http/1"`, `"dns-udp"`, `"dns-tcp"`,
`"tls"`, `"icmp"`) but they're string-literals at the match site — typos
pass the type checker silently. The slugs also live in two places today:
the `parser_kind()` impl body and the consumer's match-arm literal.

This plan exposes the slugs as public `&'static str` constants per
parser module, makes each parser's `parser_kind()` impl forward to the
constant (single source of truth), and ships a top-level
`flowscope::parser_kinds` re-export module so consumers don't need to
remember which submodule owns which slug.

## Status

Not started.

## Prerequisites

- Plan 72 (`parser_kind` field on `SessionEvent::Application`) —
  shipped in 0.5.0.

## Out of scope

- Forcing consumers to use the constants. The literals continue to
  work; constants are a convenience.
- Validating slug content (lowercase, ASCII, snake-case-or-slash).
  The convention is already documented in `SessionParser::parser_kind`
  rustdoc; enforcement stays advisory.
- Per-instance dynamic kinds. Parsers that need a dynamic kind keep
  using their `Message` type for routing.

## Files

- `src/http/mod.rs` — `pub const PARSER_KIND: &str = "http/1";`
- `src/dns/mod.rs` — `pub const PARSER_KIND_UDP: &str = "dns-udp";` +
  `pub const PARSER_KIND_TCP: &str = "dns-tcp";`
- `src/tls/mod.rs` — `pub const PARSER_KIND: &str = "tls";`
- `src/icmp/mod.rs` — `pub const PARSER_KIND: &str = "icmp";`
- `src/http/session.rs` — `parser_kind()` returns `http::PARSER_KIND`.
- `src/dns/datagram.rs`, `src/dns/session.rs` — return the
  corresponding consts.
- `src/tls/session.rs` — returns `tls::PARSER_KIND`.
- `src/icmp/datagram.rs` — returns `icmp::PARSER_KIND`.
- `src/lib.rs` — new `pub mod parser_kinds` re-exporting all five
  constants under one path for ergonomics.
- `tests/parser_kind_constants.rs` — round-trip: each parser's
  `parser_kind()` equals the module constant; the umbrella re-export
  exposes the same values.
- `docs/OBSERVABILITY.md` — note the constants in the "Routing by
  parser_kind" section.
- `CHANGELOG.md` — `### Added` entry.

## API

```rust
// src/http/mod.rs
/// `&'static str` slug returned by `HttpParser::parser_kind()`. Use
/// at match sites in place of a string literal so typos fail to
/// resolve instead of silently miss.
pub const PARSER_KIND: &str = "http/1";

// src/dns/mod.rs
pub const PARSER_KIND_UDP: &str = "dns-udp";
pub const PARSER_KIND_TCP: &str = "dns-tcp";

// src/tls/mod.rs
pub const PARSER_KIND: &str = "tls";

// src/icmp/mod.rs
pub const PARSER_KIND: &str = "icmp";

// src/lib.rs
/// Re-export of every shipped parser-kind constant under one
/// path. Match against `flowscope::parser_kinds::HTTP` instead of
/// remembering `flowscope::http::PARSER_KIND`.
pub mod parser_kinds {
    #[cfg(feature = "http")]
    pub use crate::http::PARSER_KIND as HTTP;
    #[cfg(feature = "dns")]
    pub use crate::dns::PARSER_KIND_UDP as DNS_UDP;
    #[cfg(feature = "dns")]
    pub use crate::dns::PARSER_KIND_TCP as DNS_TCP;
    #[cfg(feature = "tls")]
    pub use crate::tls::PARSER_KIND as TLS;
    #[cfg(feature = "icmp")]
    pub use crate::icmp::PARSER_KIND as ICMP;
}
```

Use site:

```rust
use flowscope::parser_kinds;

match evt {
    SessionEvent::Application { parser_kind, message, .. }
        if parser_kind == parser_kinds::DNS_UDP => /* DNS lookup logic */,
    SessionEvent::Application { parser_kind, message, .. }
        if parser_kind == parser_kinds::HTTP => /* HTTP request logic */,
    _ => {}
}
```

Note the `if parser_kind == CONST` form instead of `parser_kind: CONST`
— Rust match patterns don't bind `&str` against a `const &str` without
named-constant pattern syntax (`#[allow(non_upper_case_globals)]`).
Documented in the test file.

## Implementation steps

1. Add the constants to each parser module's `mod.rs` (or `lib`-level
   for icmp which already has `mod.rs`).
2. Update each `SessionParser::parser_kind` /
   `DatagramParser::parser_kind` impl to return the const.
3. Add `pub mod parser_kinds` to `src/lib.rs` with the cfg-gated
   re-exports.
4. Tests in `tests/parser_kind_constants.rs`:
   - Each parser's `parser_kind()` returns the module constant.
   - The umbrella `parser_kinds::*` matches the per-module values.
   - Compile-time guard: shadowing match (`const HTTP: &str = …;
     match s { HTTP => …, … }`) compiles (proves the constants are
     usable in match patterns when the consumer wants pattern-binding
     semantics).
5. `OBSERVABILITY.md` subsection: routing by `parser_kind` using the
   new constants.
6. CHANGELOG entry under `### Added`.

## Tests

`tests/parser_kind_constants.rs`:

- `http_constant_matches_parser_kind` — instantiate `HttpParser`,
  assert `parser.parser_kind() == http::PARSER_KIND`.
- Mirror for DNS-UDP / DNS-TCP / TLS / ICMP.
- `parser_kinds_umbrella_matches_modules` — assert
  `parser_kinds::HTTP == http::PARSER_KIND` etc.
- `constants_work_in_match_patterns` — defines a local const-shadow
  and matches against it (proves the public consts are pattern-usable).

## Acceptance criteria

- `cargo test --all-features --test parser_kind_constants` clean.
- Every shipped parser's `parser_kind()` returns the corresponding
  module constant. Asserted by the round-trip test.
- `flowscope::parser_kinds::*` exposes one constant per shipped
  parser kind, cfg-gated by the parser's feature.
- `cargo doc --all-features --no-deps` documents the constants
  cleanly.

## Risks

- **Slug rename pressure.** A future plan that changes a slug (e.g.
  `http/1` → `http/1.1`) becomes a breaking change because the
  constant is public. This is the *intended* behaviour — locking the
  vocabulary is the point. Documented in the rustdoc.
- **Test brittleness for absent features.** The umbrella module is
  cfg-gated; tests must mirror the same gates. The test file uses
  `#[cfg(feature = "...")]` per case.

## Effort

~50 LoC across five touched files + ~80 LoC tests + 10 lines
OBSERVABILITY.md. **~1 hour.**

## Provenance

Round-3 wishlist item B1 in
[`docs/feedback-2026-06-06-netring-wishlist.md`](../docs/feedback-2026-06-06-netring-wishlist.md).
The umbrella `parser_kinds` module is the "bonus" the author mentioned.

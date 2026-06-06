# Plan 96 — Error type unification

## Summary

Replace the five module-local `Error` enums (`http::Error`,
`tls::Error`, `dns::Error`, `pcap::Error`, `icmp::Error`) with a
single `flowscope::Error` carrying an `ErrorKind` discriminant and
an optional `source` chain to the upstream parser library's error
type. Consumers match on `ErrorKind`; `source()` walks via the
standard `std::error::Error::source()` trait.

This is a public-API break — every consumer that names
`flowscope::http::Error` (etc.) updates — but it's the simplest
shape that gives flowscope a `Result<T, flowscope::Error>` story
across module boundaries.

## Status

**Ready to implement.** Targets 0.9.0. Sibling to plan 94
(high-level API) — plan 94's `Pipeline::run_pcap` returns this
unified error, so 96 lands first in the cycle.

## Prerequisites

None within flowscope. Lands independently of plan 94, but
should land first so 94's surface can consume the unified
error type.

## Out of scope

- Adding `Error` variants for cases that don't exist today (e.g.
  "tracker eviction"). The migration is byte-equivalent on
  variants; new error cases come from new features.
- Removing the upstream errors. The error chain captures them
  via `source()` so a `Display` walk still surfaces the
  underlying `httparse::Error` / `simple_dns::Error` / etc.
- A typed error code (`ErrorCode = u32`) for FFI / serialisation.
  Out of scope; revisit if a consumer asks.
- `anyhow::Error` interop helpers (`From<Error> for
  anyhow::Error` etc.). Already free via the
  `std::error::Error` impl; no flowscope-side code needed.

---

## Files

```
src/error.rs               # new module
src/lib.rs                 # re-export Error + ErrorKind
src/http/parser.rs         # drop local Error, return flowscope::Error
src/tls/parser.rs          # drop local Error
src/dns/mod.rs             # drop local Error
src/pcap/source.rs         # drop local Error
src/icmp/parser.rs         # drop local Error
docs/concepts.md           # one-paragraph "error model" section
CHANGELOG.md               # migration recipe
tests/error_chain.rs       # new — source-chain coverage
```

## API

### Core

```rust
// src/error.rs

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
#[error("{kind}: {source:?}")]
pub struct Error {
    pub kind: ErrorKind,
    #[source]
    pub source: Option<Box<dyn std::error::Error + Send + Sync + 'static>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// Module that produced the error.
    pub module: Module,
    /// Stable short identifier for matching in user code.
    pub code: ErrorCode,
    /// Human-readable diagnostic. Format may change between releases.
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Module {
    Http,
    Tls,
    Dns,
    Icmp,
    Pcap,
    Reassembler,
    Tracker,
    Pipeline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    Parse,
    BufferOverflow,
    Io,
    Unsupported,
    Truncated,
    Eof,
    Other,
}
```

### Construction helpers (crate-internal)

```rust
impl Error {
    pub(crate) fn parse(module: Module, msg: impl Into<String>) -> Self;
    pub(crate) fn parse_with(module: Module, msg: impl Into<String>, source: impl std::error::Error + Send + Sync + 'static) -> Self;
    pub(crate) fn buffer_overflow(module: Module, cap: usize) -> Self;
    pub(crate) fn io(module: Module, e: std::io::Error) -> Self;
}
```

### Inspection (public)

```rust
impl Error {
    pub fn kind(&self) -> &ErrorKind;
    pub fn module(&self) -> Module;
    pub fn code(&self) -> ErrorCode;
    pub fn is_recoverable(&self) -> bool;  // true for BufferOverflow/Parse, false for Io
}
```

### Result alias

```rust
pub type Result<T> = std::result::Result<T, Error>;
```

Used internally and re-exported.

---

## Migration mapping

| 0.8 type                  | 0.9 replacement                                  |
|---------------------------|--------------------------------------------------|
| `http::Error::Parse(s)`   | `Error::kind().code = Parse`, `module = Http`    |
| `http::Error::BufferOverflow(n)` | `code = BufferOverflow`, `module = Http`  |
| `tls::Error::*`           | same shape; `module = Tls`                       |
| `dns::Error::Parse(s)`    | `module = Dns`, `code = Parse`                   |
| `pcap::Error::Io(e)`      | `module = Pcap`, `code = Io`, `source = Some(e)` |
| `pcap::Error::Format(s)`  | `module = Pcap`, `code = Parse`                  |
| `icmp::Error::Parse(s)`   | `module = Icmp`, `code = Parse`                  |

The CHANGELOG carries this table with a `match` rewrite recipe:

```rust
// 0.8
match err {
    flowscope::http::Error::Parse(s) => log::warn!("http parse: {s}"),
    flowscope::http::Error::BufferOverflow(n) => log::error!("http overflow at {n}"),
}

// 0.9
match (err.module(), err.code()) {
    (Module::Http, ErrorCode::Parse) => log::warn!("http parse: {}", err),
    (Module::Http, ErrorCode::BufferOverflow) => log::error!("http overflow: {}", err),
    _ => {}
}
```

---

## Implementation steps

1. Create `src/error.rs` with `Error`, `ErrorKind`, `Module`,
   `ErrorCode`, and the `Result<T>` alias.
2. Re-export from `src/lib.rs`.
3. For each module with a local `Error`:
   - Delete the local `enum Error`.
   - Replace returns with `flowscope::Error::parse(Module::Foo,
     …)` / `::parse_with(…, upstream_err)` / etc.
   - Where the upstream parser library returns its own error
     (`httparse::Error`, `tls_parser::Err`, `simple_dns::SimpleDnsError`,
     `pcap_file::PcapError`), wrap it via `.parse_with(module, msg,
     upstream)` so the `source()` chain is preserved.
4. Sweep `Result<…, http::Error>` etc. signatures to
   `Result<…, flowscope::Error>` (using the new alias).
5. Sweep tests and examples.
6. Add `tests/error_chain.rs` covering:
   - `source()` returns the underlying upstream error when one
     exists.
   - `Display` walks the chain (`err.to_string()` includes the
     upstream message).
   - `Error: Send + Sync + 'static` (compile-only assertion).
7. Update `docs/concepts.md` with a short "Error model" section.
8. CHANGELOG.md 0.9.0 entry with the mapping table.

## Tests

`tests/error_chain.rs`:

- HTTP parse failure → `err.module() == Http`, `err.code() ==
  Parse`, `err.source()` is `None` (httparse errors are not
  wrapped today — the existing string interpolation drops them).
  Decision: in this plan, *do* wrap httparse errors via
  `parse_with`, so the test asserts `source().is_some()`.
- DNS parse failure → likewise, simple_dns error preserved via
  `source()`.
- pcap I/O failure → `code() == Io`, `source()` chain reaches an
  `io::Error`.
- `Error: Send + Sync + 'static`.

## Acceptance criteria

- Zero remaining `pub enum Error` in module files; all parser /
  source modules return `flowscope::Result<T>`.
- `tests/error_chain.rs` passes.
- All existing tests sweep.
- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- `docs/concepts.md` gains the error-model section.
- CHANGELOG mapping table ships.

## Risks

- **Loss of variant-specific data.** Today, `http::Error::Parse(String)`
  carries a string and `BufferOverflow(usize)` carries the cap.
  The unified type carries `message: String` + `code` only;
  numeric details get folded into the message. Acceptable —
  consumers needing structured numeric extraction can parse the
  message or downcast `source()` to a known upstream type.
- **`Display` format change.** Today `http::Error::BufferOverflow(8192)`
  formats as `"buffer overflow: message exceeded max_buffer=8192"`.
  After the migration, `Error.message` is set to the same string
  but `Display` formats `"{kind}: {source:?}"` — a different
  shape. Decision: change the format to `"{module}: {code}: {message}"`
  for human readability and document the format-stability
  policy in `docs/concepts.md` (format strings are not stable
  across releases).
- **Boxing cost.** `Box<dyn std::error::Error + Send + Sync +
  'static>` is one allocation per error. Errors are not hot in
  any current profile; acceptable.

## Effort

- `src/error.rs`: ~140 LoC, ~3 hours.
- Per-module migration (5 modules): ~100 LoC delta, ~3 hours.
- Tests: ~60 LoC, ~1.5 hours.
- Doc + CHANGELOG: ~1.5 hours.
- **Total:** ~10 hours, ~300 LoC (net delta ~0 — code added in
  `src/error.rs` is offset by deletions across the parser
  modules).

## Provenance

Plan 93's audit identifies the five-Error-enum split as a real
ergonomic loss for consumers writing cross-module pipelines.
`thiserror::Error` does most of the work; the migration cost
is mechanical.

References for the chosen shape:

- `std::io::Error` (kind + Box<dyn Error>) — the closest
  precedent in std.
- `reqwest::Error` (kind + chained source) — a widely-used
  third-party precedent.
- `serde_json::Error` (single struct, error code accessor,
  source chain) — drop-in pattern for parser-library errors.

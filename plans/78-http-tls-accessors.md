# Plan 78 — HTTP / TLS convenience accessors

## Summary

Every HTTP monitor netring writes against 0.6 ends up with the
same four-line dance to read a header:

```rust
let host = req.headers.iter()
    .find(|(k, _)| k.eq_ignore_ascii_case("host"))
    .and_then(|(_, v)| std::str::from_utf8(v).ok())
    .unwrap_or("?");
```

For the modal queries — `Host`, `User-Agent`, `Cookie` on
requests; `Content-Type`, `Content-Length`, `Set-Cookie` on
responses — that boilerplate is repeated everywhere.

This plan ships the focused accessor set as inherent methods on
`HttpRequest` and `HttpResponse`, plus a generic
case-insensitive `header(name)` lookup. The scope is *exactly*
the six accessors the netring author identified plus the
generic; the line is drawn there to avoid never-ending header
sprawl.

For TLS, `TlsClientHello::sni` is already exposed as a direct
field. We add a `sni() -> Option<&str>` convenience method for
symmetry with the HTTP shape — one-liner, zero risk.

## Status

Not started.

## Prerequisites

- Plan 31 (TLS / HTTP `SessionParser`-shaped APIs) — shipped in
  0.4.0. `HttpRequest` / `HttpResponse` / `TlsClientHello`
  shapes are stable.

## Out of scope

- `Accept-Encoding`, `Referer`, `Authorization`, `Content-Encoding`,
  `Transfer-Encoding`, etc. The generic `header(name)` covers
  them. We resist adding more inherent accessors until a second
  consumer asks for one specifically.
- Body decoding. Header values only; bodies stay on `Vec<u8>` /
  `Bytes` accessors elsewhere.
- Cookie parsing into `(name, value)` pairs. `cookie()` returns
  the raw header value; a downstream cookie crate (e.g.
  `cookie`) handles parsing. Adding cookie parsing pulls in
  a dep we don't want for a one-line accessor.
- HTTP/2 / HTTP/3 — flowscope is HTTP/1.1 today; nothing
  changes here.
- TLS extension lookup by type (`extension(0x0000)` style). The
  ClientHello already exposes named fields (`sni`, `alpn`,
  `supported_versions`, etc.); the per-extension raw lookup is
  not a per-monitor friction point yet.

## Files

- `src/http/types.rs` — accessors on `HttpRequest`,
  `HttpResponse`; shared `header_lookup` helper.
- `src/tls/types.rs` — `TlsClientHello::sni()` convenience
  method.
- `tests/http_accessors.rs` — new file; covers each accessor +
  edge cases (missing, non-UTF-8, case variation, multiple
  Set-Cookie).
- `tests/tls_parser.rs` — extend with `sni()` round-trip.
- `docs/SESSION_GUIDE.md` — short subsection in the HTTP
  example pointing at the accessors.
- `CHANGELOG.md` — `### Added` entry.

## API

```rust
// src/http/types.rs

impl HttpRequest {
    /// `Host:` header value as UTF-8.
    /// `None` if the header is absent or its value isn't
    /// valid UTF-8.
    pub fn host(&self) -> Option<&str> {
        self.header_str("host")
    }

    /// `User-Agent:` header value as UTF-8.
    pub fn user_agent(&self) -> Option<&str> {
        self.header_str("user-agent")
    }

    /// `Cookie:` header value as UTF-8 (raw — no parsing into
    /// `name=value` pairs). For parsing, route through a
    /// downstream cookie crate.
    pub fn cookie(&self) -> Option<&str> {
        self.header_str("cookie")
    }

    /// Case-insensitive lookup of an arbitrary header.
    /// Returns the first match's raw value (HTTP/1.x allows
    /// duplicates; this surfaces the first one observed).
    /// For multi-valued headers, use [`headers_all`](Self::headers_all).
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        header_lookup(&self.headers, name).next()
    }

    /// All matches for an arbitrary header (case-insensitive).
    /// Useful for `Cookie:` / `Set-Cookie:` cases where
    /// multi-value semantics matter.
    pub fn headers_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> + 'a {
        header_lookup(&self.headers, name)
    }

    fn header_str(&self, name: &str) -> Option<&str> {
        self.header(name)
            .and_then(|v| std::str::from_utf8(v).ok())
    }
}

impl HttpResponse {
    /// `Content-Type:` header value as UTF-8.
    pub fn content_type(&self) -> Option<&str> {
        self.header_str("content-type")
    }

    /// `Content-Length:` header value parsed as `u64`.
    /// `None` if absent, non-UTF-8, or non-numeric.
    pub fn content_length(&self) -> Option<u64> {
        self.header_str("content-length")
            .and_then(|v| v.trim().parse().ok())
    }

    /// All `Set-Cookie:` header values as UTF-8. HTTP/1.x
    /// servers can set multiple cookies via repeated headers;
    /// this exposes them in observation order.
    pub fn set_cookie(&self) -> impl Iterator<Item = &str> + '_ {
        self.headers_all("set-cookie")
            .filter_map(|v| std::str::from_utf8(v).ok())
    }

    /// Mirror of [`HttpRequest::header`].
    pub fn header(&self, name: &str) -> Option<&[u8]> {
        header_lookup(&self.headers, name).next()
    }

    /// Mirror of [`HttpRequest::headers_all`].
    pub fn headers_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [u8]> + 'a {
        header_lookup(&self.headers, name)
    }

    fn header_str(&self, name: &str) -> Option<&str> {
        self.header(name)
            .and_then(|v| std::str::from_utf8(v).ok())
    }
}

/// Case-insensitive header iterator. Pulled out so request and
/// response share the same lookup logic.
fn header_lookup<'a>(
    headers: &'a [(String, Vec<u8>)],
    name: &'a str,
) -> impl Iterator<Item = &'a [u8]> + 'a {
    headers
        .iter()
        .filter(move |(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_slice())
}
```

```rust
// src/tls/types.rs

impl TlsClientHello {
    /// `Server Name Indication` extension value, if present.
    /// Convenience accessor — the same value is exposed as the
    /// public `sni: Option<String>` field.
    pub fn sni(&self) -> Option<&str> {
        self.sni.as_deref()
    }
}
```

## Implementation steps

1. **Add `header_lookup` helper** in `src/http/types.rs`. Two-line
   iterator; case-insensitive via `eq_ignore_ascii_case`.
2. **Add request accessors** (`host`, `user_agent`, `cookie`,
   `header`, `headers_all`).
3. **Add response accessors** (`content_type`, `content_length`,
   `set_cookie`, `header`, `headers_all`).
4. **Add `TlsClientHello::sni()`** — one-liner forwarding to the
   existing field.
5. **Tests** — see Tests section.
6. **SESSION_GUIDE.md** — short subsection under the HTTP
   example showing the canonical use:
   ```rust,ignore
   if let SessionEvent::Application { message: HttpMessage::Request(req), .. } = ev {
       println!("{} {} (host={}, ua={})",
           req.method, req.path,
           req.host().unwrap_or("?"),
           req.user_agent().unwrap_or("?"));
   }
   ```
7. **CHANGELOG entry under `### Added`**:
   ```
   - **HTTP and TLS convenience accessors** (plan 78). On
     `HttpRequest`: `host()`, `user_agent()`, `cookie()`. On
     `HttpResponse`: `content_type()`, `content_length()` (parsed
     `u64`), `set_cookie()` (iterator). Both gain `header(name)`
     and `headers_all(name)` for arbitrary case-insensitive
     lookup. `TlsClientHello::sni()` mirrors the `sni` field for
     accessor symmetry. Saves the `find().and_then(str::from_utf8)`
     dance in every L7 example.
   ```

## Tests

`tests/http_accessors.rs`:
- **Per-accessor happy path** — construct a fixture
  `HttpRequest` / `HttpResponse` with the expected header,
  assert the accessor returns it.
- **Case insensitivity** — `Host` / `HOST` / `host` all match
  `request.host()`.
- **Absent header** returns `None` (not `Some("")`).
- **Non-UTF-8 value** returns `None` from the `_str()` flavours
  but the raw bytes from `header(name)`.
- **Multiple `Set-Cookie`** — fixture with three; iterator
  yields all three in order.
- **`Content-Length` parsing** — valid u64, whitespace-padded,
  negative, oversized, non-numeric. Each behaves per the
  contract (None for everything that isn't a clean parse).
- **`Content-Length: 18446744073709551616`** (u64::MAX + 1) →
  `None` (parse overflow).

Extension to `tests/tls_parser.rs`:
- `sni_method_matches_field` — fixture with SNI extension;
  assert `hello.sni()` equals `hello.sni.as_deref()`.

## Acceptance criteria

- All accessors compile and pass `cargo test --all-features --test
  http_accessors`.
- `clippy --all-features --all-targets -- -D warnings` clean.
- Feature-matrix CI green (the accessors are `http`-feature
  gated; ensure `--features http` build alone is enough).
- `cargo doc --all-features --no-deps` warns nothing.
- SESSION_GUIDE shows the canonical example using the new
  accessors.

## Risks

- **Scope creep pressure post-merge.** Someone will ask for
  `accept_encoding()`, `referer()`, etc. The plan-of-record
  documents the line: those use the generic `header()`. Hold
  firm; revisit only if two independent consumers ask for the
  same one.
- **`headers_all` lifetime overhead.** Each call returns a fresh
  borrow-tied iterator. Cheap; no allocation. Documented in the
  rustdoc.
- **HTTP/1.x header folding (RFC 7230 §3.2.4).** Folded headers
  are deprecated but in-the-wild. The parser already collapses
  them; the accessors see one logical value per header occurrence.
  No new exposure here.

## Effort

~80 LoC source (~15 accessors + 1 helper) + ~150 LoC tests + 20
lines SESSION_GUIDE. ~4 hours including the CHANGELOG and
docs/example refresh.

## Provenance

Round-2 feedback item F3 in
[`docs/feedback-2026-05-29-netring-round2.md`](../docs/feedback-2026-05-29-netring-round2.md).
The accessor set is bounded to the four the author identified
(`host`, `user_agent`, `cookie`, `set_cookie` plus
`content_type` / `content_length`) plus the generic `header(name)`;
scope-creep pressure (`accept_encoding`, `referer`, …) is
documented as out-of-scope here and in the plan-of-record.

`TlsClientHello::sni()` was added for symmetry with the HTTP
accessors; the existing public `sni: Option<String>` field
already meets the author's underlying ask, so the new method is
a strict convenience.

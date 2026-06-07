# Plan 110 — rustdoc landing pages + convenience-accessor index

## Summary

Rewrite the module-level rustdoc for `flowscope::http`,
`flowscope::tls`, `flowscope::dns`, `flowscope::icmp` to lead
with a "Convenience accessors" table — every accessor method
shipped on the public types, listed once at the top of the
module page.

Theme 4 from
[`plans/100-examples-postmortem.md`](./100-examples-postmortem.md):
I reinvented `HttpRequest::host()` and `user_agent()` in four
examples because they didn't surface in module-level
rustdoc. Same likely applies to TLS / DNS accessors.

## Status

**Ready to implement.** Targets 0.10.0. Pure docs work — no
code changes.

## Prerequisites

None.

## Out of scope

- **Cookbook-style examples in rustdoc.** Those go in
  `docs/recipes.md` (already shipped). Module-level rustdoc
  should be a *navigation aid*, not a tutorial.
- **Generated convenience-accessor index** (procedural).
  Maintained by hand for now; if list drift becomes a
  problem, switch to a `build.rs`-generated table.
- **Changes to existing accessor method names or signatures.**
  Pure docs polish only.

---

## What changes per module

### `flowscope::http`

Add an `## Convenience accessors` section to
`src/http/mod.rs` rustdoc. Table-shape:

```rust
//! ## Convenience accessors
//!
//! ### `HttpRequest`
//!
//! | Method | Returns | Equivalent | Notes |
//! |--------|---------|------------|-------|
//! | `host()` | `Option<&str>` | first `Host` header value | RFC 7230 §5.4 — required on HTTP/1.1 |
//! | `user_agent()` | `Option<&str>` | first `User-Agent` header | |
//! | `cookie()` | `Option<&str>` | first `Cookie` header | concatenated by `;` per RFC 6265 |
//! | `content_type()` | `Option<&str>` | `Content-Type` header | |
//! | `content_length()` | `Option<u64>` | parsed `Content-Length` | |
//! | `referer()` | `Option<&str>` | `Referer` header | new in 0.10 |
//! | `accept()` | `Option<&str>` | `Accept` header | new in 0.10 |
//! | `header(name)` | `impl Iterator<…>` | all matching headers | case-insensitive |
//!
//! ### `HttpResponse`
//!
//! | Method | Returns | Equivalent | Notes |
//! |--------|---------|------------|-------|
//! | `status_class()` | `Option<u8>` | `status / 100` | new in 0.10 |
//! | `is_success()` | `bool` | `2xx` | new in 0.10 |
//! | `is_redirect()` | `bool` | `3xx` | new in 0.10 |
//! | `is_client_error()` | `bool` | `4xx` | new in 0.10 |
//! | `is_server_error()` | `bool` | `5xx` | new in 0.10 |
//! | `content_type()` | `Option<&str>` | `Content-Type` header | |
//! | `set_cookie()` | `impl Iterator<…>` | all `Set-Cookie` headers | |
//! | `header(name)` | `impl Iterator<…>` | all matching headers | |
```

### `flowscope::tls`

Inventory of accessors on `TlsClientHello`, `TlsServerHello`,
`TlsAlert`. Many already exist (e.g. `TlsClientHello::sni()`);
catalog them.

### `flowscope::dns`

Inventory of accessors on `DnsQuery`, `DnsResponse`,
`DnsMessage`, `DnsRdata`.

### `flowscope::icmp`

Inventory of accessors on `IcmpMessage`.

---

## Implementation steps

1. **`src/http/mod.rs`**: insert the "Convenience accessors"
   table after the existing `# Scope` section.
2. **Add the new HttpResponse helpers** in `src/http/types.rs`:
   `status_class()`, `is_success()`, `is_redirect()`,
   `is_client_error()`, `is_server_error()`. These are
   one-liners.
3. **Add HttpRequest::referer() and accept() accessors** (one-
   liners following the existing `host()` pattern).
4. **`src/tls/mod.rs`**: same — inventory + table.
5. **`src/dns/mod.rs`**: same.
6. **`src/icmp/mod.rs`**: same.
7. **`docs/concepts.md`**: brief paragraph in the L7 section
   pointing at the module-level rustdoc.
8. **CHANGELOG entry** under 0.10.0 "Added".

## Acceptance criteria

- Four module-level rustdoc landing pages updated.
- 7 new accessor methods land
  (HttpRequest::referer, accept;
   HttpResponse::status_class, is_success, is_redirect,
   is_client_error, is_server_error).
- `cargo doc --all-features --no-deps` zero warnings.
- CHANGELOG entry.

## Risks

- **List drift.** Adding new accessors but forgetting the
  table. Mitigation: a `cargo check` against a small docs-CI
  script that asserts every `pub fn` returning `Option<&str>`
  or `bool` on the documented types appears in the table.
  Optional; defer if maintainer thinks it's overkill.

## Effort

| Surface | LoC | Hours |
|---------|-----|-------|
| HTTP module rustdoc + 7 new accessors | ~140 | 3 |
| TLS module rustdoc | ~60 | 1 |
| DNS module rustdoc | ~60 | 1 |
| ICMP module rustdoc | ~30 | 0.5 |
| Tests for the new accessors (5 status helpers + 2 headers) | ~80 | 1 |
| CHANGELOG | ~30 | 0.5 |
| **Total** | **~400 LoC** | **~7 hours** |

## Provenance

Postmortem theme 4:

> Several examples reinvented accessors that already exist
> (`HttpRequest::host`, `user_agent`, `content_type`, …). The
> existence of `host()` is mentioned in the README but not in
> rustdoc-visible cross-references.
>
> Two fixes:
> 1. **Curated accessor index in module-level rustdoc.**
>    `flowscope::http`'s top-level docs should list every
>    shipped convenience accessor in a `# Convenience
>    accessors` heading. Same for `flowscope::tls`,
>    `flowscope::dns`.

# Plan 110 — DX polish: rustdoc landing pages + quick wins

## Summary

A single "polish pass" plan combining:

- **Sub-plan A** — rustdoc landing pages with curated
  convenience-accessor tables for `flowscope::http`,
  `flowscope::tls`, `flowscope::dns`, `flowscope::icmp`
  (+ 7 new HTTP accessor helpers).
- **Sub-plan B** — quick-win helper sweep across
  `Timestamp` / `FlowStats` / `EndReason` / `LayerKind` /
  `Layer` / `LayerStack` / `KeyIndexed`.

Both are theme-1 / theme-3 / theme-4 work from
[`plans/100-examples-postmortem.md`](./100-examples-postmortem.md)
— the small things every example-writer reinvented because
the helpers didn't exist or weren't discoverable.

| Sub-PR | Scope | LoC | Hours |
|--------|-------|-----|-------|
| A | rustdoc landing pages + 7 HTTP accessors | ~400 | ~7 |
| B | quick-win helper sweep | ~535 | ~10 |
| **Total** | | **~935** | **~17** |

## Status

**Ready to implement.** Targets 0.10.0. Ship sub-plan B
first — it lands the helpers the other 0.10 plans lean on.

## Prerequisites

None. Both sub-plans are independent additive sweeps.

## Out of scope

- Anything large enough to deserve its own plan.
- Changes to existing method names or behaviour.
- New features beyond the ergonomic additions listed.
- Cookbook-style examples in rustdoc — those go in
  `docs/recipes.md`. Module-level rustdoc is a *navigation
  aid*, not a tutorial.

---

## Sub-plan A — rustdoc landing pages + 7 new HTTP accessors

### What changes per module

For each of `flowscope::http`, `flowscope::tls`,
`flowscope::dns`, `flowscope::icmp`: add a
`## Convenience accessors` section to the module-level
rustdoc with a table cataloging every public accessor on
the module's main types. The 0.9 examples-writing pass
revealed that consumers reinvented `HttpRequest::host()` /
`user_agent()` in four examples because they didn't
surface in module-level rustdoc.

### `flowscope::http` rustdoc shape

```rust
//! ## Convenience accessors
//!
//! ### `HttpRequest`
//!
//! | Method | Returns | Equivalent | Notes |
//! |--------|---------|------------|-------|
//! | `host()` | `Option<&str>` | first `Host` header | RFC 7230 §5.4 |
//! | `user_agent()` | `Option<&str>` | first `User-Agent` | |
//! | `cookie()` | `Option<&str>` | first `Cookie` | concatenated per RFC 6265 |
//! | `content_type()` | `Option<&str>` | `Content-Type` | |
//! | `content_length()` | `Option<u64>` | parsed `Content-Length` | |
//! | `referer()` | `Option<&str>` | `Referer` | **new in 0.10** |
//! | `accept()` | `Option<&str>` | `Accept` | **new in 0.10** |
//! | `header(name)` | `impl Iterator<…>` | all matching | case-insensitive |
//!
//! ### `HttpResponse`
//!
//! | Method | Returns | Equivalent | Notes |
//! |--------|---------|------------|-------|
//! | `status_class()` | `Option<u8>` | `status / 100` | **new in 0.10** |
//! | `is_success()` | `bool` | `2xx` | **new in 0.10** |
//! | `is_redirect()` | `bool` | `3xx` | **new in 0.10** |
//! | `is_client_error()` | `bool` | `4xx` | **new in 0.10** |
//! | `is_server_error()` | `bool` | `5xx` | **new in 0.10** |
//! | `content_type()` | `Option<&str>` | `Content-Type` | |
//! | `set_cookie()` | `impl Iterator<…>` | all `Set-Cookie` | |
//! | `header(name)` | `impl Iterator<…>` | all matching | |
```

### Other modules

- `flowscope::tls` — inventory `TlsClientHello`,
  `TlsServerHello`, `TlsAlert`. Many accessors already
  exist (e.g. `TlsClientHello::sni()`); catalog them.
- `flowscope::dns` — `DnsQuery`, `DnsResponse`,
  `DnsMessage`, `DnsRdata`.
- `flowscope::icmp` — `IcmpMessage`.

### 7 new HTTP accessor methods

| Type | Method | Returns | Implementation |
|------|--------|---------|----------------|
| `HttpRequest` | `referer()` | `Option<&str>` | first `Referer` header |
| `HttpRequest` | `accept()` | `Option<&str>` | first `Accept` header |
| `HttpResponse` | `status_class()` | `Option<u8>` | `status / 100` |
| `HttpResponse` | `is_success()` | `bool` | `status_class() == Some(2)` |
| `HttpResponse` | `is_redirect()` | `bool` | `status_class() == Some(3)` |
| `HttpResponse` | `is_client_error()` | `bool` | `status_class() == Some(4)` |
| `HttpResponse` | `is_server_error()` | `bool` | `status_class() == Some(5)` |

One-liners following the existing `host()` pattern.

### Files (sub-A)

```
src/http/mod.rs     # rustdoc landing page (convenience-accessor table)
src/http/types.rs   # 7 new accessor methods + tests
src/tls/mod.rs      # rustdoc landing page
src/dns/mod.rs      # rustdoc landing page
src/icmp/mod.rs     # rustdoc landing page
docs/concepts.md    # brief paragraph in L7 section pointing at module rustdoc
CHANGELOG.md        # 0.10 entry under "Added"
```

### Implementation steps (sub-A)

1. **`src/http/mod.rs`** — insert "Convenience accessors"
   table after the existing `# Scope` section.
2. **Add the 5 new HttpResponse helpers** in
   `src/http/types.rs` — `status_class()`, `is_success()`,
   `is_redirect()`, `is_client_error()`, `is_server_error()`.
3. **Add HttpRequest::referer() and accept()** — one-liners.
4. **`src/tls/mod.rs`** — inventory + table.
5. **`src/dns/mod.rs`** — same.
6. **`src/icmp/mod.rs`** — same.
7. **`docs/concepts.md`** — pointer paragraph.
8. CHANGELOG entry.

---

## Sub-plan B — quick-win helper sweep

### `Timestamp` (`src/timestamp.rs`)

```rust
impl Timestamp {
    /// Convert to Unix epoch seconds. Inverse of `from_unix_f64`.
    pub fn to_unix_f64(self) -> f64 { /* … */ }

    /// Construct from Unix epoch seconds.
    pub fn from_unix_f64(secs: f64) -> Self { /* … */ }

    /// Signed delta in seconds: `self - other`.
    pub fn relative_to(self, other: Timestamp) -> f64 { /* … */ }

    pub fn from_system_time(ts: SystemTime) -> Self;
}

impl Display for Timestamp {
    /// `"{sec}.{nsec:09}"` — Zeek-compatible timestamp shape.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result;
}
```

### `FlowStats` (`src/event.rs`)

```rust
impl FlowStats {
    pub fn total_bytes(&self) -> u64;
    pub fn total_packets(&self) -> u64;
    pub fn total_retransmits(&self) -> u64;
    pub fn retransmit_rate(&self) -> f64;
    pub fn duration(&self) -> Duration;
    pub fn duration_secs(&self) -> f64;
}
```

### `EndReason` (`src/event.rs`)

```rust
impl EndReason {
    /// Snake-case identifier matching the 0.8 serde wire format.
    /// E.g. `"fin"` / `"rst"` / `"idle_timeout"` /
    /// `"buffer_overflow"` / `"parse_error"`.
    pub fn as_str(&self) -> &'static str;
}

impl Display for EndReason {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result;
}
```

(Note: `as_zeek_state()` lands with plan 101, not here.)

### `LayerKind` (`src/layers/kind.rs`)

```rust
impl LayerKind {
    pub const fn is_l2(self) -> bool;
    pub const fn is_l3(self) -> bool;
    pub const fn is_l4(self) -> bool;
    pub const fn is_tunnel(self) -> bool;
}
```

### `Layer<'_>` (`src/layers/mod.rs`)

```rust
impl<'a> Display for Layer<'a> {
    /// One-line summary like `ipv4 src=10.0.0.1 dst=10.0.0.2 proto=6`.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result;
}
```

### `LayerStack` (`src/layers/fast.rs`)

```rust
impl LayerStack {
    pub fn depth(&self) -> usize;
    pub fn iter_kinds(&self) -> impl Iterator<Item = LayerKind> + '_;
}
```

### `KeyIndexed` (`src/correlate/indexed.rs`)

```rust
impl<K, V> KeyIndexed<K, V> where K: Hash + Eq {
    /// Read-only get — does NOT bump LRU recency.
    pub fn peek(&self, k: &K, now: Timestamp) -> Option<&V>;
}
```

### Files (sub-B)

```
src/timestamp.rs           # 4 new methods + Display
src/event.rs               # 6 FlowStats helpers + EndReason::as_str + Display
src/layers/kind.rs         # 4 const predicates
src/layers/mod.rs          # Display for Layer
src/layers/fast.rs         # depth + iter_kinds for LayerStack
src/correlate/indexed.rs   # peek
tests/quick_wins.rs        # NEW — coverage for every addition
examples/*                 # opportunistic use of the new helpers
CHANGELOG.md               # 0.10 entry
```

### Implementation steps (sub-B)

1. `Timestamp` additions + Display + doctests.
2. `FlowStats` rollup helpers + doctests.
3. `EndReason::as_str()` + `Display`.
4. `LayerKind` predicates.
5. `Layer<'_>::Display`.
6. `LayerStack::depth()` + `iter_kinds()`.
7. `KeyIndexed::peek()`.
8. `tests/quick_wins.rs` — one section per addition.
9. CHANGELOG entry.

### Tests (sub-B)

```rust
- Timestamp::to_unix_f64 / from_unix_f64 round-trip.
- FlowStats helpers match manual computation.
- EndReason::as_str returns snake-case strings.
- LayerKind::is_l2 / l3 / l4 / tunnel match layer_number groups.
- Layer<'_>::Display produces a one-line summary
  containing layer-specific fields.
- LayerStack::depth matches the populated slot count on
  Eth+IPv4+TCP.
- KeyIndexed::peek does NOT mutate LRU.
```

---

## Acceptance criteria (whole plan)

- Four module-level rustdoc landing pages updated (sub-A).
- 7 new HTTP accessor methods land (sub-A).
- ~20 new public methods land across modules (sub-B).
- ~12 quick-win test scenarios pass (sub-B).
- `cargo doc --all-features --no-deps` zero warnings.
- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- CHANGELOG entries under 0.10.0 "Added" — one per sub-PR.

## Risks

- **List drift in rustdoc tables** (sub-A) — adding new
  accessors but forgetting the table. Mitigation: optional
  docs-CI script asserting every `pub fn` returning
  `Option<&str>` or `bool` on the documented types appears
  in the table. Defer if maintainer thinks it's overkill.
- **Adding many small methods at once** (sub-B) — no
  individual risk; the sweep nature means the PR is easy
  to review by section.

## Effort

| Sub-PR / section | LoC | Hours |
|------------------|-----|-------|
| A — HTTP rustdoc + 7 accessors | ~140 | 3 |
| A — TLS rustdoc | ~60 | 1 |
| A — DNS rustdoc | ~60 | 1 |
| A — ICMP rustdoc | ~30 | 0.5 |
| A — Tests for new accessors | ~80 | 1 |
| A — CHANGELOG | ~30 | 0.5 |
| B — Timestamp additions + Display | ~50 | 1 |
| B — FlowStats helpers | ~80 | 1.5 |
| B — EndReason::as_str + Display | ~30 | 0.5 |
| B — LayerKind predicates | ~25 | 0.5 |
| B — Layer<'_>::Display | ~80 | 2 |
| B — LayerStack helpers | ~40 | 1 |
| B — KeyIndexed::peek | ~20 | 0.5 |
| B — Tests | ~180 | 3 |
| B — Docs + CHANGELOG | ~30 | 0.5 |
| **Total** | **~935** | **~17** |

## Provenance

Postmortem theme 4 (sub-A):

> Several examples reinvented accessors that already exist
> (`HttpRequest::host`, `user_agent`, `content_type`, …). The
> existence of `host()` is mentioned in the README but not in
> rustdoc-visible cross-references.

Postmortem themes 1 + 3 (sub-B) — the "quick wins" sprint:

> `Timestamp::to_unix_f64()` / `from_unix_f64()` / `Display`;
> `FlowStats::total_bytes()` / `total_packets()` /
> `total_retransmits()` / `retransmit_rate()` / `duration()`;
> `EndReason::as_str()` (snake_case);
> `KeyIndexed::peek()` (non-mutating);
> `Layer<'_>::Display` impl;
> `HttpResponse::status_class()` / `is_2xx()` / `is_5xx()`
> (these are in sub-A's accessor-helper batch since they live
> in `http`);
> `LayerStack::depth()` / `iter_kinds()`;
> `LayerKind::is_l2 / l3 / l4 / tunnel()` predicates.

`EndReason::as_zeek_state()` lives with plan 101 (emit
module) alongside the Zeek `conn.log` writer.

Consolidated from prior individual plans 110 (rustdoc
landing pages) and 111 (quick wins) — both are pure
additive DX polish and ship cleanly as one cohesive plan
with two PR boundaries.

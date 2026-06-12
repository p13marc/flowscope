# Plan 172 — `LabelTable` completeness + `override_count` removal

**Cycle:** 0.14.0 pre-release polish
**Priority:** P1 (config-reload gate + small breaking cleanup)
**Effort:** ~quarter day
**Status:** drafted (consolidation review added breaking cleanup)

## Motivation

Plan 165 shipped `LabelTable` with the write-only operations
(`set` / `extend`) plus `inherit_builtin` / `override_count`.
For hot-reload config without restarting the monitor, the
inverse (`remove`) and the membership/introspection helpers
(`contains` / `is_empty` / `len`) are missing.

Plus a small cleanup: `override_count` was shipped in plan
165, but `len()` is the standard Rust collection idiom.
Having both is API bloat. Since this is pre-1.0 and `override_count`
has only been on `master` for hours (not yet on crates.io),
the cleanest move is to **remove** `override_count` in favor
of `len`.

## Proposed shape

```rust
impl LabelTable {
    /// Remove the override for `(proto, port)`. Returns the
    /// previously-set label if any. After removal, `lookup`
    /// falls back to the built-in table if `inherit_builtin()
    /// == true`, otherwise returns `None`.
    pub fn remove(&mut self, proto: L4Proto, port: u16) -> Option<&'static str>;

    /// Check whether this table has an override for
    /// `(proto, port)`. Does NOT consult the built-in
    /// fallback — use [`Self::lookup`] for that.
    pub fn contains(&self, proto: L4Proto, port: u16) -> bool;

    /// Number of overrides currently registered. Independent
    /// of `inherit_builtin`.
    pub fn len(&self) -> usize;

    /// `true` if no overrides have been registered.
    /// Independent of `inherit_builtin` — a `LabelTable::new()`
    /// is "empty of overrides" but still resolves built-in
    /// labels via [`Self::lookup`].
    pub fn is_empty(&self) -> bool;
}
```

## Breaking change

**Remove `LabelTable::override_count`** — replaced by `len()`.
Justification:

- Pre-1.0; method shipped on master ~hours ago in commit
  `5f5c88d` and is not yet on crates.io.
- `len()` matches the standard Rust collection idiom; no
  established consumer depends on the older name.
- Documented in the 0.14 migration doc § §12 (new).

If we discover an external consumer mid-cycle, add a
`#[deprecated(since="0.14.0", note="use len()")]` alias before
release. Default plan: clean removal.

## Files touched

- `src/well_known/mod.rs` — four new methods + delete
  `override_count`
- `docs/migration-0.13-to-0.14.md` — append §12 noting the
  `override_count` → `len()` rename

## Implementation notes

- `remove` — `self.overrides.remove(&(proto, port))`. Returns
  the removed `&'static str`.
- `contains` — `self.overrides.contains_key(&(proto, port))`.
- `len` — `self.overrides.len()`.
- `is_empty` — `self.overrides.is_empty()`.

## Tests

Extend `tests/well_known.rs`:
- `remove` returns previously-set label.
- `remove` of absent key returns None.
- After `remove`, `lookup` falls back to built-in iff
  `inherit_builtin`.
- `contains` true after `set`, false after `remove`.
- `is_empty` true on `new()`, false after `set`, true again
  after `remove` of the only entry.
- `len` agrees with manual count of `set` calls minus
  `remove`.

## Acceptance criteria

- All four methods compile + pass tests.
- `override_count` is gone from public API.
- Documentation cross-links `remove` ↔ `set`, `contains` ↔
  `lookup`.
- No grep hits for `override_count` in `src/` or `tests/`
  outside `migration-0.13-to-0.14.md`.

## Non-goals

- `LabelTable::merge(other)` — wait for a real consumer ask.
- `iter_overrides()` — `entries()` free function already
  covers built-ins; add an override-iterator later if needed.
- `Cow<'static, str>` labels — discussed; the `Box::leak`
  workaround is documented and sufficient for runtime-loaded
  labels. Changing to `Cow` would force every existing call
  site to disambiguate `Cow::Borrowed` vs `Cow::Owned`.

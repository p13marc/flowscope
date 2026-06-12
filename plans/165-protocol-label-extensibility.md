# Plan 165 — `protocol_label` extensibility via `LabelTable`

## Summary

Add a `LabelTable` value type to `flowscope::well_known` so
sites can layer custom port labels over the built-in table
without forking the source. Plus
`FiveTupleKey::protocol_label_with` / `app_label_with`
companions.

## Status

Not started. P1 for 0.14.

## Prerequisites

- Plan 163 (`FiveTupleKey::app_label`) — `app_label_with` is
  the parallel of `app_label` with a custom table.

## Out of scope

- **Runtime-string labels.** The table holds `&'static str`,
  matching the built-in table's contract. Runtime-loaded
  labels can use `Box::leak(string)` as a documented escape
  hatch. A `LabelTableOwned<Cow<'static, str>>` sibling is
  deferrable to 0.15 if a consumer asks.
- **Tracker integration** (`FlowTracker::with_label_table`).
  Defer; ship the value type first, see if integration is
  needed.

## Files

| Action | Path | Purpose |
|---|---|---|
| Modify | `src/well_known/mod.rs` | Add `LabelTable` struct + impl |
| Modify | `src/extract/five_tuple.rs` | Add `FiveTupleKey::protocol_label_with` + `app_label_with` |
| Modify | `src/prelude.rs` | Add `LabelTable` to the extractors-feature prelude (plan 167 sweep) |
| New | `tests/well_known_label_table.rs` | Override + inherit + standalone tests |

## API

```rust
// src/well_known/mod.rs
use std::collections::HashMap;
use crate::extractor::L4Proto;

/// Caller-supplied port label table that layers over (or
/// replaces) the built-in `well_known::protocol_label`
/// dispatch.
///
/// Use for site-custom services ("our internal gRPC on 8765",
/// "metrics scrape on 9101"). The built-in table covers ~80
/// standard ports; this struct lets you add the rest without
/// forking the source.
///
/// `Clone + Send + Sync`. Labels are `&'static str` — match
/// the built-in contract. For runtime-loaded labels use
/// `Box::leak(string)` to bridge.
///
/// Plan 165 (0.14).
#[derive(Clone, Default, Debug)]
pub struct LabelTable {
    overrides: HashMap<(L4Proto, u16), &'static str>,
    /// If `true` (default), unknown ports fall back to the
    /// built-in table. If `false`, only `overrides` are
    /// consulted.
    inherit_builtin: bool,
}

impl LabelTable {
    /// Empty table that inherits the built-in entries when
    /// no override matches.
    pub fn new() -> Self {
        Self {
            overrides: HashMap::new(),
            inherit_builtin: true,
        }
    }

    /// Empty table that does NOT inherit the built-in entries.
    /// Use when the site wants strict whitelist semantics.
    pub fn standalone() -> Self {
        Self {
            overrides: HashMap::new(),
            inherit_builtin: false,
        }
    }

    /// Add or override a label. `&'static str` keeps the
    /// zero-allocation contract.
    pub fn set(&mut self, proto: L4Proto, port: u16, label: &'static str) -> &mut Self {
        self.overrides.insert((proto, port), label);
        self
    }

    /// Bulk-set from an iterator. Convenient for config-
    /// driven table population.
    pub fn extend<I>(&mut self, entries: I) -> &mut Self
    where
        I: IntoIterator<Item = (L4Proto, u16, &'static str)>,
    {
        for (proto, port, label) in entries {
            self.overrides.insert((proto, port), label);
        }
        self
    }

    /// Lookup. Same shape as the existing free function
    /// [`protocol_label`].
    ///
    /// Algorithm:
    /// - Try the override map on `(proto, src_port)`.
    /// - Try the override map on `(proto, dst_port)`.
    /// - If `inherit_builtin`, fall back to the built-in
    ///   [`protocol_label`] function.
    /// - Else return `None`.
    pub fn lookup(&self, proto: L4Proto, src_port: u16, dst_port: u16) -> Option<&'static str> {
        if let Some(label) = self.overrides.get(&(proto, src_port)) {
            return Some(*label);
        }
        if let Some(label) = self.overrides.get(&(proto, dst_port)) {
            return Some(*label);
        }
        if self.inherit_builtin {
            protocol_label(proto, src_port, dst_port)
        } else {
            None
        }
    }
}
```

```rust
// src/extract/five_tuple.rs

impl FiveTupleKey {
    /// Companion to [`Self::protocol_label`] that consults a
    /// caller-provided `LabelTable` first.
    ///
    /// Plan 165 (0.14).
    pub fn protocol_label_with(
        &self,
        table: &crate::well_known::LabelTable,
    ) -> Option<&'static str> {
        table.lookup(self.proto, self.a.port(), self.b.port())
    }

    /// Always-Some variant — falls back to
    /// `proto.canonical_name()` when no label matches.
    ///
    /// Plan 165 (0.14).
    pub fn app_label_with(&self, table: &crate::well_known::LabelTable) -> &'static str {
        self.protocol_label_with(table)
            .unwrap_or_else(|| self.proto.canonical_name())
    }
}
```

## Implementation steps

1. Add `LabelTable` struct + impl to `src/well_known/mod.rs`.
2. Add `protocol_label_with` + `app_label_with` to
   `FiveTupleKey`.
3. Tests covering: override match, inherit-builtin fallback,
   standalone (no fallback), bulk extend, src+dst port lookup.
4. Add a usage recipe to `docs/recipes.md` — "Custom port
   labels for site-specific services".

## Tests

- `label_table_lookup_override_matches`.
- `label_table_lookup_falls_back_to_builtin_when_inherit_true`.
- `label_table_standalone_returns_none_when_no_override`.
- `label_table_extend_bulk_sets_entries`.
- `label_table_set_overrides_existing_label`.
- `label_table_lookup_tries_src_port_first_then_dst`.
- `protocol_label_with_uses_label_table`.
- `app_label_with_falls_back_to_canonical_name_when_unknown`.
- `label_table_is_send_and_sync` (compile-time assertion).

## Acceptance criteria

- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- A site can construct a `LabelTable`, populate it from a
  config file (with `Box::leak`), and pass it to
  `protocol_label_with` — fully functional override
  semantics.

## Risks

**R1: `&'static str` ergonomics for runtime configs.**
Consumers loading from YAML/JSON must leak strings. Mitigation:
documented escape hatch (`Box::leak`); `LabelTableOwned`
sibling planned for 0.15 if asked.

**R2: Override lookup order ambiguity.** When BOTH src and
dst ports match different overrides, the src-port match wins.
Mitigation: documented in rustdoc; pin via test.

## Effort

- LOC delta: +250 (struct + impl + accessors + tests + docs).
- Time estimate: **1 day**.

## Provenance

Wishlist plan 165. The `&'static str` (not `Cow`) decision —
see umbrella 169 §3.6.

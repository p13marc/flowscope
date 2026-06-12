# Plan 163 — `FiveTupleKey::app_label` + `L4Proto::canonical_name`

## Summary

Two sibling methods filling gaps in the existing label surface:

1. **`L4Proto::canonical_name() -> &'static str`** — always-
   Some, lowercase, snake-case-compatible. Sibling to the
   existing `L4Proto::proto_str()` (uppercase, EVE/Suricata
   schema-shaped). Use for metric labels and fallbacks.

2. **`FiveTupleKey::app_label() -> &'static str`** — always-
   Some companion to `protocol_label()`. Falls back to
   `proto.canonical_name()` when no port-based label matches.
   Lets bandwidth-by-app reports drop the `is_tcp: bool`
   workaround.

## Status

Not started. P1 for 0.14.

## Prerequisites

None.

## Out of scope

- **Replacing `proto_str()`.** The EVE-shaped uppercase
  labels are a Suricata schema requirement. The two
  methods serve different consumers.
- **Per-flow custom labels.** Plan 165 (`LabelTable`) covers
  site-custom extensibility.

## Files

| Action | Path | Purpose |
|---|---|---|
| Modify | `src/extractor.rs` | Add `L4Proto::canonical_name() -> &'static str` |
| Modify | `src/extract/five_tuple.rs` | Add `FiveTupleKey::app_label() -> &'static str` |
| Modify | `tests/well_known.rs` (or new) | Assert label correctness for every L4Proto variant + the protocol-label fallback contract |

## API

```rust
// src/extractor.rs

impl L4Proto {
    /// Stable lowercase short slug for any `L4Proto`. Always
    /// returns `Some`-equivalent (i.e., never empty, never
    /// `None`):
    ///
    /// - `Tcp` → `"tcp"`
    /// - `Udp` → `"udp"`
    /// - `Icmp` → `"icmp"`
    /// - `IcmpV6` → `"icmp6"`
    /// - `Sctp` → `"sctp"`
    /// - `Other(_)` → `"other"`
    ///
    /// Sibling to [`KeyFields::proto_str`] (uppercase,
    /// EVE/Suricata schema-shaped, `None` for `Other`). Use
    /// this method for metric labels, log slugs, and
    /// `app_label` fallbacks where lowercase + always-Some is
    /// the right contract.
    ///
    /// Plan 163 (0.14).
    pub fn canonical_name(&self) -> &'static str {
        match self {
            L4Proto::Tcp => "tcp",
            L4Proto::Udp => "udp",
            L4Proto::Icmp => "icmp",
            L4Proto::IcmpV6 => "icmp6",
            L4Proto::Sctp => "sctp",
            L4Proto::Other(_) => "other",
        }
    }
}
```

```rust
// src/extract/five_tuple.rs

impl FiveTupleKey {
    /// Always-Some companion to [`Self::protocol_label`].
    /// Falls back to [`L4Proto::canonical_name`] when no
    /// port-based label matches.
    ///
    /// Use for bandwidth-by-app and metric-label reports
    /// where "we don't know the app, but we know the L4" is
    /// the right fallback. Use `protocol_label()` directly
    /// when only an L7 label is acceptable.
    ///
    /// Examples:
    /// - `(TCP, 80, 33000)` → `"http"` (well-known port match)
    /// - `(TCP, 33000, 33001)` → `"tcp"` (L4 fallback)
    /// - `(SCTP, 100, 200)` → `"sctp"` (L4 fallback)
    ///
    /// Plan 163 (0.14).
    pub fn app_label(&self) -> &'static str {
        self.protocol_label()
            .unwrap_or_else(|| self.proto.canonical_name())
    }
}
```

## Implementation steps

1. Add `L4Proto::canonical_name` method.
2. Add `FiveTupleKey::app_label` method.
3. Tests covering both methods for every variant.
4. Rustdoc cross-link from `proto_str` ↔ `canonical_name` so
   consumers find the right one.

## Tests

- `canonical_name_returns_lowercase_slug_for_every_l4proto`.
- `canonical_name_returns_other_for_other_variant`.
- `app_label_returns_well_known_label_when_port_matches`.
- `app_label_falls_back_to_canonical_name_when_no_port_match`.
- `app_label_and_proto_str_are_distinct` (lock the contract
  that one is uppercase-Option, the other is lowercase-
  always-Some).

## Acceptance criteria

- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- netring 0.22's `bandwidth_by_app()` primitive can drop its
  `is_tcp: bool` workaround.

## Risks

**R1: Two-method confusion.** Consumers see `proto_str` +
`canonical_name` and don't know which to reach for.
Mitigation: rustdoc cross-link with a decision-table
explaining the trade-off.

## Effort

- LOC delta: +80 (methods + tests + rustdoc).
- Time estimate: **0.5 day**.

## Provenance

Wishlist plan 163.

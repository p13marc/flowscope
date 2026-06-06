# Plan 84 — `IcmpType::is_error()` + `error_inner()`

## Summary

ICMP error-class messages (`DestinationUnreachable`, `TimeExceeded`,
`Redirect`, `ParameterProblem` on v4; the v6 counterparts plus
`PacketTooBig`) all carry an `inner: Option<IcmpInner>` field — the
cross-protocol correlation primitive. The netring author hand-rolled a
40-LoC `extract_icmp_error()` helper to pattern-match every variant
and pull out `(label, &IcmpInner)`. Every consumer of `IcmpInner`-
bearing types ends up writing the same helper.

This plan ships three convenience methods on `IcmpType` and mirrors on
`IcmpMessage`:

```rust
impl IcmpType {
    pub fn is_error(&self) -> bool;
    pub fn error_inner(&self) -> Option<(&'static str, &IcmpInner)>;
    pub fn short_kind(&self) -> &'static str;
}
```

`short_kind` is a stable variant slug analogous to
`AnomalyKind::short_kind` (plan 88) — usable as a Prometheus label,
zero-allocation.

## Status

Not started.

## Prerequisites

- Plan 76 (`flowscope::icmp` module) — shipped in 0.7.0. The
  `IcmpType` enum + `IcmpInner` struct are stable.

## Out of scope

- Re-exposing inner fields like `code` on the helper API. The
  `error_inner()` returns `&IcmpInner`; the type-specific code lives
  in the parent variant. Consumers wanting the code keep matching.
- Adding helpers for the non-error variants (Echo, NS, NA). The
  consumer-friction signal is specifically about error-message
  extraction.
- A `is_request() / is_reply()` pair. Echo is the only request/reply
  variant; matching on it directly is fine.

## Files

- `src/icmp/types.rs` — three `impl` methods on `IcmpType`, three
  mirrors on `IcmpMessage`.
- `tests/icmp_parser.rs` — extend with focused helper tests.
- `examples/icmp_explained_drop.rs` — new example demonstrating the
  killer use case: "log every ICMP error referencing flow X" using
  `error_inner()`.
- `docs/SESSION_GUIDE.md` — short ICMP subsection cross-linking the
  example.
- `CHANGELOG.md` — `### Added` entry.

## API

```rust
// src/icmp/types.rs

impl IcmpType {
    /// `true` if this is an error-class type — one that carries an
    /// `inner: Option<IcmpInner>` field.
    ///
    /// Error class:
    /// - v4: `DestinationUnreachable`, `Redirect`, `TimeExceeded`,
    ///   `ParameterProblem`
    /// - v6: `DestinationUnreachable`, `PacketTooBig`, `TimeExceeded`,
    ///   `ParameterProblem`
    ///
    /// Non-error: `Echo*`, `Timestamp*`, `NeighborSolicitation`,
    /// `NeighborAdvertisement`, `Other`. These return `false`.
    pub fn is_error(&self) -> bool;

    /// Convenience: `(short label, &IcmpInner)` for any error variant
    /// whose `inner` was successfully parsed. `None` for non-error
    /// types or truncated embeds.
    ///
    /// The short label is the same slug `short_kind()` returns —
    /// e.g. `"dest_unreachable"` / `"time_exceeded"` /
    /// `"packet_too_big"` / `"parameter_problem"` / `"redirect"`.
    /// Stable, zero-allocation, suitable as a metric label.
    pub fn error_inner(&self) -> Option<(&'static str, &IcmpInner)>;

    /// Stable variant slug. Suitable as a metric label (zero
    /// allocation, `&'static str`).
    ///
    /// | Variant | Slug |
    /// |---------|------|
    /// | v4 EchoRequest / EchoReply / Redirect / TimeExceeded etc. | (see table in rustdoc body) |
    pub fn short_kind(&self) -> &'static str;
}

// Mirrors on IcmpMessage forward to self.ty.
impl IcmpMessage {
    pub fn is_error(&self) -> bool { self.ty.is_error() }
    pub fn error_inner(&self) -> Option<(&'static str, &IcmpInner)> { self.ty.error_inner() }
    pub fn short_kind(&self) -> &'static str { self.ty.short_kind() }
}
```

Slug vocabulary (locked from 0.8 forward; matches metric-label
convention):

| Variant | Slug |
|---------|------|
| `V4(EchoRequest)` | `"echo_request"` |
| `V4(EchoReply)` | `"echo_reply"` |
| `V4(DestinationUnreachable)` | `"dest_unreachable"` |
| `V4(Redirect)` | `"redirect"` |
| `V4(TimeExceeded)` | `"time_exceeded"` |
| `V4(ParameterProblem)` | `"parameter_problem"` |
| `V4(Timestamp)` | `"timestamp"` |
| `V4(TimestampReply)` | `"timestamp_reply"` |
| `V4(Other)` | `"other"` |
| `V6(DestinationUnreachable)` | `"dest_unreachable"` |
| `V6(PacketTooBig)` | `"packet_too_big"` |
| `V6(TimeExceeded)` | `"time_exceeded"` |
| `V6(ParameterProblem)` | `"parameter_problem"` |
| `V6(EchoRequest)` | `"echo_request"` |
| `V6(EchoReply)` | `"echo_reply"` |
| `V6(NeighborSolicitation)` | `"neighbor_solicitation"` |
| `V6(NeighborAdvertisement)` | `"neighbor_advertisement"` |
| `V6(Other)` | `"other"` |

Note: v4 and v6 variants with the same semantic meaning share the
same slug (`"echo_request"`, `"dest_unreachable"`). The `family` field
on `IcmpMessage` disambiguates when the consumer needs it.

## Implementation steps

1. Add the three methods to `IcmpType` in `src/icmp/types.rs`. One
   match per method; fully exhaustive against the existing variants.
2. Add the three forwarding mirrors on `IcmpMessage`.
3. Tests in `tests/icmp_parser.rs`:
   - `is_error_returns_true_for_error_variants` — exhaustive table.
   - `is_error_returns_false_for_non_error_variants` — same.
   - `error_inner_returns_label_and_inner_for_dest_unreach` —
     specific case with a TCP-inner fixture.
   - `error_inner_returns_none_for_truncated_inner` —
     unparseable-inner case.
   - `error_inner_returns_none_for_non_error` —
     `EchoRequest`-style.
   - `short_kind_table` — every variant returns its expected slug.
   - `short_kind_v4_v6_share_slug` — `V4(EchoRequest)` and
     `V6(EchoRequest)` both return `"echo_request"`.
4. New `examples/icmp_explained_drop.rs`:
   ```rust
   // For every ICMP error message in a pcap, log the (kind, original
   // src:port → dst:port) it references.
   for view in PcapFlowSource::open("trace.pcap")?.datagrams(FiveTuple::bidirectional(), IcmpParser::new()) {
       let Ok((_key, _side, msg)) = view else { continue };
       let Some((kind, inner)) = msg.error_inner() else { continue };
       println!(
           "icmp {kind}: {} → {} (proto={}, sport={:?}, dport={:?})",
           inner.src, inner.dst, inner.proto,
           inner.src_port, inner.dst_port,
       );
   }
   ```
5. SESSION_GUIDE: short ICMP correlation subsection linking the
   example.
6. CHANGELOG entry under `### Added`.

## Tests

See Implementation step 3. ~7 focused tests in `tests/icmp_parser.rs`.

## Acceptance criteria

- All three methods compile and pass `cargo test --features icmp
  --test icmp_parser`.
- `short_kind` returns `&'static str` (asserted via type ascription
  in test).
- `error_inner` returns `Some` for every error variant when the
  inner is parseable; `None` otherwise.
- `is_error` matches the variants whose definition includes
  `inner: Option<IcmpInner>`.
- The new `icmp_explained_drop.rs` example builds and runs against
  a test fixture.
- `cargo clippy --features icmp --all-targets -- -D warnings` clean.

## Risks

- **Adding a new `IcmpType` variant in the future.** The
  exhaustive-match tests catch the addition: a new variant fails to
  compile the match arm without explicit handling. This is the
  intended behaviour.
- **v4/v6 slug overlap.** Two variants share a slug for shared
  semantics; consumers needing to disambiguate use `msg.family`.
  Documented.

## Effort

~80 LoC source (three methods + mirrors + Cargo.toml example entry)
+ ~120 LoC tests + ~40 LoC example. **~4 hours.**

## Provenance

Round-3 wishlist item A2 in
[`docs/feedback-2026-06-06-netring-wishlist.md`](../docs/feedback-2026-06-06-netring-wishlist.md).
Author proposed `is_error` + `error_inner`; `short_kind` ships as a
bonus mirroring plan 88's `AnomalyKind::short_kind` and saving every
consumer the per-variant label match.

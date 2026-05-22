# Plan 60 — `l7` umbrella feature + intra-doc-link recipe note

## 1. Summary

Two trivial polish items bundled together for one PR:

1. **Cargo feature `l7 = ["dns", "tls", "http"]`** — bench harnesses
   and "give me all the L7" call sites stop having to enumerate
   three features.
2. **Intra-doc-link recipe in `CLAUDE.md`** — when a downstream
   crate re-exports flowscope types, the obvious
   `[FlowSessionDriver](flowscope::FlowSessionDriver)` style triggers
   `redundant_explicit_links` warnings; the right pattern is
   `[FlowSessionDriver]` (path resolution flows through the
   re-export). One paragraph saves every re-exporter the same
   5-minute debug session.

## 2. Status

Not started.

## 3. Prerequisites

None.

## 4. Out of scope

- New L7 protocol features (HTTP/2, gRPC, AMQP — separate plans).
- Reorganising the existing `dns` / `tls` / `http` features. They
  stay individually selectable; `l7` is purely additive sugar.
- A `metrics`-and-`tracing` umbrella. Observability features are
  intentionally separable per the CLAUDE.md "zero-cost when off"
  contract — bundling would obscure that.

## 5. Files

| File | Change |
|------|--------|
| `Cargo.toml` | Add `l7 = ["dns", "tls", "http"]` under `[features]`. |
| `README.md` | Update the feature table to note the umbrella. |
| `CLAUDE.md` | Add an "Intra-doc links for re-exporters" subsection under the existing module / convention prose. |
| `docs/SESSION_GUIDE.md` | Optionally mention `l7` once where features are discussed. |
| `CHANGELOG.md` | Additive entry. |

## 6. API

```toml
# Cargo.toml
[features]
# … existing features …
l7 = ["dns", "tls", "http"]
```

The existing `full` feature stays as the "everything including
observability and pcap":

```toml
full = ["http", "tls", "ja3", "dns", "pcap", "metrics", "tracing", "tracing-messages"]
```

`l7` is a strict subset (just the protocol parsers, no `ja3`, no
`pcap`, no observability). Users can layer:
`flowscope = { version = "0.5", features = ["l7", "pcap"] }`.

### Intra-doc-link recipe

To add to `CLAUDE.md` (or a small section in `docs/SESSION_GUIDE.md`
— pick one home; `CLAUDE.md` is fine since this is meta-guidance
for downstream maintainers):

> **Intra-doc links across re-exports.** If your crate re-exports
> `flowscope::FlowSessionDriver` and you want a doc-comment link to
> it, write `[FlowSessionDriver]` (path resolution flows through
> the re-export — rustdoc finds it). Writing
> `[FlowSessionDriver](flowscope::FlowSessionDriver)` triggers
> `redundant_explicit_links` because the link target equals what
> rustdoc would resolve `[FlowSessionDriver]` to anyway.

## 7. Implementation steps

1. **`Cargo.toml`** — one-line addition under `[features]`.
2. **`README.md`** — feature table: add `l7` row.
3. **`CLAUDE.md`** — add the intra-doc-link note. Place it near
   the "Pre-publish checklist" or the "Relationship to netring"
   section — a one-paragraph block with the example.
4. **Verify** `cargo build --no-default-features --features l7`
   builds (and pulls in `http`, `tls`, `dns`).
5. **CHANGELOG** — additive entry.

## 8. Tests

- **Build-time** verification under `cargo build --no-default-features
  --features l7` (manual check in CI matrix — plan 61 covers a
  proper feature-matrix CI step).
- **Doc** — the intra-doc-link recipe doesn't need a test (it's
  prose guidance).

## 9. Acceptance criteria

- `cargo build --no-default-features --features l7` builds and
  has `dns`, `tls`, `http` modules visible.
- `README.md` feature table mentions `l7`.
- `CLAUDE.md` carries the intra-doc-link recipe.
- `cargo build/test/clippy/fmt/doc --all-features` clean.

## 10. Risks

- None. Cargo features are namespaced; adding `l7` doesn't conflict
  with anything.

## 11. Effort

Trivial — ~10 minutes including the doc paragraph.

## 12. Provenance

[`docs/feedback-2026-05-22-netring.md`](../docs/feedback-2026-05-22-netring.md)
items **#11** (`l7`) and **#12** (intra-doc-link note).

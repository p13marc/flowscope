# Plan 35 — High-level pcap → L7 iterators

## 1. Summary

`PcapFlowSource::with_extractor()` yields a clean
`Iterator<Item = Result<FlowEvent>>` — the README quick-start's
one-expression bar. There is **no equivalent for the L7 layer**:
offline HTTP/TLS/DNS forces the user to hand-wire a driver, the
`views()` loop, and the final sweep, as all three L7 examples do.
This plan adds `PcapFlowSource::sessions(extractor, parser)` and
`PcapFlowSource::datagrams(extractor, parser)`, returning iterators
of `Result<SessionEvent<…>>` with the end-of-input flush folded in,
so an offline L7 program is again a single iterator expression.

## 2. Status

Not started.

## 3. Prerequisites

- **Plan 32** — the new `FlowSessionDriver::new(extractor, parser)`
  / `FlowDatagramDriver::new(extractor, parser)` by-value
  constructors and the relaxed `P: SessionParser + Clone` bound are
  what `sessions()` / `datagrams()` call.
- **Plan 33** — the iterators call `driver.finish()` to drain
  remaining flows at end-of-pcap.

Land 32 and 33 first.

## 4. Out of scope

- A callback-`Factory` pcap adapter (for `HttpFactory` etc.). The
  typed-parser path is the strategic one; the factory path already
  has the manual `FlowDriver` + `views()` recipe and an example.
  Revisit only on a real consumer ask.
- Async pcap streaming — that is netring's territory.
- Changing `with_extractor` — it stays as the `FlowEvent`-level
  entry point.

## 5. Files

| File | Change |
|------|--------|
| `src/pcap/source.rs` | Add `sessions()` / `datagrams()` methods + `SessionIter` / `DatagramIter` iterator types. |
| `src/lib.rs` | Re-export `SessionIter` / `DatagramIter` if `with_extractor`'s `EventIter` is re-exported (check; keep parity). |
| `README.md` | Add an offline-L7 one-liner next to the quick-start. |
| `docs/SESSION_GUIDE.md` | Add `PcapFlowSource::sessions` to the sync-driving section and the decision flow. |
| `examples/http_log.rs` | Optionally rewrite onto `sessions()` (see §10). |
| `CHANGELOG.md` | Additive-feature entry. |

## 6. API

```rust
impl<R: Read> PcapFlowSource<R> {
    // existing
    pub fn with_extractor<E: FlowExtractor>(self, extractor: E) -> EventIter<R, E>;

    /// One-step offline TCP-session pipeline: every packet flows
    /// through `extractor` + a per-flow `parser`, yielding typed L7
    /// `SessionEvent`s. The final flow flush is automatic — when the
    /// pcap is exhausted the iterator drains every still-open flow.
    #[cfg(all(feature = "session", feature = "reassembler"))]
    pub fn sessions<E, P>(self, extractor: E, parser: P) -> SessionIter<R, E, P>
    where
        E: FlowExtractor,
        E::Key: std::hash::Hash + Eq + Clone + Send + 'static,
        P: SessionParser + Clone + Send + 'static;

    /// One-step offline UDP-datagram pipeline. Mirror of
    /// [`Self::sessions`] for [`DatagramParser`].
    #[cfg(all(feature = "session", feature = "reassembler", feature = "extractors"))]
    pub fn datagrams<E, P>(self, extractor: E, parser: P) -> DatagramIter<R, E, P>
    where
        E: FlowExtractor,
        E::Key: std::hash::Hash + Eq + Clone + Send + 'static,
        P: DatagramParser + Clone + Send + 'static;
}

/// Iterator yielding `Result<SessionEvent<E::Key, P::Message>, Error>`.
#[cfg(all(feature = "session", feature = "reassembler"))]
pub struct SessionIter<R: Read, E, P> { /* ViewIter + FlowSessionDriver + pending + finished */ }

/// Iterator yielding `Result<SessionEvent<E::Key, P::Message>, Error>`.
#[cfg(all(feature = "session", feature = "reassembler", feature = "extractors"))]
pub struct DatagramIter<R: Read, E, P> { /* ViewIter + FlowDatagramDriver + pending + finished */ }
```

Target call site (the acceptance bar):

```rust
for evt in PcapFlowSource::open("trace.pcap")?
    .sessions(FiveTuple::bidirectional(), HttpParser::default())
{
    if let SessionEvent::Application { message, .. } = evt? {
        println!("{message:?}");
    }
}
```

## 7. Implementation steps

1. **`SessionIter` struct** — model it on the existing `EventIter`:
   fields `views: ViewIter<R>`, `driver: FlowSessionDriver<E, P>`,
   `pending: VecDeque<SessionEvent<E::Key, P::Message>>`,
   `finished: bool`.
2. **`SessionIter::next`** — port the `EventIter::next` loop:
   - Drain `pending` first.
   - Pull the next view; on `Ok(view)` push
     `driver.track(&view)` results into `pending` (uses plan 34's
     `Into<PacketView>` if landed, else `view.as_view()`).
   - On `Err(e)` return `Some(Err(e))`.
   - On `None` (pcap exhausted): if `!finished`, set `finished`,
     push `driver.finish()` results into `pending`; else return
     `None`.
3. **`DatagramIter`** — identical structure wrapping
   `FlowDatagramDriver`.
4. **`PcapFlowSource::sessions`** — construct
   `FlowSessionDriver::new(extractor, parser)` and wrap with
   `self.views()`. `datagrams` mirrors it.
5. **Feature gating** — `sessions` needs `session` + `reassembler`;
   `datagrams` additionally needs `extractors` (the `FlowExtractor`
   built-ins) — match the gates `FlowSessionDriver` /
   `FlowDatagramDriver` themselves carry in `lib.rs`. The whole
   `pcap` module is already `#[cfg(feature = "pcap")]`, so these are
   nested gates.
6. **`lib.rs`** — if `EventIter` is publicly re-exported, re-export
   `SessionIter` / `DatagramIter` the same way for parity (likely
   they are only reachable as `pcap::SessionIter` — match whatever
   `EventIter` does).
7. **Docs** — `README.md` gets an offline-L7 snippet; `SESSION_GUIDE.md`
   decision flow gains a "offline pcap, typed L7" → `sessions()` row.
8. **`CHANGELOG.md`** — "Added" entry.

## 8. Tests

- **`tests/`** — a new integration test (or extend
  `tests/http_pcap.rs`): open a fixture pcap via
  `.sessions(FiveTuple::bidirectional(), HttpParser::default())`,
  collect events, assert the `Started` / `Application` / `Closed`
  counts match what the manual `FlowDriver` + `HttpFactory` path
  produces for the same fixture.
- **DNS** — `.datagrams(FiveTuple::bidirectional(), DnsUdpParser::default())`
  against a DNS fixture pcap; assert query/response counts.
- **Empty pcap** — `sessions()` over a zero-packet pcap yields an
  empty iterator (the `finish()` path produces nothing).
- **Doctests** — the new `README.md` / module snippets compile
  (`no_run`).

## 9. Acceptance criteria

- An offline HTTP-over-pcap program is a single iterator expression
  with no manual `FlowDriver`, no `views()` loop, no explicit sweep.
- `cargo test --all-features` clean; new integration test green.
- `cargo build` with **only** `--features pcap` (no `session`)
  still compiles — the new methods are correctly gated out.
- `cargo clippy --all-features --all-targets -- -D warnings` clean.
- `cargo doc --all-features --no-deps` zero warnings.

## 10. Risks

- **Feature-gate matrix.** `sessions` / `datagrams` exist only when
  the right feature combination is on. Verify the gates compile in
  the partial-feature builds: `--features pcap`,
  `--features pcap,session,reassembler`,
  `--features pcap,session,reassembler,extractors`. Add these combos
  to the CI matrix or at least to the plan's manual check.
- **`http_log.rs` rewrite.** Rewriting the example onto `sessions()`
  is tempting but the example currently demonstrates the *factory*
  (`HttpFactory` + `HttpHandler`) path. Keep one example on the
  factory path and one on `sessions()` so both are documented —
  decide during implementation. Lowest-risk: leave `http_log.rs`,
  add a short new example or a doctest for `sessions()`.
- Iterator code duplicates `EventIter`'s loop shape. Acceptable —
  the three iterators differ in driver type and event type; a shared
  generic helper would need a trait over "driver that tracks views
  and finishes," which is more machinery than three ~25-line
  `next()` bodies. Note it; don't over-abstract.

## 11. Effort

M — ~180 lines (two iterator types + two methods + tests). Estimate
half a day.

## 12. Provenance

`plans/API-ERGONOMICS-REVIEW.md` finding **F2** (🔴) — "the README
quick-start makes flowscope look one-liner-easy, then the ergonomics
fall off a cliff at L7."

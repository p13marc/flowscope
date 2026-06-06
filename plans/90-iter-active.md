# Plan 90 — `FlowTracker::iter_active()`

## Summary

`FlowTracker::all_flow_stats()` (since 0.4.0) exposes
`Iterator<Item = (&K, &FlowStats)>` for periodic
per-flow snapshots. It's missing two things consumers want:

1. **Per-flow user state** — the `S` parameter on
   `FlowTracker<E, S>`. Consumers using `with_state_*` constructors
   can't read their custom state through the iterator today.
2. **`FlowState`** — the TCP state machine state (`SynSent` /
   `Established` / `FinWait` / …). Dashboards rendering "stuck
   handshakes" need to filter by state.

This plan ships `FlowTracker::iter_active()` returning
`Iterator<Item = ActiveFlow<'_, K, S>>` — a named-field struct that
includes the key, stats, user state, TCP state, and L4 protocol.
Marked `#[non_exhaustive]` so future fields stay additive.

`all_flow_stats()` is **deprecated** in favour of `iter_active()`.
Existing call sites keep compiling with a deprecation warning; we
remove the deprecated method in 0.9 or 0.10.

## Status

Not started.

## Prerequisites

- Plan 38 (driver `S` restore) — shipped in 0.6.0. The
  `FlowTracker<E, S>` is the canonical owner of per-flow `S` again.
- Plan 79 (`l4` on `Ended`) — shipped in 0.7.0. Sets the
  precedent of surfacing `l4` on aggregate event types.

## Out of scope

- Mutable iteration (`iter_active_mut`). The wishlist asks for
  shared-borrow snapshots; mutation goes through `force_close`
  (plan 89) or direct tracker methods.
- Returning owned `ActiveFlow` (`Item = ActiveFlow<K, S>` where
  `K: Clone, S: Clone`). Borrowed is correct for read-only
  snapshotting; owned forces a `Clone` cost the consumer may not
  want.
- Filtering at the iterator (`iter_active_in_state(state)`).
  Consumer composes via `.filter()`; one less API method.
- Removing `all_flow_stats` outright. Deprecate-then-remove keeps
  the migration smooth.

## Files

- `src/tracker.rs` — `ActiveFlow` struct + `iter_active` method +
  `#[deprecated]` on `all_flow_stats`.
- `tests/iter_active.rs` — new file covering happy path + filtering +
  per-flow state + deprecation lint.
- `examples/active_flows_snapshot.rs` — new example: periodic top-N
  by bytes.
- `docs/SESSION_GUIDE.md` — short subsection "Snapshotting active
  flows".
- `CHANGELOG.md` — `### Added` + `### Deprecated` entries.

## API

```rust
// src/tracker.rs

/// Snapshot of one live flow returned by [`FlowTracker::iter_active`].
///
/// `#[non_exhaustive]` so future fields stay non-breaking.
#[derive(Debug)]
#[non_exhaustive]
pub struct ActiveFlow<'a, K, S> {
    pub key: &'a K,
    pub stats: &'a FlowStats,
    /// Per-flow user state. `()` when the tracker was constructed
    /// via the stateless `new` / `with_config` constructors.
    pub user: &'a S,
    pub state: FlowState,
    pub l4: Option<L4Proto>,
}

impl<E: FlowExtractor, S: Send + 'static> FlowTracker<E, S> {
    /// Iterate over every live flow as an [`ActiveFlow`] snapshot.
    /// LRU order is **not** touched (uses `LruCache::iter`).
    ///
    /// Use for periodic dashboards, top-N reports, stuck-handshake
    /// inspection, or any other read-only per-flow snapshot.
    /// Mutation through this iterator is not allowed (shared borrow);
    /// use [`Self::force_close`] to end a specific flow.
    ///
    /// Replaces [`Self::all_flow_stats`] (deprecated). Consumers
    /// using `all_flow_stats` should migrate to `iter_active` —
    /// the new method returns a strict superset of the old.
    pub fn iter_active(&self) -> impl Iterator<Item = ActiveFlow<'_, E::Key, S>> {
        self.flows.iter().map(|(key, entry)| ActiveFlow {
            key,
            stats: &entry.stats,
            user: &entry.user,
            state: entry.state,
            l4: entry.l4,
        })
    }

    /// **Deprecated** (0.8.0). Use [`Self::iter_active`] which
    /// exposes per-flow user state and TCP state machine state in
    /// addition to the basic `FlowStats`.
    #[deprecated(
        since = "0.8.0",
        note = "use `iter_active()` which exposes per-flow user state, TCP state, and L4 protocol in addition to stats"
    )]
    pub fn all_flow_stats(&self) -> impl Iterator<Item = (&E::Key, &FlowStats)> {
        self.flows.iter().map(|(k, e)| (k, &e.stats))
    }
}
```

## Implementation steps

1. Define the `ActiveFlow` struct in `src/tracker.rs`. Derive
   `Debug` only (it borrows; `Clone` doesn't help, and consumers
   that want owned copies clone the borrowed fields themselves).
2. Implement `iter_active`. Borrow rules: `&self → &'a entry`; no
   LRU touch (`LruCache::iter` is read-only).
3. Apply `#[deprecated(since = "0.8.0", note = "…")]` to
   `all_flow_stats`.
4. Update in-tree call sites of `all_flow_stats` (likely zero —
   the method was added in 0.4 and recent code uses other
   accessors). Run with `-D warnings` to surface any.
5. Tests in `tests/iter_active.rs` — see Tests section.
6. New `examples/active_flows_snapshot.rs`:
   ```rust,ignore
   // Print top-5 flows by total bytes every 5 seconds during pcap
   // replay.
   let mut driver = FlowDriver::new(FiveTuple::bidirectional(), ...);
   let mut next_snapshot_at = Timestamp::default();
   for view in PcapFlowSource::open("trace.pcap")?.views() {
       let view = view?;
       driver.track(&view);
       if view.ts > next_snapshot_at {
           let mut flows: Vec<_> = driver
               .tracker()
               .iter_active()
               .collect();
           flows.sort_by_key(|af|
               u64::MAX - (af.stats.bytes_initiator + af.stats.bytes_responder));
           println!("--- top-5 by bytes at {}", view.ts);
           for af in flows.iter().take(5) {
               println!("  {:?} state={:?} bytes={}+{}",
                   af.key, af.state,
                   af.stats.bytes_initiator, af.stats.bytes_responder);
           }
           next_snapshot_at = view.ts + Duration::from_secs(5).into();
       }
   }
   ```
7. SESSION_GUIDE subsection.
8. CHANGELOG entries (Added + Deprecated).

## Tests

`tests/iter_active.rs`:

- `empty_tracker_yields_no_entries` — fresh tracker, empty iter.
- `yields_each_active_flow_once` — three TCP flows, assert
  `iter_active().count() == 3`.
- `surfaces_user_state` — `FlowTracker<_, MyState>` with
  `with_state_init`; assert `ActiveFlow::user` equals the init'd
  state for each flow.
- `surfaces_tcp_state` — drive a 3WHS; assert
  `ActiveFlow::state == FlowState::Established` for the
  established flow.
- `surfaces_l4` — UDP + TCP flow in the same tracker; assert
  `ActiveFlow::l4` matches each.
- `does_not_touch_lru` — record LRU order before / after a full
  iteration; assert no change.
- `composes_with_filter` — `iter_active().filter(|af|
  af.state.is_terminal()).count() == 0` on live flows.
- `all_flow_stats_emits_deprecation_warning` — compile-fail-with-
  warning test using `#[allow(deprecated)]` toggle (or `#[deny]`
  in a test build to assert the lint fires).

## Acceptance criteria

- `FlowTracker::iter_active()` yields every active flow once,
  exposing key + stats + user + state + l4.
- `all_flow_stats` emits a `deprecated` lint diagnostic; calls
  still compile.
- The new `examples/active_flows_snapshot.rs` builds and runs
  against a test fixture.
- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings` clean
  (no deprecation lint from the implementation itself; only fired
  on caller code).
- `cargo doc --all-features --no-deps` clean.

## Risks

- **`ActiveFlow` field additions become semver-additive.**
  `#[non_exhaustive]` makes this explicit. Construction from
  outside the crate is not supported.
- **Deprecation warning noise for users on 0.7-bridge code.** The
  one-line migration (`s/all_flow_stats/iter_active/`) is in the
  CHANGELOG; warning level is conventional.
- **LRU iteration order not specified.** `iter_active` does not
  promise any particular order; the example sorts client-side.
  Documented.

## Effort

~100 LoC source (struct + method + deprecation + ActiveFlow Debug
impl) + ~150 LoC tests + ~60 LoC example + 20 lines SESSION_GUIDE.
**~3 hours.**

## Provenance

Round-3 wishlist item B7 in
[`docs/feedback-2026-06-06-netring-wishlist.md`](../docs/feedback-2026-06-06-netring-wishlist.md).
Plan-of-record §5 documents the deviation from the wishlist's
proposed tuple-return shape: named struct with `#[non_exhaustive]`
is more Rust-idiomatic and keeps the surface stable as future
fields land.

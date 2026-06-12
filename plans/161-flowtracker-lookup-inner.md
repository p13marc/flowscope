# Plan 161 — `FlowTracker<FiveTuple, S>::lookup_inner` + `FiveTupleKey::from_inner_canonical`

## Summary

The highest-leverage 0.14 addition. Lets ICMP error consumers
join an `IcmpInner` (the embedded original 5-tuple from an
ICMP DU / TE / etc. error) back to a live flow with one method
call — instead of hand-rolling a `HashMap<FlowKey, FlowStats>`
mirror cache.

Three additions:

1. **`FiveTupleKey::from_inner_canonical(&IcmpInner) -> Option<FiveTupleKey>`** —
   public canonicalisation helper. Builds the canonical
   5-tuple key from a partial 5-tuple, applying the same
   bidirectional canonicalisation logic the extractor uses
   internally.
2. **`FlowTracker<FiveTuple, S>::lookup_inner(&IcmpInner) -> Option<FiveTupleKey>`** —
   specialised impl block: takes an ICMP inner, returns the
   matching live flow's canonical key. O(1) hash lookup.
3. **`FlowTracker<FiveTuple, S>::stats_for_inner(&IcmpInner) -> Option<(FiveTupleKey, &FlowStats)>`** —
   convenience for the common "join then read stats" pattern.

## Status

Not started. P0 for 0.14.

## Prerequisites

None.

## Out of scope

- **Generic-key lookup.** `IcmpInner` carries IP + ports +
  proto — a FiveTupleKey-shape. Custom extractor key types
  (`IpPair`, `MacPair`, user-defined) don't have a meaningful
  "lookup by 5-tuple" semantics. The new methods are
  specialised to `FlowTracker<FiveTuple, S>`.
- **Cross-extractor lookup.** Pure FiveTuple match only. If a
  consumer wants `IpPair` matching on partial 5-tuple, they
  can implement it themselves.

## Files

| Action | Path | Purpose |
|---|---|---|
| Modify | `src/extract/five_tuple.rs` | Add `FiveTupleKey::from_inner_canonical` public ctor |
| Modify | `src/tracker.rs` | Add specialised `impl<S> FlowTracker<FiveTuple, S>` block with `lookup_inner` + `stats_for_inner` |
| Modify | `src/icmp/mod.rs` | Re-export `IcmpInner` at the icmp module level (verify it's reachable) |
| New | `tests/tracker_lookup_inner.rs` | Integration tests covering bidirectional canonicalisation |

## API

### Canonicalisation helper

```rust
// src/extract/five_tuple.rs

impl FiveTupleKey {
    /// Construct a canonical `FiveTupleKey` from an ICMP
    /// inner 5-tuple (the original packet's headers
    /// embedded in an ICMPv4/v6 error message).
    ///
    /// Returns `None` if the inner tuple's ports are missing
    /// for a port-carrying proto (TCP/UDP/SCTP) — in that
    /// case the lookup can't disambiguate which flow the
    /// error refers to.
    ///
    /// The returned key uses the same bidirectional
    /// canonicalisation logic the live extractor applies —
    /// so a key built from an `IcmpInner` matches the live
    /// flow's key regardless of which direction the flow
    /// started in.
    ///
    /// Plan 161 (0.14).
    pub fn from_inner_canonical(inner: &crate::icmp::IcmpInner) -> Option<Self> {
        use std::net::SocketAddr;

        // Port-carrying protos need ports; protocol/host/network
        // unreachable on raw IP packets carry no port.
        let need_ports = matches!(
            inner.proto,
            L4Proto::Tcp | L4Proto::Udp | L4Proto::Sctp
        );
        if need_ports && (inner.src_port.is_none() || inner.dst_port.is_none()) {
            return None;
        }

        let src = SocketAddr::new(inner.src, inner.src_port.unwrap_or(0));
        let dst = SocketAddr::new(inner.dst, inner.dst_port.unwrap_or(0));

        // Same bidirectional canonicalisation as
        // `extract_from_parsed`: order by raw addr.
        let (a, b) = if src > dst { (dst, src) } else { (src, dst) };

        Some(FiveTupleKey {
            proto: inner.proto,
            a,
            b,
        })
    }
}
```

### FlowTracker specialised impl

```rust
// src/tracker.rs

impl<S> FlowTracker<crate::extract::FiveTuple, S>
where
    S: Send + 'static,
{
    /// Join an ICMP error's inner 5-tuple back to a live
    /// flow. Returns the canonical `FiveTupleKey` if a
    /// matching flow exists, or `None` if the tracker has no
    /// such flow (truncated embed, parse error, or the flow
    /// already expired).
    ///
    /// O(1) hash lookup. Read-only.
    ///
    /// Plan 161 (0.14).
    pub fn lookup_inner(
        &self,
        inner: &crate::icmp::IcmpInner,
    ) -> Option<crate::extract::FiveTupleKey> {
        let key = FiveTupleKey::from_inner_canonical(inner)?;
        if self.flows.contains(&key) {
            Some(key)
        } else {
            None
        }
    }

    /// Companion: read the current `FlowStats` for a
    /// matching flow, if any. Saves the second lookup for
    /// the common "join then read stats" pattern.
    ///
    /// Plan 161 (0.14).
    pub fn stats_for_inner(
        &self,
        inner: &crate::icmp::IcmpInner,
    ) -> Option<(crate::extract::FiveTupleKey, &FlowStats)> {
        let key = FiveTupleKey::from_inner_canonical(inner)?;
        let entry = self.flows.peek(&key)?;
        Some((key, &entry.stats))
    }
}
```

(Note: the `flows.contains` / `flows.peek` calls assume the
internal `LruCache` exposes these. Verify and adjust during
implementation — may need to use `self.get(&key).is_some()`
instead of `contains`.)

## Implementation steps

1. Add `FiveTupleKey::from_inner_canonical` constructor.
2. Add the specialised `impl<S> FlowTracker<FiveTuple, S>`
   block with `lookup_inner` + `stats_for_inner`.
3. Tests covering:
   - Direction-agnostic matching (key A→B, inner reports B→A).
   - Missing ports for TCP returns `None`.
   - Missing ports for ICMP-on-ICMP returns the IP-only key.
   - Non-existent flow returns `None`.
   - Stats read matches the tracker's actual stats.
4. Add a usage recipe to `docs/recipes.md` under "0.14
   patterns" — "Joining ICMP errors back to live flows".

## Tests

- `lookup_inner_matches_forward_direction`.
- `lookup_inner_matches_reverse_direction_canonically`.
- `lookup_inner_returns_none_when_flow_missing`.
- `lookup_inner_returns_none_on_missing_ports_for_tcp`.
- `lookup_inner_accepts_icmp_on_icmp_inner` (raw IP no-port
  case).
- `stats_for_inner_returns_canonical_key_and_stats`.
- `stats_for_inner_returns_none_when_flow_missing`.

## Acceptance criteria

- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- netring 0.22's `IcmpError { correlated_flow }` typed event
  becomes a thin wrapper over `tracker.lookup_inner(&inner)`.

## Risks

**R1: Direction canonicalisation logic divergence.** The
`from_inner_canonical` helper must match the live extractor's
canonicalisation exactly. Mitigation: extract the existing
canonicalisation into a shared private helper, call it from
both sites. Adversarial test: synthesize a flow A→B, then
call `lookup_inner` with `IcmpInner` reporting B→A, assert
match.

**R2: `IcmpInner` may not be reachable from `tracker.rs`.**
The `tracker` module doesn't depend on `icmp` today.
Mitigation: the impl block can be in a separate file
(`src/tracker/icmp_lookup.rs`) gated on `feature = "icmp"` to
avoid pulling ICMP into the tracker's hot dependency tree.

**R3: Specialised impl block syntax.** Rust allows
specialised impl blocks for concrete extractor types. Verify
the impl signature compiles. Alternative: a free function
`flowscope::icmp::lookup_inner_in(tracker: &FlowTracker<FiveTuple, S>, inner: &IcmpInner)` if the impl block is awkward.

## Effort

- LOC delta: +250 (canonicaliser + impl block + tests + docs).
- Time estimate: **1.5 days**.

## Provenance

Wishlist plan 161. Counter-proposals (specialise the impl,
add `from_inner_canonical` as the shared infrastructure) —
see umbrella 169 §3.2.

The wishlist's caveat about FlowTracker being "mutate-only"
was verified WRONG: `FlowTracker<E, S>` already exposes a
rich read API (`get`, `snapshot_stats`, `flows`,
`iter_active`). No refactor is needed.

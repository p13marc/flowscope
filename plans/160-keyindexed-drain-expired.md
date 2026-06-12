# Plan 160 — `KeyIndexed::drain_expired` + `drain_expired_into`

## Summary

Add owned-draining variants to [`KeyIndexed<K, V>`] alongside
the existing `evict_expired` (which discards). Lets callers
inspect expired entries — typical for "DNS resolved but no
connection followed", "TLS handshake started but never
completed", "ICMP didn't explain a flow death" patterns.

Ships two variants:
- `drain_expired(now) -> Vec<(K, V)>` — ergonomic, allocates.
- `drain_expired_into(now, &mut Vec<(K, V)>) -> usize` —
  reusable storage, amortizes allocation across calls.

## Status

Not started. P0 for 0.14.

## Prerequisites

None.

## Out of scope

- **Zero-alloc lazy iterator.** The `lru::LruCache` underneath
  has no `drain()` method; collecting expired keys into a
  `Vec<K>` first is unavoidable. The `_into` variant amortizes
  this across calls but doesn't eliminate it.
- **`drain_all` (drain everything regardless of TTL).** The
  existing `KeyIndexed::iter` + `remove` pattern covers this;
  add later if a consumer asks.

## Files

| Action | Path | Purpose |
|---|---|---|
| Modify | `src/correlate/indexed.rs` | Add `drain_expired` + `drain_expired_into` methods |
| New | `tests/correlate_drain_expired.rs` (or extend existing) | Unit tests |

## API

```rust
// src/correlate/indexed.rs

impl<K, V> KeyIndexed<K, V>
where
    K: Hash + Eq + Clone,
{
    /// Drain entries whose TTL has elapsed at `now`. Returns
    /// the expired entries as owned `(K, V)` pairs in
    /// arbitrary order.
    ///
    /// Non-expired entries stay in the index. Companion to
    /// [`Self::evict_expired`] (which discards) — use this
    /// when the caller needs to inspect expired entries
    /// (typical for "DNS resolved but no connection followed"
    /// or "ICMP didn't explain a flow death" patterns).
    ///
    /// Allocation: the underlying `lru::LruCache` doesn't
    /// expose a `drain()` method, so this method must collect
    /// expired keys into an intermediate `Vec` before popping.
    /// For amortized-allocation hot loops, use
    /// [`Self::drain_expired_into`] with a reusable buffer.
    ///
    /// Plan 160 (0.14).
    pub fn drain_expired(&mut self, now: Timestamp) -> Vec<(K, V)> {
        let mut out = Vec::new();
        self.drain_expired_into(now, &mut out);
        out
    }

    /// Append expired entries to `out` and return the count.
    /// Reuses `out`'s allocation across calls.
    ///
    /// Mirrors the `track_into` (plan 119) / `drain_n`
    /// (plan 149) idiom: pre-allocate `out` once, reuse it
    /// in the hot loop.
    ///
    /// Plan 160 (0.14).
    pub fn drain_expired_into(
        &mut self,
        now: Timestamp,
        out: &mut Vec<(K, V)>,
    ) -> usize {
        let start = out.len();
        // Identify expired keys by iterating; collect-then-pop
        // because lru::LruCache::iter borrows the cache.
        let now_dur = now.to_duration();
        let expired: Vec<K> = self
            .inner
            .iter()
            .filter_map(|(k, (_v, inserted))| {
                if now_dur.saturating_sub(inserted.to_duration()) > self.ttl {
                    Some(k.clone())
                } else {
                    None
                }
            })
            .collect();
        for k in expired {
            if let Some((v, _ts)) = self.inner.pop(&k) {
                out.push((k, v));
            }
        }
        out.len() - start
    }
}
```

## Implementation steps

1. Add `drain_expired_into` (the primitive).
2. Add `drain_expired` as a thin wrapper that allocates a
   fresh `Vec`.
3. Rustdoc: cross-link to `evict_expired` (the discard
   sibling) and document the allocation contract.
4. Tests covering: empty cache, no expired, all expired,
   partial expiry, `_into` append semantics, idempotency on
   repeated calls.

## Tests

- `drain_expired_returns_empty_on_no_expiry`.
- `drain_expired_returns_owned_pairs_on_full_expiry`.
- `drain_expired_returns_partial_on_mixed_expiry`.
- `drain_expired_after_drain_returns_empty` (idempotency).
- `drain_expired_into_appends_to_existing_vec`.
- `drain_expired_into_returns_correct_count`.
- `drain_expired_leaves_non_expired_entries_intact`.

## Acceptance criteria

- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- netring 0.22 can drop its local `correlate::KeyIndexed` copy
  (the wishlist's `0.22-G` item) and re-export from flowscope.

## Risks

**R1: Honest allocation contract.** The wishlist's
`impl Iterator + '_` signature implied zero-alloc; this design
ships a `Vec` return and documents the allocation honestly.
Mitigation: the `_into` variant lets hot loops amortize.

**R2: `K: Clone` bound.** Required because we collect keys
before popping. Same constraint as the existing
`KeyIndexed::evict_expired`. Mitigation: documented.

## Effort

- LOC delta: +120 (methods + tests + rustdoc).
- Time estimate: **0.5 day**.

## Provenance

Wishlist plan 160 / netring 0.22-G. Counter-proposal on
allocation contract — see umbrella 169 §3.1.

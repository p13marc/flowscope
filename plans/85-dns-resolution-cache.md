# Plan 85 — `DnsResolutionCache` primitive

## Summary

The cross-protocol-correlation pattern *"this client resolved
foo.com → IPs Y at time T; was the subsequent TCP/UDP connection
within the resolution's TTL?"* shows up in at least two netring
detectors (`dns_resolved_no_connection.rs`,
`tls_to_unresolved_ip.rs`). Both hand-roll the same shape:

```rust
HashMap<IpAddr /* client */, KeyIndexed<IpAddr /* target */, ()>>
```

This plan ships a focused, high-level primitive — `DnsResolutionCache`
— in `flowscope::dns::correlate`. It absorbs the open-code pattern and
the per-source-IP eviction logic, exposing a small set of methods that
match the two known consumer patterns:

1. *"Did client X recently resolve target Y?"* (boolean predicate)
2. *"What hostname did client X resolve target Y from?"* (string lookup)
3. *"Drop stale entries"* (sweep on a tick)

The primitive owns its TTL semantics; consumers don't need to track
per-entry timestamps externally.

This is **not** the broader `flowscope::correlate` module from plan 81
(that stays RFC-only on the 0.9 track). This plan ships a
domain-specific primitive that doesn't preclude later generalization
into `correlate`.

## Status

Not started.

## Prerequisites

- Plan 35 (DNS parser shape: `DnsMessage`, `DnsResponse`,
  `DnsRdata`) — shipped in 0.4.0.
- `lru` crate dependency (already used by `FlowTracker`) — no new
  crate dependency added by this plan.

## Out of scope

- General-purpose `KeyIndexed<K, V>` / `TimeBucketedCounter<K>`. Those
  belong in `flowscope::correlate` (plan 81) when the RFC settles.
  This plan ships only the DNS-specific cache.
- DNSSEC validation. The cache is opportunistic correlation, not
  authoritative resolution.
- Reverse lookup (target → set of names). The two known consumers
  use the forward direction only.
- IPv4 / IPv6 unification. The cache stores `IpAddr` (the standard
  library's discriminated union); separate v4 and v6 enumeration is
  out of scope.
- Response correlation by transaction ID. That's the `Correlator`
  shipped in 0.4 (`flowscope::dns::Correlator`). This cache consumes
  the *output* of a correlated response, not the wire bytes.

## Files

- `src/dns/correlate.rs` — new file. `DnsResolutionCache` struct +
  methods.
- `src/dns/mod.rs` — `mod correlate;` + `pub use correlate::DnsResolutionCache;`.
- `tests/dns_resolution_cache.rs` — integration tests covering the
  three method patterns + TTL expiry + multi-client isolation.
- `docs/SESSION_GUIDE.md` — new subsection "Cross-protocol
  correlation: DNS resolutions".
- `CHANGELOG.md` — `### Added` entry.

## API

```rust
//! src/dns/correlate.rs

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use lru::LruCache;

use crate::Timestamp;
use crate::dns::{DnsRdata, DnsResponse};

/// Per-client DNS-resolution cache with TTL eviction.
///
/// Keyed by `(client_ip, target_ip)`; the value carries the
/// hostname and the resolution timestamp. Records every A / AAAA
/// answer record observed via [`Self::observe_response`].
///
/// Bounded by capacity (LRU eviction) and TTL (per-entry expiry).
/// Both are tuneable at construction.
pub struct DnsResolutionCache {
    inner: LruCache<(IpAddr, IpAddr), Resolution>,
    ttl: Duration,
}

#[derive(Debug, Clone)]
struct Resolution {
    name: String,
    observed: Timestamp,
}

impl DnsResolutionCache {
    /// Construct a cache with the given TTL and a default capacity
    /// (16,384 entries — bounded memory for production deployments).
    ///
    /// `ttl` controls per-entry expiry; entries older than `ttl` are
    /// considered absent by [`Self::was_resolved`] and
    /// [`Self::lookup_name`]. Use [`Self::sweep`] to physically remove
    /// expired entries.
    pub fn new(ttl: Duration) -> Self {
        Self::with_capacity(ttl, 16_384)
    }

    /// Construct with explicit capacity.
    pub fn with_capacity(ttl: Duration, capacity: usize) -> Self {
        let capacity = std::num::NonZeroUsize::new(capacity.max(1)).unwrap();
        Self {
            inner: LruCache::new(capacity),
            ttl,
        }
    }

    /// Record every A / AAAA answer record in `response` as a
    /// resolution by `client_ip` at `now`. CNAME, NS, MX, and other
    /// rtypes are skipped.
    ///
    /// Hostnames are canonicalised to lowercase ASCII (RFC 1035 §2.3.1).
    pub fn observe_response(
        &mut self,
        client_ip: IpAddr,
        response: &DnsResponse,
        now: Timestamp,
    ) {
        let name = response.canonical_name().to_ascii_lowercase();
        for answer in &response.answers {
            let target_ip = match answer.rdata {
                DnsRdata::A(ip) => IpAddr::V4(ip),
                DnsRdata::Aaaa(ip) => IpAddr::V6(ip),
                _ => continue,
            };
            self.inner.put(
                (client_ip, target_ip),
                Resolution {
                    name: name.clone(),
                    observed: now,
                },
            );
        }
    }

    /// `true` if `client_ip` has resolved a name to `target_ip`
    /// within `self.ttl` of `now`.
    pub fn was_resolved(
        &mut self,
        client_ip: IpAddr,
        target_ip: IpAddr,
        now: Timestamp,
    ) -> bool {
        self.lookup_name(client_ip, target_ip, now).is_some()
    }

    /// The canonical hostname `client_ip` last resolved `target_ip`
    /// from, if within `self.ttl` of `now`. `None` if absent or
    /// expired.
    ///
    /// Takes `&mut self` because `lru::LruCache::get` mutates LRU
    /// order. Callers wanting `&self` read-only access can peek via
    /// [`Self::peek_name`].
    pub fn lookup_name(
        &mut self,
        client_ip: IpAddr,
        target_ip: IpAddr,
        now: Timestamp,
    ) -> Option<&str> {
        let entry = self.inner.get(&(client_ip, target_ip))?;
        if self.is_expired(entry, now) {
            return None;
        }
        Some(entry.name.as_str())
    }

    /// `&self` peek — does not promote in LRU order.
    pub fn peek_name(
        &self,
        client_ip: IpAddr,
        target_ip: IpAddr,
        now: Timestamp,
    ) -> Option<&str> {
        let entry = self.inner.peek(&(client_ip, target_ip))?;
        if self.is_expired(entry, now) {
            return None;
        }
        Some(entry.name.as_str())
    }

    /// Drop entries older than `ttl` relative to `now`. Call from a
    /// periodic tick. Returns the number of entries removed.
    pub fn sweep(&mut self, now: Timestamp) -> usize {
        // Collect expired keys; LruCache doesn't expose retain-style
        // iteration that mutates in place.
        let expired: Vec<(IpAddr, IpAddr)> = self
            .inner
            .iter()
            .filter(|(_, res)| self.is_expired(res, now))
            .map(|(k, _)| *k)
            .collect();
        let n = expired.len();
        for key in expired {
            self.inner.pop(&key);
        }
        n
    }

    /// Current number of cached resolutions (some may be expired but
    /// not yet swept).
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    fn is_expired(&self, entry: &Resolution, now: Timestamp) -> bool {
        let elapsed = now.to_duration().saturating_sub(entry.observed.to_duration());
        elapsed > self.ttl
    }
}
```

`DnsResponse::canonical_name()` is a small helper on the existing type
returning the first question's name (canonical for the response).
If not present, we add it in this plan.

## Implementation steps

1. Add `DnsResponse::canonical_name() -> &str` accessor (~3 LoC) in
   `src/dns/types.rs` — returns `self.questions.first().map(|q| q.name.as_str()).unwrap_or("")`.
2. Add `src/dns/correlate.rs` with the full implementation above.
3. Wire it via `src/dns/mod.rs`.
4. Tests in `tests/dns_resolution_cache.rs`:
   - `observes_a_record` — single A answer → was_resolved + lookup_name.
   - `observes_aaaa_record` — same for AAAA.
   - `skips_cname` — CNAME-only response doesn't populate.
   - `expired_lookups_return_none` — entry past TTL.
   - `sweep_removes_expired` — sweep count + post-sweep len.
   - `lru_eviction_at_capacity` — `with_capacity(_, 2)` + 3 entries.
   - `multiple_clients_isolated` — client A's resolution doesn't
     answer client B's lookup.
   - `case_insensitive_canonical_name` — `Foo.COM` and `foo.com`
     resolutions are de-duplicated.
   - `peek_does_not_promote` — `peek_name` followed by an eviction
     test.
5. SESSION_GUIDE new subsection `Cross-protocol correlation`:
   ```rust,ignore
   use flowscope::dns::DnsResolutionCache;
   use std::time::Duration;

   let mut cache = DnsResolutionCache::new(Duration::from_secs(300));

   // On every DNS response message:
   cache.observe_response(client_ip, &response, now);

   // On every TCP/UDP flow start:
   if !cache.was_resolved(client_ip, target_ip, now) {
       println!("⚠ {client_ip} → {target_ip} without DNS context");
   }

   // Periodically:
   cache.sweep(now);
   ```
6. CHANGELOG `### Added` entry.

## Tests

See step 4. Nine focused tests in `tests/dns_resolution_cache.rs`.

## Acceptance criteria

- All public methods compile and pass tests.
- TTL eviction works for both `lookup_name` (logical) and `sweep`
  (physical).
- Multi-client isolation is verified.
- LRU bound is enforced.
- `cargo test --features dns --test dns_resolution_cache` clean.
- `cargo clippy --features dns --all-targets -- -D warnings` clean.
- `cargo doc --features dns --no-deps` documents the module
  cleanly.
- Feature-matrix CI green (`dns` standalone build covers the new
  module).

## Risks

- **Capacity-vs-eviction collision.** A hot client pushes new
  resolutions; older clients' resolutions evict via LRU regardless
  of TTL. This is the intended behaviour for bounded memory; the
  16K default capacity is documented.
- **`&mut self` on `lookup_name`.** Required by `lru::LruCache::get`.
  Documented; the `peek_name` `&self` variant is the workaround
  for callers in immutable contexts.
- **Hostname canonicalisation.** ASCII lowercase only. IDNA / Punycode
  decoding is out of scope; consumers feeding non-ASCII names get
  pass-through.

## Effort

~150 LoC source (cache + helper) + ~180 LoC tests + 30 lines
SESSION_GUIDE. **~1 day** including CHANGELOG.

## Provenance

Round-3 wishlist item A3 in
[`docs/feedback-2026-06-06-netring-wishlist.md`](../docs/feedback-2026-06-06-netring-wishlist.md).
Two netring detectors already implement it. Shipping here saves
the third user from reimplementing and provides a known-correct
base for the broader `correlate` module (plan 81) to compose with
later.

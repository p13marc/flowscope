//! Plan 85 — per-client DNS resolution cache with TTL eviction.

use std::{net::IpAddr, num::NonZeroUsize, time::Duration};

use lru::LruCache;

use crate::{
    dns::{DnsRdata, DnsResponse},
    Timestamp,
};

/// Per-client DNS-resolution cache with TTL eviction.
///
/// Records every A / AAAA answer record from a [`DnsResponse`]
/// keyed by `(client_ip, target_ip)`. Useful for cross-protocol
/// correlation: *"Did client X recently resolve target Y?"*
/// or *"What hostname did client X use for target Y?"*
///
/// Bounded by capacity (LRU eviction) and TTL (per-entry expiry).
/// Both are tuneable at construction.
///
/// ```ignore
/// use flowscope::dns::DnsResolutionCache;
/// use std::time::Duration;
///
/// let mut cache = DnsResolutionCache::new(Duration::from_secs(300));
///
/// // On every DNS response message in the consumer loop:
/// cache.observe_response(client_ip, &response, now);
///
/// // On every TCP/UDP flow start:
/// if !cache.was_resolved(client_ip, target_ip, now) {
///     println!("⚠ {client_ip} → {target_ip} without DNS context");
/// }
///
/// // Periodically:
/// cache.sweep(now);
/// ```
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
    /// Construct with the given TTL and a default capacity of 16,384
    /// entries (bounded memory for production deployments).
    pub fn new(ttl: Duration) -> Self {
        Self::with_capacity(ttl, 16_384)
    }

    /// Construct with explicit capacity. `capacity` is clamped to at
    /// least 1.
    pub fn with_capacity(ttl: Duration, capacity: usize) -> Self {
        let capacity = NonZeroUsize::new(capacity.max(1)).unwrap();
        Self {
            inner: LruCache::new(capacity),
            ttl,
        }
    }

    /// Record every A / AAAA answer record in `response` as a
    /// resolution by `client_ip` at `now`. CNAME, NS, MX, and other
    /// rtypes are skipped.
    ///
    /// Hostnames are canonicalised to lowercase ASCII (RFC 1035
    /// §2.3.1).
    pub fn observe_response(&mut self, client_ip: IpAddr, response: &DnsResponse, now: Timestamp) {
        let name = canonical_name(response).to_ascii_lowercase();
        for answer in &response.answers {
            let target_ip = match answer.data {
                DnsRdata::A(ip) => IpAddr::V4(ip),
                DnsRdata::AAAA(ip) => IpAddr::V6(ip),
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
    ///
    /// Takes `&mut self` because the LRU lookup mutates access
    /// order. Use [`Self::peek_resolved`] for a non-promoting
    /// `&self` variant.
    pub fn was_resolved(&mut self, client_ip: IpAddr, target_ip: IpAddr, now: Timestamp) -> bool {
        self.lookup_name(client_ip, target_ip, now).is_some()
    }

    /// `&self`-borrowing companion to [`Self::was_resolved`]. Does
    /// not touch LRU order.
    pub fn peek_resolved(&self, client_ip: IpAddr, target_ip: IpAddr, now: Timestamp) -> bool {
        self.peek_name(client_ip, target_ip, now).is_some()
    }

    /// The canonical hostname `client_ip` last resolved `target_ip`
    /// from, if within `self.ttl` of `now`. `None` if absent or
    /// expired.
    ///
    /// Takes `&mut self`; see [`Self::peek_name`] for the `&self`
    /// variant.
    pub fn lookup_name(
        &mut self,
        client_ip: IpAddr,
        target_ip: IpAddr,
        now: Timestamp,
    ) -> Option<&str> {
        let ttl = self.ttl;
        let entry = self.inner.get(&(client_ip, target_ip))?;
        if is_expired(entry, now, ttl) {
            return None;
        }
        Some(entry.name.as_str())
    }

    /// `&self`-borrowing companion to [`Self::lookup_name`]. Does
    /// not touch LRU order.
    pub fn peek_name(&self, client_ip: IpAddr, target_ip: IpAddr, now: Timestamp) -> Option<&str> {
        let entry = self.inner.peek(&(client_ip, target_ip))?;
        if is_expired(entry, now, self.ttl) {
            return None;
        }
        Some(entry.name.as_str())
    }

    /// Drop entries older than `ttl` relative to `now`. Returns the
    /// number of entries removed.
    pub fn sweep(&mut self, now: Timestamp) -> usize {
        let ttl = self.ttl;
        let expired: Vec<(IpAddr, IpAddr)> = self
            .inner
            .iter()
            .filter(|(_, res)| is_expired(res, now, ttl))
            .map(|(k, _)| *k)
            .collect();
        let n = expired.len();
        for key in expired {
            self.inner.pop(&key);
        }
        n
    }

    /// Current number of cached resolutions. Some may be expired but
    /// not yet swept.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

fn is_expired(entry: &Resolution, now: Timestamp, ttl: Duration) -> bool {
    let elapsed = now
        .to_duration()
        .saturating_sub(entry.observed.to_duration());
    elapsed > ttl
}

/// First question's name, or empty string if there are no
/// questions. Canonical because in real-world DNS responses the
/// question section echoes the queried name.
fn canonical_name(response: &DnsResponse) -> &str {
    response
        .questions
        .first()
        .map(|q| q.name.as_str())
        .unwrap_or("")
}

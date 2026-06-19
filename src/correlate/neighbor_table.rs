//! [`NeighborTable`] — bounded + TTL'd IP→hardware-address binding
//! tracker with change-of-binding detection.
//!
//! Designed up-front to support both ARP (IPv4 + MAC) AND IPv6
//! Neighbor Discovery (IPv6 + MAC) without a future API rename:
//! the table is generic over the L3 address type and the
//! link-layer address type. The ARP feature in 0.17 ships
//! [`ArpTable`] as a type alias; a future NDP feature will add
//! `NdpTable` for IPv6.
//!
//! Layers on [`crate::correlate::KeyIndexed`] for the TTL +
//! bounded-cardinality discipline.
//!
//! The natural producer of bindings is the `arp` feature's
//! [`crate::arp::ArpMessage`] (gated): take each parsed reply /
//! gratuitous announcement, call `observe(sender_ip, sender,
//! now)`, and route the returned [`NeighborEvent`] to your
//! anomaly emitter. The fast wire-level read path is
//! [`crate::layers::ArpSlice`] (always-on under the
//! `extractors` feature).
//!
//! Issue #1 (0.17).

use std::{hash::Hash, num::NonZeroUsize, time::Duration};

use crate::{correlate::KeyIndexed, Timestamp};

/// Per-binding state stored in a [`NeighborTable`].
///
/// `#[non_exhaustive]` — future fields (per-binding metrics,
/// debounce counters, source tag, …) will be additive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct NeighborBinding<L4> {
    /// The currently-observed link-layer address.
    pub addr: L4,
    /// Timestamp this IP→L4 binding was first seen in this row.
    pub first_seen: Timestamp,
    /// Timestamp of the most recent observation.
    pub last_seen: Timestamp,
    /// Number of times this exact binding has been observed.
    pub seen_count: u32,
    /// Number of times the link-layer address has changed for
    /// this IP. `0` means stable since first seen.
    pub change_count: u32,
    /// Previous link-layer address before the most recent
    /// change. `None` until the first change.
    pub prior_addr: Option<L4>,
}

/// Result of observing one IP→L4 binding.
///
/// `#[non_exhaustive]` — future variants (e.g. `Withdrawn` for
/// NDP `Unreachable`) will be additive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "kind", rename_all = "snake_case"))]
#[non_exhaustive]
pub enum NeighborEvent<L4> {
    /// First time this IP has been seen in the table.
    NewBinding { addr: L4 },
    /// Same IP, same L4 — refresh.
    Refresh,
    /// IP rebound to a different L4 (possible MAC change, host
    /// reboot, or ARP-spoof). Carries both addresses for the
    /// caller's response policy.
    Changed { prior: L4, new: L4 },
}

/// Bounded, TTL'd IP→L4 binding table.
///
/// Generic over:
/// - `L3` — the network-layer address type (`Ipv4Addr` for ARP,
///   `Ipv6Addr` for NDP).
/// - `L4` — the link-layer address type (typically [`crate::MacAddr`]).
///
/// Bounded by an LRU policy (oldest unseen entries evicted first)
/// AND a TTL (entries unseen for longer than the TTL are dropped
/// on `evict_expired`).
#[derive(Debug)]
pub struct NeighborTable<L3, L4>
where
    L3: Hash + Eq + Clone,
    L4: Clone + PartialEq,
{
    inner: KeyIndexed<L3, NeighborBinding<L4>>,
}

impl<L3, L4> NeighborTable<L3, L4>
where
    L3: Hash + Eq + Clone,
    L4: Clone + PartialEq,
{
    /// LRU-bounded table with the given `ttl` and `capacity`.
    pub fn new(ttl: Duration, capacity: NonZeroUsize) -> Self {
        Self {
            inner: KeyIndexed::new(ttl, capacity.get()),
        }
    }

    /// Unbounded table — only TTL bounds memory.
    pub fn new_unbounded(ttl: Duration) -> Self {
        Self {
            inner: KeyIndexed::new_unbounded(ttl),
        }
    }

    /// Observe an IP→L4 binding at `now`. Updates the table and
    /// returns the [`NeighborEvent`] describing what happened.
    pub fn observe(&mut self, ip: L3, addr: L4, now: Timestamp) -> NeighborEvent<L4> {
        if let Some(binding) = self.inner.get_mut(&ip, now) {
            if binding.addr == addr {
                binding.last_seen = now;
                binding.seen_count = binding.seen_count.saturating_add(1);
                NeighborEvent::Refresh
            } else {
                let prior = binding.addr.clone();
                binding.prior_addr = Some(prior.clone());
                binding.addr = addr.clone();
                binding.last_seen = now;
                binding.change_count = binding.change_count.saturating_add(1);
                binding.seen_count = binding.seen_count.saturating_add(1);
                NeighborEvent::Changed { prior, new: addr }
            }
        } else {
            self.inner.insert(
                ip,
                NeighborBinding {
                    addr: addr.clone(),
                    first_seen: now,
                    last_seen: now,
                    seen_count: 1,
                    change_count: 0,
                    prior_addr: None,
                },
                now,
            );
            NeighborEvent::NewBinding { addr }
        }
    }

    /// Look up the current binding for `ip` without updating TTL.
    ///
    /// `now` is required for TTL filtering — stale entries return
    /// `None` even if they're still in the internal storage.
    pub fn peek(&self, ip: &L3, now: Timestamp) -> Option<&NeighborBinding<L4>> {
        self.inner.peek(ip, now)
    }

    /// Drop entries whose age exceeds the TTL. Idempotent.
    pub fn evict_expired(&mut self, now: Timestamp) {
        self.inner.evict_expired(now);
    }

    /// Number of bindings currently tracked.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// `true` if no bindings are tracked.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

/// IPv4 + MAC binding table — the ARP case. Shipped behind the
/// `arp` feature.
#[cfg(feature = "arp")]
pub type ArpTable = NeighborTable<std::net::Ipv4Addr, crate::MacAddr>;

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::MacAddr;

    fn ts(secs: u32) -> Timestamp {
        Timestamp::new(secs, 0)
    }

    #[test]
    fn first_observation_emits_new_binding() {
        let mut table: NeighborTable<Ipv4Addr, MacAddr> =
            NeighborTable::new_unbounded(Duration::from_secs(60));
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        let mac = MacAddr([1, 2, 3, 4, 5, 6]);
        let ev = table.observe(ip, mac, ts(0));
        assert!(matches!(ev, NeighborEvent::NewBinding { addr } if addr == mac));
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn same_binding_emits_refresh_and_increments_count() {
        let mut table: NeighborTable<Ipv4Addr, MacAddr> =
            NeighborTable::new_unbounded(Duration::from_secs(60));
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        let mac = MacAddr([1, 2, 3, 4, 5, 6]);
        table.observe(ip, mac, ts(0));
        let ev = table.observe(ip, mac, ts(5));
        assert!(matches!(ev, NeighborEvent::Refresh));
        let b = table.peek(&ip, ts(5)).unwrap();
        assert_eq!(b.seen_count, 2);
        assert_eq!(b.change_count, 0);
        assert_eq!(b.first_seen, ts(0));
        assert_eq!(b.last_seen, ts(5));
        assert!(b.prior_addr.is_none());
    }

    #[test]
    fn different_mac_emits_changed_and_increments_change_count() {
        let mut table: NeighborTable<Ipv4Addr, MacAddr> =
            NeighborTable::new_unbounded(Duration::from_secs(60));
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        let mac_a = MacAddr([1, 2, 3, 4, 5, 6]);
        let mac_b = MacAddr([7, 8, 9, 10, 11, 12]);
        table.observe(ip, mac_a, ts(0));
        let ev = table.observe(ip, mac_b, ts(10));
        assert!(matches!(
            ev,
            NeighborEvent::Changed { prior, new }
                if prior == mac_a && new == mac_b
        ));
        let b = table.peek(&ip, ts(10)).unwrap();
        assert_eq!(b.addr, mac_b);
        assert_eq!(b.prior_addr, Some(mac_a));
        assert_eq!(b.change_count, 1);
        assert_eq!(b.seen_count, 2);
    }

    #[test]
    fn multiple_changes_increment_count() {
        let mut table: NeighborTable<Ipv4Addr, MacAddr> =
            NeighborTable::new_unbounded(Duration::from_secs(60));
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        table.observe(ip, MacAddr([1; 6]), ts(0));
        table.observe(ip, MacAddr([2; 6]), ts(1));
        table.observe(ip, MacAddr([3; 6]), ts(2));
        table.observe(ip, MacAddr([1; 6]), ts(3)); // back to first
        let b = table.peek(&ip, ts(3)).unwrap();
        assert_eq!(b.change_count, 3);
    }

    #[test]
    fn ttl_eviction() {
        let mut table: NeighborTable<Ipv4Addr, MacAddr> =
            NeighborTable::new_unbounded(Duration::from_secs(60));
        table.observe(Ipv4Addr::new(10, 0, 0, 1), MacAddr([1; 6]), ts(0));
        table.observe(Ipv4Addr::new(10, 0, 0, 2), MacAddr([2; 6]), ts(0));
        assert_eq!(table.len(), 2);
        // 120 s later — both are stale (TTL = 60 s).
        table.evict_expired(ts(120));
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn lru_bound_evicts_oldest() {
        let mut table: NeighborTable<Ipv4Addr, MacAddr> =
            NeighborTable::new(Duration::from_secs(60), NonZeroUsize::new(2).unwrap());
        table.observe(Ipv4Addr::new(10, 0, 0, 1), MacAddr([1; 6]), ts(0));
        table.observe(Ipv4Addr::new(10, 0, 0, 2), MacAddr([2; 6]), ts(1));
        // Third insert evicts the LRU entry.
        table.observe(Ipv4Addr::new(10, 0, 0, 3), MacAddr([3; 6]), ts(2));
        assert_eq!(table.len(), 2);
        assert!(table.peek(&Ipv4Addr::new(10, 0, 0, 1), ts(2)).is_none());
    }

    #[cfg(feature = "arp")]
    #[test]
    fn arp_table_alias_works() {
        let mut t: super::ArpTable = NeighborTable::new_unbounded(Duration::from_secs(60));
        t.observe(Ipv4Addr::new(10, 0, 0, 1), MacAddr([1; 6]), ts(0));
        assert_eq!(t.len(), 1);
    }
}

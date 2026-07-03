//! `Inventory` — LRU-bounded MacAddr → Asset store.

use std::num::NonZeroUsize;

use lru::LruCache;

use super::core::Asset;
use crate::{MacAddr, Timestamp};

/// LRU-bounded `MacAddr → Asset` inventory.
///
/// Asset records age out by LRU. Reads via [`Self::get`]
/// don't reorder; only `absorb()` does. That keeps the cache
/// honest about what's recently *contributed to* the
/// inventory, not what's recently *queried* — the operational
/// distinction matters because a dashboard polling every
/// asset every second would otherwise hold every MAC in
/// memory forever.
///
/// `Inventory` is `Send` (the underlying `LruCache` is).
///
/// Issue #27 (0.18).
#[derive(Debug)]
pub struct Inventory {
    cache: LruCache<MacAddr, Asset>,
}

impl Inventory {
    /// Construct with the given max capacity. A capacity of
    /// `0` is treated as `1` (the LRU library disallows
    /// zero).
    pub fn new(capacity: usize) -> Self {
        let cap = NonZeroUsize::new(capacity.max(1)).unwrap();
        Self {
            cache: LruCache::new(cap),
        }
    }

    /// Merge `update` into the existing entry for
    /// `update.mac`, or insert as new. Returns a reference to
    /// the post-merge entry.
    ///
    /// `absorb` is the only mutator that touches LRU order —
    /// callers polling with `get` don't keep stale records
    /// pinned.
    pub fn absorb(&mut self, mut update: Asset) -> &Asset {
        let mac = update.mac;
        if let Some(existing) = self.cache.get_mut(&mac) {
            existing.merge(&update);
            // peek/get already promoted the entry on access.
            // Return a borrow to it; have to re-fetch to avoid
            // borrow-check issues.
        } else {
            // Stamp `last_seen` if the update didn't already.
            if update.last_seen == Timestamp::default() {
                update.last_seen = Timestamp::default();
            }
            self.cache.put(mac, update);
        }
        // Safe: we just inserted-or-updated.
        self.cache.peek(&mac).expect("just inserted")
    }

    /// Insert `update` with an explicit observation timestamp.
    /// Equivalent to setting `update.last_seen = ts` before
    /// `absorb`.
    pub fn absorb_at(&mut self, mut update: Asset, ts: Timestamp) -> &Asset {
        update.last_seen = ts;
        // Stamp first_seen so the record carries a meaningful
        // creation time; merge keeps the earliest across updates.
        if update.first_seen == Timestamp::default() {
            update.first_seen = ts;
        }
        self.absorb(update)
    }

    /// Look up the asset for `mac`. Does NOT promote LRU
    /// order (uses `peek` internally).
    pub fn get(&self, mac: &MacAddr) -> Option<&Asset> {
        self.cache.peek(mac)
    }

    /// Number of assets currently in the inventory.
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// `true` when no assets are recorded.
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Configured capacity (the LRU cap, not the live count).
    pub fn capacity(&self) -> usize {
        self.cache.cap().get()
    }

    /// Iterate the inventory in LRU order (most-recently-
    /// `absorb`'d first). Does not promote.
    pub fn iter(&self) -> impl Iterator<Item = (&MacAddr, &Asset)> {
        self.cache.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asset::AssetSourceSet;

    fn mac(b: u8) -> MacAddr {
        MacAddr([b; 6])
    }

    #[test]
    fn empty_inventory_has_zero_len() {
        let inv = Inventory::new(16);
        assert_eq!(inv.len(), 0);
        assert!(inv.is_empty());
        assert_eq!(inv.capacity(), 16);
    }

    #[test]
    fn capacity_zero_is_treated_as_one() {
        let inv = Inventory::new(0);
        assert_eq!(inv.capacity(), 1);
    }

    #[test]
    fn absorb_inserts_new_record() {
        let mut inv = Inventory::new(4);
        let mut a = Asset::new(mac(1));
        a.seen_via |= AssetSourceSet::ARP;
        let stored = inv.absorb(a);
        assert!(stored.seen_via.contains(AssetSourceSet::ARP));
        assert_eq!(inv.len(), 1);
    }

    #[test]
    fn absorb_merges_two_messages_same_mac() {
        let mut inv = Inventory::new(4);
        let mut a = Asset::new(mac(1));
        a.seen_via |= AssetSourceSet::ARP;
        a.hostname = Some("first".into());
        inv.absorb(a);
        let mut b = Asset::new(mac(1));
        b.seen_via |= AssetSourceSet::DHCP;
        b.hostname = Some("second".into());
        inv.absorb(b);
        assert_eq!(inv.len(), 1, "same MAC merged into one entry");
        let got = inv.get(&mac(1)).unwrap();
        assert!(got.seen_via.contains(AssetSourceSet::ARP));
        assert!(got.seen_via.contains(AssetSourceSet::DHCP));
        // Second hostname wins (last-write).
        assert_eq!(got.hostname.as_deref(), Some("second"));
    }

    #[test]
    fn lru_eviction_drops_oldest() {
        let mut inv = Inventory::new(2);
        inv.absorb(Asset::new(mac(1)));
        inv.absorb(Asset::new(mac(2)));
        inv.absorb(Asset::new(mac(3))); // evicts mac(1)
        assert!(
            inv.get(&mac(1)).is_none(),
            "mac(1) should have been evicted"
        );
        assert!(inv.get(&mac(2)).is_some());
        assert!(inv.get(&mac(3)).is_some());
    }

    #[test]
    fn get_does_not_promote_lru_order() {
        let mut inv = Inventory::new(2);
        inv.absorb(Asset::new(mac(1)));
        inv.absorb(Asset::new(mac(2)));
        // Polling mac(1) repeatedly mustn't keep it alive.
        let _ = inv.get(&mac(1));
        let _ = inv.get(&mac(1));
        inv.absorb(Asset::new(mac(3)));
        assert!(
            inv.get(&mac(1)).is_none(),
            "mac(1) must still be evicted; get does not promote"
        );
    }

    #[test]
    fn absorb_at_stamps_observation_time() {
        let mut inv = Inventory::new(4);
        let ts = Timestamp::new(123, 0);
        inv.absorb_at(Asset::new(mac(1)), ts);
        assert_eq!(inv.get(&mac(1)).unwrap().last_seen, ts);
    }
}

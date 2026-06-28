//! [`BroadcastSlotHandle<M, K>`] — fan-out sibling of
//! [`super::SlotHandle<M, K>`].
//!
//! Where [`SlotHandle`] clones share one MPMC queue (competitive
//! consumer — each message goes to exactly one drainer),
//! [`BroadcastSlotHandle`] clones each own a private queue and
//! every push fans out to all live clones (broadcast — each
//! message goes to every drainer).
//!
//! Plan 150 (0.13).

use std::sync::{Arc, Mutex, Weak};

use crossbeam_queue::SegQueue;

use super::slot::SlotMessage;

/// Per-subscriber broadcast handle. Each [`Clone`] yields a new
/// subscriber with its own private queue; every push to the
/// owning slot fans out to every live subscriber.
///
/// # Comparison with [`super::SlotHandle`]
///
/// | Aspect             | `SlotHandle`        | `BroadcastSlotHandle` |
/// |--------------------|---------------------|-----------------------|
/// | Clone semantics    | Competitive consumer (MPMC) | Broadcast (every clone sees every message) |
/// | Per-push cost      | O(1) atomic         | O(subscribers) clones + pushes |
/// | `M` bound          | `Send`              | `Send + Clone` |
/// | Memory per subscriber | Shares one queue | One private queue each |
///
/// # Drop semantics
///
/// Dropping a subscriber removes its queue from the broadcast
/// set on the next push (best-effort prune via
/// [`Weak::upgrade`]). Slow subscribers' queues grow until
/// they're drained or dropped — bound externally via
/// [`Self::drain_n`] from plan 149.
#[must_use = "drop the BroadcastSlotHandle and this subscriber never sees the parser's messages — keep it and drain it"]
pub struct BroadcastSlotHandle<M, K>
where
    M: Send + Sync + Clone + 'static,
    K: Send + Sync + Clone + 'static,
{
    inner: Arc<BroadcastInner<M, K>>,
    my_queue: SubscriberQueue<M, K>,
    parser_kind: &'static str,
}

/// Per-subscriber queue handle held in the broadcast list.
/// Strong-owned by each [`BroadcastSlotHandle`]; downgraded to
/// `Weak` in the shared subscriber registry.
pub(crate) type SubscriberQueue<M, K> = Arc<SegQueue<SlotMessage<M, K>>>;

/// Weak handle to a subscriber's queue. Kept in the registry so
/// dropped subscribers prune lazily on next push.
pub(crate) type SubscriberWeak<M, K> = Weak<SegQueue<SlotMessage<M, K>>>;

/// Shared state between all `BroadcastSlotHandle` clones + the
/// owning slot. The slot pushes by upgrading `Weak`s; subscribers
/// drain their `my_queue` directly.
pub(crate) struct BroadcastInner<M, K>
where
    M: Send + Sync + Clone + 'static,
    K: Send + Sync + Clone + 'static,
{
    pub(crate) subscribers: Mutex<Vec<SubscriberWeak<M, K>>>,
}

impl<M, K> BroadcastInner<M, K>
where
    M: Send + Sync + Clone + 'static,
    K: Send + Sync + Clone + 'static,
{
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            subscribers: Mutex::new(Vec::new()),
        })
    }

    /// Push one message; fan out to every live subscriber.
    /// Dead subscribers (Weak::upgrade returns None) are pruned
    /// inline.
    ///
    /// Cost: one mutex lock + (live_subscribers) clones + pushes.
    /// For the zero-subscriber case this is just a lock acquire
    /// (no clone, no push) — allocation-free.
    pub(crate) fn push(&self, msg: SlotMessage<M, K>) {
        let mut subs = self.subscribers.lock().expect("broadcast lock poisoned");
        subs.retain(|w| {
            if let Some(q) = w.upgrade() {
                q.push(msg.clone());
                true
            } else {
                false
            }
        });
    }

    /// Register a fresh subscriber. Returns the new private
    /// queue; caller stores the `Arc` in their handle and pushes
    /// a `Weak` into the subscriber list.
    pub(crate) fn subscribe(self: &Arc<Self>) -> SubscriberQueue<M, K> {
        let q = Arc::new(SegQueue::new());
        self.subscribers
            .lock()
            .expect("broadcast lock poisoned")
            .push(Arc::downgrade(&q));
        q
    }
}

impl<M, K> BroadcastSlotHandle<M, K>
where
    M: Send + Sync + Clone + 'static,
    K: Send + Sync + Clone + 'static,
{
    /// Internal constructor for the typed slot. Public only via
    /// the broadcast registration builders.
    pub(crate) fn new(inner: Arc<BroadcastInner<M, K>>, parser_kind: &'static str) -> Self {
        let my_queue = inner.subscribe();
        Self {
            inner,
            my_queue,
            parser_kind,
        }
    }

    /// Drain every message this subscriber has received since
    /// the last call, into `out`. Returns the count.
    pub fn drain(&mut self, out: &mut Vec<SlotMessage<M, K>>) -> usize {
        let mut n = 0;
        while let Some(msg) = self.my_queue.pop() {
            out.push(msg);
            n += 1;
        }
        n
    }

    /// Bounded variant — drain at most `max` messages.
    pub fn drain_n(&mut self, out: &mut Vec<SlotMessage<M, K>>, max: usize) -> usize {
        let mut n = 0;
        while n < max
            && let Some(msg) = self.my_queue.pop()
        {
            out.push(msg);
            n += 1;
        }
        n
    }

    /// Pending message count for this subscriber.
    pub fn pending(&self) -> usize {
        self.my_queue.len()
    }

    /// Active subscriber count across the broadcast set
    /// (best-effort; read under a lock).
    pub fn subscribers(&self) -> usize {
        self.inner
            .subscribers
            .lock()
            .map(|s| s.iter().filter(|w| w.strong_count() > 0).count())
            .unwrap_or(0)
    }

    /// Parser-kind slug from registration.
    pub fn parser_kind(&self) -> &'static str {
        self.parser_kind
    }
}

impl<M, K> super::SlotDrain<M, K> for BroadcastSlotHandle<M, K>
where
    M: Send + Sync + Clone + 'static,
    K: Send + Sync + Clone + 'static,
{
    fn drain(&mut self, out: &mut Vec<SlotMessage<M, K>>) -> usize {
        BroadcastSlotHandle::drain(self, out)
    }
    fn drain_n(&mut self, out: &mut Vec<SlotMessage<M, K>>, max: usize) -> usize {
        BroadcastSlotHandle::drain_n(self, out, max)
    }
    fn pending(&self) -> usize {
        BroadcastSlotHandle::pending(self)
    }
    fn parser_kind(&self) -> &'static str {
        BroadcastSlotHandle::parser_kind(self)
    }
}

impl<M, K> Clone for BroadcastSlotHandle<M, K>
where
    M: Send + Sync + Clone + 'static,
    K: Send + Sync + Clone + 'static,
{
    /// New subscriber: gets its own queue inside the broadcast
    /// set. Subsequent pushes go to every live queue. The new
    /// subscriber sees only messages pushed AFTER this clone
    /// call (no replay of earlier pushes).
    fn clone(&self) -> Self {
        Self::new(Arc::clone(&self.inner), self.parser_kind)
    }
}

impl<M, K> std::fmt::Debug for BroadcastSlotHandle<M, K>
where
    M: Send + Sync + Clone + 'static,
    K: Send + Sync + Clone + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BroadcastSlotHandle")
            .field("parser_kind", &self.parser_kind)
            .field("pending", &self.pending())
            .field("subscribers", &self.subscribers())
            .finish()
    }
}

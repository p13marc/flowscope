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
use crate::parser_kind::ParserKind;

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
    parser_kind: ParserKind,
    slot: crate::SlotId,
}

/// One subscriber's private queue plus the waker of a task waiting
/// on it ([`BroadcastSlotHandle::poll_recv`]).
pub(crate) struct Subscriber<M, K> {
    queue: SegQueue<SlotMessage<M, K>>,
    waker: Mutex<Option<std::task::Waker>>,
}

impl<M, K> Subscriber<M, K> {
    fn push(&self, msg: SlotMessage<M, K>) {
        self.queue.push(msg);
        if let Some(w) = self.waker.lock().ok().and_then(|mut w| w.take()) {
            w.wake();
        }
    }
}

/// Per-subscriber queue handle held in the broadcast list.
/// Strong-owned by each [`BroadcastSlotHandle`]; downgraded to
/// `Weak` in the shared subscriber registry.
pub(crate) type SubscriberQueue<M, K> = Arc<Subscriber<M, K>>;

/// Weak handle to a subscriber's queue. Kept in the registry so
/// dropped subscribers prune lazily on next push.
pub(crate) type SubscriberWeak<M, K> = Weak<Subscriber<M, K>>;

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
        let q = Arc::new(Subscriber {
            queue: SegQueue::new(),
            waker: Mutex::new(None),
        });
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
    pub(crate) fn new(
        inner: Arc<BroadcastInner<M, K>>,
        parser_kind: ParserKind,
        slot: crate::SlotId,
    ) -> Self {
        let my_queue = inner.subscribe();
        Self {
            inner,
            my_queue,
            parser_kind,
            slot,
        }
    }

    /// Drain every message this subscriber has received since
    /// the last call, into `out`. Returns the count.
    pub fn drain(&mut self, out: &mut Vec<SlotMessage<M, K>>) -> usize {
        let mut n = 0;
        while let Some(msg) = self.my_queue.queue.pop() {
            out.push(msg);
            n += 1;
        }
        n
    }

    /// Bounded variant — drain at most `max` messages.
    pub fn drain_n(&mut self, out: &mut Vec<SlotMessage<M, K>>, max: usize) -> usize {
        let mut n = 0;
        while n < max
            && let Some(msg) = self.my_queue.queue.pop()
        {
            out.push(msg);
            n += 1;
        }
        n
    }

    /// Next message for this subscriber, if one is queued.
    pub fn try_recv(&mut self) -> Option<SlotMessage<M, K>> {
        self.my_queue.queue.pop()
    }

    /// Async receive: `Ready(msg)` when a message is queued,
    /// otherwise `Pending` with `cx`'s waker registered — the next
    /// push to this subscriber wakes it. The building block of a
    /// `Stream` over the handle. New in 0.25.0.
    pub fn poll_recv(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<SlotMessage<M, K>> {
        if let Some(msg) = self.my_queue.queue.pop() {
            return std::task::Poll::Ready(msg);
        }
        if let Ok(mut w) = self.my_queue.waker.lock() {
            *w = Some(cx.waker().clone());
        }
        // A push between the pop and the registration would
        // otherwise be missed.
        match self.my_queue.queue.pop() {
            Some(msg) => std::task::Poll::Ready(msg),
            None => std::task::Poll::Pending,
        }
    }

    /// Pending message count for this subscriber.
    pub fn pending(&self) -> usize {
        self.my_queue.queue.len()
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

    /// Parser-kind identity from registration.
    pub fn parser_kind(&self) -> ParserKind {
        self.parser_kind
    }

    /// This parser's registration identity (see
    /// [`crate::driver::SlotHandle::slot_id`]). New in 0.25.0.
    pub fn slot_id(&self) -> crate::SlotId {
        self.slot
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
    fn parser_kind(&self) -> ParserKind {
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
        Self::new(Arc::clone(&self.inner), self.parser_kind, self.slot)
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

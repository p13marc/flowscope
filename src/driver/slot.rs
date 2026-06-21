//! Typed slot drain handles for the [`super::typed::Driver`].
//!
//! Plan 121 architecture. Each registered parser gets its own
//! typed `SlotHandle<M, K>` at builder time. Per packet, the
//! driver's `track_into` emits flow-lifecycle events (no `M`
//! parameter on the event type); per-parser typed messages
//! land in the slot's internal queue, drained by the consumer
//! through `SlotHandle::drain`.
//!
//! Plan 122: the backing store is `Arc<crossbeam_queue::SegQueue<…>>`
//! (lock-free MPMC). `SlotHandle<M, K>` is `Send + Sync` so the
//! handle can be moved/cloned across threads — drain inside a
//! tokio task while the driver runs on a dedicated capture
//! thread, or fan out from one shard's driver to multiple
//! consumer threads.

use std::sync::Arc;

use crossbeam_queue::SegQueue;

use crate::Timestamp;
use crate::event::FlowSide;

/// One typed message emitted by a registered parser.
///
/// The queue behind the `SlotHandle` holds these directly; the
/// `key` and `side` are the flow's metadata at the moment the
/// parser produced the message.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SlotMessage<M, K> {
    pub key: K,
    pub side: FlowSide,
    pub message: M,
    pub ts: Timestamp,
}

/// Typed drain handle returned by the builder for each
/// registered parser. The slot pushes and the handle drains
/// — both share the same `Arc<SegQueue>`.
///
/// **`Send + Sync`** — move the handle across threads, drain
/// from a tokio task on another core, share via Arc with
/// multiple drainers. Since 0.13 the whole `Driver<E>` is also
/// `Send + Sync`, so the common pattern is to `tokio::spawn` the
/// driver task on the default multi-thread runtime and drain
/// the handle from anywhere.
///
/// # Cloning semantics
///
/// `Clone` hands out a second **competitive consumer** — both
/// drain from the same `SegQueue` and race for messages. The
/// sum across all clones equals the number of messages pushed,
/// matching MPMC semantics. For broadcast (every consumer sees
/// every message), drain into a channel and fan out yourself.
pub struct SlotHandle<M, K>
where
    M: Send + 'static,
    K: Send + 'static,
{
    pub(super) inner: Arc<SegQueue<SlotMessage<M, K>>>,
    pub(super) parser_kind: &'static str,
}

impl<M, K> SlotHandle<M, K>
where
    M: Send + 'static,
    K: Send + 'static,
{
    /// Drain all currently-queued messages into `out`, reusing
    /// `out`'s capacity. Returns the number drained.
    ///
    /// Per-pop cost is ~10-15 ns on uncontended `SegQueue`;
    /// at the typical netring drain cadence (0-2 messages per
    /// `track_into` call) the difference vs a `Vec` batch-move
    /// is invisible. Bulk drains with hundreds of pending
    /// messages will see the O(n) pop loop.
    pub fn drain(&mut self, out: &mut Vec<SlotMessage<M, K>>) -> usize {
        let mut n = 0;
        while let Some(msg) = self.inner.pop() {
            out.push(msg);
            n += 1;
        }
        n
    }

    /// Drain at most `max` queued messages into `out`. Returns
    /// the number actually drained.
    ///
    /// Bounded variant of [`drain`](Self::drain). Use when:
    ///
    /// - The consumer wants explicit back-pressure (drop the
    ///   rest if downstream can't keep up).
    /// - Drain cadence is unpredictable — one shard's drain
    ///   shouldn't monopolise a CPU when another shard has
    ///   packets waiting.
    ///
    /// `max = 0` is a valid no-op that returns 0 without
    /// touching the queue. `max = usize::MAX` is behaviourally
    /// identical to [`drain`](Self::drain).
    ///
    /// Plan 149 (0.13).
    pub fn drain_n(&mut self, out: &mut Vec<SlotMessage<M, K>>, max: usize) -> usize {
        let mut n = 0;
        while n < max
            && let Some(msg) = self.inner.pop()
        {
            out.push(msg);
            n += 1;
        }
        n
    }

    /// Clear `out` and drain all queued messages into it in
    /// one call. Eliminates the `out.clear(); slot.drain(&mut
    /// out);` two-step that every per-packet drain loop ends
    /// up writing. Returns the number drained.
    ///
    /// Equivalent to:
    ///
    /// ```ignore
    /// out.clear();
    /// let n = slot.drain(&mut out);
    /// ```
    ///
    /// but reads at the call site as the single thing it is.
    ///
    /// New in 0.18.
    pub fn drain_replacing(&mut self, out: &mut Vec<SlotMessage<M, K>>) -> usize {
        out.clear();
        self.drain(out)
    }

    /// Approximate message count currently in the queue. Cheap
    /// inspection; result may be slightly stale under
    /// concurrent push/pop.
    pub fn pending(&self) -> usize {
        self.inner.len()
    }

    /// Parser kind identifier (from
    /// [`crate::SessionParser::parser_kind`] /
    /// [`crate::DatagramParser::parser_kind`]).
    pub fn parser_kind(&self) -> &'static str {
        self.parser_kind
    }

    /// Discard any buffered messages without draining them.
    /// Useful between test runs.
    pub fn clear(&mut self) {
        while self.inner.pop().is_some() {}
    }
}

impl<M, K> Clone for SlotHandle<M, K>
where
    M: Send + 'static,
    K: Send + 'static,
{
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            parser_kind: self.parser_kind,
        }
    }
}

impl<M, K> std::fmt::Debug for SlotHandle<M, K>
where
    M: Send + 'static,
    K: Send + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlotHandle")
            .field("parser_kind", &self.parser_kind)
            .field("pending", &self.pending())
            .finish()
    }
}

// Send + Sync follow automatically from the field types:
//   Arc<T>:        Send + Sync where T: Send + Sync
//   SegQueue<T>:   Send + Sync where T: Send
//   SlotMessage<M, K>: Send + Sync where M, K: Send + Sync
// The bounds on the impl block (`M: Send + 'static, K: Send +
// 'static`) provide the necessary `Send` constraint; the auto
// traits flow through.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_handle_drain_basic() {
        let queue = Arc::new(SegQueue::<SlotMessage<u32, u8>>::new());
        let mut handle = SlotHandle::<u32, u8> {
            inner: Arc::clone(&queue),
            parser_kind: "test",
        };
        assert_eq!(handle.pending(), 0);
        queue.push(SlotMessage {
            key: 1,
            side: FlowSide::Initiator,
            message: 100,
            ts: Timestamp::default(),
        });
        queue.push(SlotMessage {
            key: 2,
            side: FlowSide::Responder,
            message: 200,
            ts: Timestamp::default(),
        });
        assert_eq!(handle.pending(), 2);

        let mut out = Vec::new();
        let n = handle.drain(&mut out);
        assert_eq!(n, 2);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].message, 100);
        assert_eq!(out[1].message, 200);
        assert_eq!(handle.pending(), 0);

        let mut out2 = Vec::new();
        let n2 = handle.drain(&mut out2);
        assert_eq!(n2, 0);
        assert!(out2.is_empty());
    }

    #[test]
    fn slot_handle_clear_drops_pending() {
        let queue = Arc::new(SegQueue::<SlotMessage<&'static str, u8>>::new());
        let mut handle = SlotHandle::<&'static str, u8> {
            inner: Arc::clone(&queue),
            parser_kind: "test",
        };
        queue.push(SlotMessage {
            key: 1,
            side: FlowSide::Initiator,
            message: "x",
            ts: Timestamp::default(),
        });
        assert_eq!(handle.pending(), 1);
        handle.clear();
        assert_eq!(handle.pending(), 0);
    }

    #[test]
    fn slot_handle_clone_is_competitive_consumer() {
        let queue = Arc::new(SegQueue::<SlotMessage<u32, u8>>::new());
        let mut h1 = SlotHandle::<u32, u8> {
            inner: Arc::clone(&queue),
            parser_kind: "test",
        };
        let mut h2 = h1.clone();
        for i in 0..10 {
            queue.push(SlotMessage {
                key: 1,
                side: FlowSide::Initiator,
                message: i,
                ts: Timestamp::default(),
            });
        }
        let mut a = Vec::new();
        let mut b = Vec::new();
        h1.drain(&mut a);
        h2.drain(&mut b);
        // Sum is exactly 10 (no broadcast, no duplicate delivery).
        assert_eq!(a.len() + b.len(), 10);
    }

    #[test]
    fn slot_handle_is_send_and_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<SlotHandle<u32, u8>>();
        assert_sync::<SlotHandle<u32, u8>>();
    }
}

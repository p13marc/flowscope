//! Typed slot drain handles for the [`super::next::Driver`].
//!
//! Plan 121 architecture. Each registered parser gets its own
//! typed `SlotHandle<M, K>` at builder time. Per packet, the
//! driver's `track_into` emits flow-lifecycle events (no `M`
//! parameter on the event type); per-parser typed messages
//! land in the slot's internal buffer, drained by the consumer
//! through `SlotHandle::drain`.
//!
//! This replaces the closed-`M` sum-type shape on
//! `super::Driver<E, M>` where every slot has to lift its
//! `P::Message` into a single composite `M` via a lift closure.
//! The closed shape is incompatible with netring's zero-allocation
//! `monitor.protocol::<P>()` pattern; the typed-handle shape is
//! what that pattern needs.

use std::cell::RefCell;
use std::rc::Rc;

use crate::Timestamp;
use crate::event::FlowSide;

/// One typed message emitted by a registered parser.
///
/// The buffer behind the `SlotHandle` holds these directly; the
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

/// Internal: shared buffer that the slot (writer) and the
/// [`SlotHandle`] (drainer) both reference via `Rc<RefCell<…>>`.
pub(super) struct SlotBuf<M, K> {
    pub(super) queue: Vec<SlotMessage<M, K>>,
}

impl<M, K> SlotBuf<M, K> {
    pub(super) fn new() -> Self {
        Self { queue: Vec::new() }
    }
}

/// Typed drain handle returned by the builder for each
/// registered parser. The handle and the slot share a
/// `Rc<RefCell<SlotBuf>>` so the slot can push and the handle
/// can drain.
///
/// **Not `Send`** — single-threaded by design (matches netring's
/// pattern of draining inside the event loop and posting via
/// channels for cross-task delivery).
pub struct SlotHandle<M, K>
where
    M: 'static,
    K: 'static,
{
    pub(super) inner: Rc<RefCell<SlotBuf<M, K>>>,
    pub(super) parser_kind: &'static str,
}

impl<M, K> SlotHandle<M, K>
where
    M: 'static,
    K: 'static,
{
    /// Drain buffered messages into `out`, reusing `out`'s
    /// capacity. Returns the number drained.
    pub fn drain(&mut self, out: &mut Vec<SlotMessage<M, K>>) -> usize {
        let mut buf = self.inner.borrow_mut();
        let n = buf.queue.len();
        if n == 0 {
            return 0;
        }
        out.append(&mut buf.queue);
        n
    }

    /// Number of messages currently buffered. Cheap inspection.
    pub fn pending(&self) -> usize {
        self.inner.borrow().queue.len()
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
        self.inner.borrow_mut().queue.clear();
    }
}

impl<M, K> Clone for SlotHandle<M, K>
where
    M: 'static,
    K: 'static,
{
    fn clone(&self) -> Self {
        Self {
            inner: Rc::clone(&self.inner),
            parser_kind: self.parser_kind,
        }
    }
}

impl<M, K> std::fmt::Debug for SlotHandle<M, K>
where
    M: 'static,
    K: 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlotHandle")
            .field("parser_kind", &self.parser_kind)
            .field("pending", &self.pending())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_handle_drain_basic() {
        let buf = Rc::new(RefCell::new(SlotBuf::<u32, u8>::new()));
        let mut handle = SlotHandle::<u32, u8> {
            inner: Rc::clone(&buf),
            parser_kind: "test",
        };
        assert_eq!(handle.pending(), 0);
        // Slot writer (simulated) pushes a couple of messages.
        buf.borrow_mut().queue.push(SlotMessage {
            key: 1,
            side: FlowSide::Initiator,
            message: 100,
            ts: Timestamp::default(),
        });
        buf.borrow_mut().queue.push(SlotMessage {
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

        // Second drain on empty buffer is a no-op.
        let mut out2 = Vec::new();
        let n2 = handle.drain(&mut out2);
        assert_eq!(n2, 0);
        assert!(out2.is_empty());
    }

    #[test]
    fn slot_handle_clear_drops_pending() {
        let buf = Rc::new(RefCell::new(SlotBuf::<&'static str, u8>::new()));
        let mut handle = SlotHandle::<&'static str, u8> {
            inner: Rc::clone(&buf),
            parser_kind: "test",
        };
        buf.borrow_mut().queue.push(SlotMessage {
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
    fn slot_handle_drain_reuses_capacity() {
        let buf = Rc::new(RefCell::new(SlotBuf::<u32, u8>::new()));
        let mut handle = SlotHandle::<u32, u8> {
            inner: Rc::clone(&buf),
            parser_kind: "test",
        };
        let mut out: Vec<SlotMessage<u32, u8>> = Vec::with_capacity(32);
        let initial_cap = out.capacity();
        for _ in 0..10 {
            buf.borrow_mut().queue.push(SlotMessage {
                key: 1,
                side: FlowSide::Initiator,
                message: 0,
                ts: Timestamp::default(),
            });
        }
        handle.drain(&mut out);
        assert_eq!(out.len(), 10);
        out.clear();
        // Capacity preserved across clear.
        assert_eq!(out.capacity(), initial_cap);
    }
}

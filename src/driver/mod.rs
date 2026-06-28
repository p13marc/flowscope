//! `flowscope::driver` — the typed `Driver<E>` + `SlotHandle<M, K>`
//! shape (plan 121).
//!
//! ```ignore
//! use flowscope::driver::{Driver, Event, SlotMessage};
//! use flowscope::extract::{FiveTuple, FiveTupleKey};
//! use flowscope::http::{HttpMessage, HttpParser};
//!
//! let mut builder = Driver::builder(FiveTuple::bidirectional());
//! let mut http_slot = builder.session_on_ports(HttpParser::default(), [80, 8080]);
//! let mut driver = builder.build();
//!
//! let mut events: Vec<Event<FiveTupleKey>> = Vec::new();
//! let mut http_msgs: Vec<SlotMessage<HttpMessage, FiveTupleKey>> = Vec::new();
//!
//! // driver.track_into(view, &mut events);
//! // http_slot.drain(&mut http_msgs);
//! ```
//!
//! ## Architecture
//!
//! - [`Driver<E>`] owns a central [`crate::FlowTracker`] for flow
//!   lifecycle + per-parser slots that own their inner
//!   session/datagram drivers.
//! - Each `.session_*` / `.datagram_*` builder call returns a
//!   typed [`SlotHandle<M, K>`]; the slot's typed messages flow
//!   into the handle's internal buffer via a shared
//!   `Arc<crossbeam_queue::SegQueue<_>>`.
//! - Per-packet: `driver.track_into(view, &mut events)` emits
//!   flow-lifecycle events; `slot.drain(&mut msgs)` drains the
//!   typed messages produced this packet.
//! - Zero-allocation in steady state across the full dispatch
//!   path including registered slots.
//!
//! Plan 122 (0.12): `SlotHandle<M, K>` is `Send + Sync` (backed
//! by `Arc<crossbeam_queue::SegQueue>`). Move the handle to a
//! worker thread, share via `Arc` with multiple drainers, drain
//! from a tokio task on another core.
//!
//! Plan 156 (0.13): the driver itself (`Driver<E>`) is also
//! `Send + Sync`. The 0.12 docs claimed otherwise on the basis
//! that `FlowTracker` used `Rc<RefCell>` interior mutability;
//! this was never true — the actual `!Send` source was a
//! missing `+ Send` bound on the `Box<dyn ErasedSlot<_>>` slot
//! list. Tightening that bound (no `unsafe`, no opt-in knob)
//! makes the whole driver Send+Sync. The 0.13 typical pattern
//! is `tokio::spawn(driver_task)` on the default multi-thread
//! runtime.

mod broadcast;
mod slot;
mod typed;
mod typed_slot;
mod typed_slot_heuristic;

pub use broadcast::BroadcastSlotHandle;
pub use slot::{SlotHandle, SlotMessage};
pub use typed::{Driver, DriverBuilder, Event};
pub use typed_slot_heuristic::{DEFAULT_PROBE_PACKETS, PROBE_BUFFER_CAP};

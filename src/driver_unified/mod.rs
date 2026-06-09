//! `flowscope::driver_unified` — the typed `Driver<E>` +
//! `SlotHandle<M, K>` shape (plan 121).
//!
//! Build via [`typed::Driver::builder`]:
//!
//! ```ignore
//! use flowscope::driver_unified::SlotMessage;
//! use flowscope::driver_unified::typed::{Driver, Event};
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
//! - `Driver<E>` owns a central [`crate::FlowTracker`] for flow
//!   lifecycle + per-parser slots that own their inner
//!   session/datagram drivers.
//! - Each `.session_*` / `.datagram_*` builder call returns a
//!   typed [`SlotHandle<M, K>`]; the slot's typed messages flow
//!   into the handle's internal buffer via shared
//!   `Rc<RefCell<…>>`.
//! - Per-packet: `driver.track_into(view, &mut events)` emits
//!   flow-lifecycle events; `slot.drain(&mut msgs)` drains the
//!   typed messages produced this packet.
//! - Zero-allocation in steady state across the full dispatch
//!   path including registered slots.
//!
//! Single-threaded by design — the slot bufs are `Rc<RefCell>`,
//! not `Arc<Mutex>`. For cross-task delivery, drain inside the
//! event loop and post through a channel.

mod slot;
pub mod typed;
mod typed_slot;
mod typed_slot_heuristic;

pub use slot::{SlotHandle, SlotMessage};
pub use typed_slot_heuristic::{DEFAULT_PROBE_PACKETS, PROBE_BUFFER_CAP};

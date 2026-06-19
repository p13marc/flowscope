//! `flowscope::correlate` — generic helpers for cross-flow
//! correlation patterns.
//!
//! Three small, composable primitives that consumers stitch into
//! detectors:
//!
//! - [`TimeBucketedCounter`] — windowed rate counting per key
//!   (DDoS rate-limits, SYN-flood thresholds, "did key K cross N
//!   in W seconds").
//! - [`KeyIndexed`] — TTL'd LRU cache with monotonic-timestamp
//!   eviction (DNS query/response correlation, ICMP error tying
//!   back to original flow, generic request/response matching).
//! - [`SequencePattern`] / [`KeylessSequencePattern`] — generic
//!   FSM trait for event-stream pattern detectors (port scans,
//!   "auth failure → success", retry storms).
//!
//! These are tracker-clock aware: `now: Timestamp` is the packet
//! timestamp, not wall clock, so live and offline pipelines
//! produce identical detector output for identical inputs.
//!
//! # Quick start: bucketed counter
//!
//! ```
//! use flowscope::correlate::TimeBucketedCounter;
//! use flowscope::Timestamp;
//! use std::time::Duration;
//!
//! let mut c: TimeBucketedCounter<u32> =
//!     TimeBucketedCounter::new(Duration::from_secs(60), Duration::from_secs(10), 1024);
//!
//! c.bump(42, Timestamp::new(0, 0));
//! c.bump(42, Timestamp::new(1, 0));
//! c.bump(42, Timestamp::new(2, 0));
//! assert_eq!(c.count(&42, Timestamp::new(3, 0)), 3);
//! ```
//!
//! # Quick start: KeyIndexed
//!
//! ```
//! use flowscope::correlate::KeyIndexed;
//! use flowscope::Timestamp;
//! use std::time::Duration;
//!
//! let mut q: KeyIndexed<u16, String> = KeyIndexed::new(Duration::from_secs(5), 1024);
//! q.insert(0x1234, "example.com".to_string(), Timestamp::new(0, 0));
//! assert_eq!(q.get(&0x1234, Timestamp::new(1, 0)).map(|s| s.as_str()), Some("example.com"));
//!
//! // Past TTL — entry is logically expired.
//! q.evict_expired(Timestamp::new(10, 0));
//! assert!(q.get(&0x1234, Timestamp::new(10, 0)).is_none());
//! ```

mod bucketed;
mod burst;
mod ewma;
mod neighbor_table;
mod rolling_rate;
// FlowStateMap defaults its key type to `crate::extract::FiveTupleKey`,
// which only exists under the `extractors` feature. Gate the module
// here so consumers running with `--no-default-features` (no extractors)
// still get the rest of `correlate`.
#[cfg(feature = "extractors")]
mod flow_state_map;
mod indexed;
mod sequence;
mod set;
mod topk;

pub use bucketed::TimeBucketedCounter;
pub use burst::{BurstDetector, BurstHit};
pub use ewma::Ewma;
#[cfg(feature = "extractors")]
pub use flow_state_map::FlowStateMap;
pub use indexed::KeyIndexed;
#[cfg(feature = "arp")]
pub use neighbor_table::ArpTable;
pub use neighbor_table::{NeighborBinding, NeighborEvent, NeighborTable};
pub use rolling_rate::{RateValue, RollingRate};
pub use sequence::{KeylessSequencePattern, SequencePattern};
pub use set::TimeBucketedSet;
pub use topk::TopK;

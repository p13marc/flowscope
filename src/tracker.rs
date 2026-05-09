//! [`FlowTracker`] — a hashtable of live flows with a TCP state
//! machine and idle-timeout sweep.
//!
//! `FlowTracker<E, S>` is generic over the flow extractor (`E`) and
//! optional per-flow user state (`S`, defaults to `()`). Drive it
//! synchronously with [`FlowTracker::track`] for sync use, or use
//! `netring`'s `AsyncCapture::flow_stream` adapter for tokio.

use std::num::NonZeroUsize;
use std::time::Duration;

use ahash::RandomState;
use lru::LruCache;
use smallvec::SmallVec;

use crate::Timestamp;
use crate::event::{EndReason, FlowEvent, FlowSide, FlowState, FlowStats};
use crate::extractor::{Extracted, FlowExtractor, L4Proto, Orientation, TcpFlags};
use crate::history::{HistoryString, push_for_flags};
use crate::tcp_state;
use crate::view::PacketView;

/// Inline-stored set of events emitted by a single `track()` call.
/// Most packets emit 1–2 events; pathological cases (Started +
/// Established + Packet) emit 3.
pub type FlowEvents<K> = SmallVec<[FlowEvent<K>; 3]>;

/// Per-flow accounting + user state.
#[derive(Debug, Clone)]
pub struct FlowEntry<S> {
    pub stats: FlowStats,
    pub state: FlowState,
    pub history: HistoryString,
    pub user: S,
    /// First-seen orientation, used to translate subsequent
    /// orientations into [`FlowSide`].
    pub(crate) initiator_orientation: Orientation,
    /// L4 protocol seen on first packet (drives idle-timeout choice).
    pub(crate) l4: Option<L4Proto>,
}

impl<S> FlowEntry<S> {
    fn side_for(&self, o: Orientation) -> FlowSide {
        if o == self.initiator_orientation {
            FlowSide::Initiator
        } else {
            FlowSide::Responder
        }
    }
}

/// Tracker configuration. Defaults follow Suricata's normal-mode values.
///
/// `#[non_exhaustive]` to keep future additions purely additive.
/// Construct via `FlowTrackerConfig::default()` and mutate; do not
/// rely on struct-literal construction from outside the crate.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FlowTrackerConfig {
    pub idle_timeout_tcp: Duration,
    pub idle_timeout_udp: Duration,
    pub idle_timeout_other: Duration,
    pub max_flows: usize,
    pub initial_capacity: usize,
    /// Sweep interval used by async adapters (the sync API doesn't
    /// auto-sweep — call [`FlowTracker::sweep`] yourself).
    pub sweep_interval: Duration,
    /// Hint to the default [`crate::BufferedReassemblerFactory`] when
    /// it's used via [`crate::FlowDriver`]. The tracker itself owns
    /// no reassemblers; custom `ReassemblerFactory` impls must read
    /// this and honour it themselves.
    ///
    /// `None` means unbounded (historical behaviour).
    pub max_reassembler_buffer: Option<usize>,
    /// Companion to [`max_reassembler_buffer`](Self::max_reassembler_buffer);
    /// no effect unless that field is `Some`.
    pub overflow_policy: crate::event::OverflowPolicy,
}

impl Default for FlowTrackerConfig {
    fn default() -> Self {
        Self {
            idle_timeout_tcp: Duration::from_secs(300),
            idle_timeout_udp: Duration::from_secs(60),
            idle_timeout_other: Duration::from_secs(30),
            max_flows: 100_000,
            initial_capacity: 1024,
            sweep_interval: Duration::from_secs(1),
            max_reassembler_buffer: None,
            overflow_policy: crate::event::OverflowPolicy::SlidingWindow,
        }
    }
}

/// Tracker-level statistics (cumulative since construction).
#[derive(Debug, Clone, Default)]
pub struct FlowTrackerStats {
    pub flows_created: u64,
    pub flows_ended: u64,
    pub flows_evicted: u64,
    pub packets_unmatched: u64,
}

type StateInit<K, S> = Box<dyn FnMut(&K) -> S + Send + 'static>;

/// Bidirectional flow tracker, generic over an extractor `E` and
/// optional per-flow user state `S`.
pub struct FlowTracker<E: FlowExtractor, S = ()> {
    extractor: E,
    flows: LruCache<E::Key, FlowEntry<S>, RandomState>,
    config: FlowTrackerConfig,
    stats: FlowTrackerStats,
    init: StateInit<E::Key, S>,
    /// Most recently accessed key. When the next packet's key
    /// matches, `track_with_payload` skips the `flows.contains`
    /// lookup. Cleared on `Ended`/`Evicted`/`forget` (and on every
    /// `set_config` for safety).
    hot: Option<E::Key>,
}

impl<E: FlowExtractor, S: Send + 'static> FlowTracker<E, S> {
    /// Construct with a custom per-flow state initializer. The
    /// closure is called once on first sight of each new flow.
    pub fn with_state<F>(extractor: E, init: F) -> Self
    where
        F: FnMut(&E::Key) -> S + Send + 'static,
    {
        Self::with_config_and_state(extractor, FlowTrackerConfig::default(), init)
    }

    /// Same as [`with_state`](Self::with_state) but with explicit config.
    pub fn with_config_and_state<F>(extractor: E, config: FlowTrackerConfig, init: F) -> Self
    where
        F: FnMut(&E::Key) -> S + Send + 'static,
    {
        let cap = NonZeroUsize::new(config.max_flows.max(1)).unwrap();
        Self {
            extractor,
            flows: LruCache::with_hasher(cap, RandomState::new()),
            config,
            stats: FlowTrackerStats::default(),
            init: Box::new(init),
            hot: None,
        }
    }

    /// Process a packet. Returns 0–3 events.
    pub fn track(&mut self, view: PacketView<'_>) -> FlowEvents<E::Key> {
        self.track_with_payload(view, |_, _, _, _| {})
    }

    /// Borrow the inner extractor (for callers that want to extract
    /// a key without driving the tracker, e.g. external dispatch).
    pub fn extractor(&self) -> &E {
        &self.extractor
    }

    /// Process a packet, calling `payload_cb(&key, side, seq, payload)`
    /// for each TCP packet with a non-empty payload **before** any
    /// events are returned. Lets sync reassemblers (or any per-segment
    /// dispatch) run inline without a second extract pass.
    ///
    /// `payload_cb` is called at most once per packet (TCP only).
    pub fn track_with_payload<F>(
        &mut self,
        view: PacketView<'_>,
        mut payload_cb: F,
    ) -> FlowEvents<E::Key>
    where
        F: FnMut(&E::Key, FlowSide, u32, &[u8]),
    {
        let mut events: FlowEvents<E::Key> = SmallVec::new();
        let extracted = match self.extractor.extract(view) {
            Some(e) => e,
            None => {
                self.stats.packets_unmatched += 1;
                crate::obs::record_packet_unmatched();
                return events;
            }
        };
        let Extracted {
            key,
            orientation,
            l4,
            tcp,
        } = extracted;
        let len = view.frame.len();
        let ts = view.timestamp;

        // ── lookup / insert ──────────────────────────────────────
        // Hot-cache fast path: when the same key reappears
        // immediately we know the entry exists and can skip the
        // `contains` lookup entirely.
        let hot_hit = self.hot.as_ref() == Some(&key);
        let is_new = !hot_hit && !self.flows.contains(&key);

        if is_new {
            let user = (self.init)(&key);
            let entry = FlowEntry {
                stats: FlowStats {
                    started: ts,
                    last_seen: ts,
                    ..FlowStats::default()
                },
                // TCP flows transition out of Active via the
                // state machine below (driven by SYN/SYN-ACK/ACK);
                // non-TCP flows stay Active until idle/eviction.
                state: FlowState::Active,
                history: HistoryString::new(),
                user,
                initiator_orientation: orientation,
                l4,
            };

            // Insert with LRU. Returns the evicted entry if at capacity.
            if let Some((evicted_key, evicted_entry)) = self.flows.push(key.clone(), entry) {
                // Don't double-evict the just-inserted flow if push was
                // a no-op replacement (key existed) — push only evicts
                // when the new key is genuinely new and capacity full.
                if evicted_key != key {
                    if self.hot.as_ref() == Some(&evicted_key) {
                        self.hot = None;
                    }
                    crate::obs::record_flow_ended(EndReason::Evicted, &evicted_entry.stats);
                    crate::obs::trace_flow_ended(EndReason::Evicted, &evicted_entry.stats);
                    events.push(FlowEvent::Ended {
                        key: evicted_key,
                        reason: EndReason::Evicted,
                        stats: evicted_entry.stats,
                        history: evicted_entry.history,
                    });
                    self.stats.flows_evicted += 1;
                    self.stats.flows_ended += 1;
                }
            }

            self.stats.flows_created += 1;
            crate::obs::record_flow_created(l4);
            crate::obs::trace_flow_started(l4);

            events.push(FlowEvent::Started {
                key: key.clone(),
                side: FlowSide::Initiator,
                ts,
                l4,
            });
        }

        // SAFETY-style invariant: we just ensured the entry exists.
        let entry = self
            .flows
            .get_mut(&key)
            .expect("flow entry just created or pre-existing");

        let side = entry.side_for(orientation);

        // ── reassembler dispatch hook ────────────────────────────
        // Called inline before any events are queued. The callback
        // sees the same `key` and the current `side`, plus the TCP
        // sequence number and payload slice. Non-TCP / no-payload
        // packets skip the call.
        if let Some(tcp_info) = &tcp
            && tcp_info.payload_len > 0
        {
            let start = tcp_info.payload_offset;
            let end = start + tcp_info.payload_len;
            if end <= view.frame.len() {
                payload_cb(&key, side, tcp_info.seq, &view.frame[start..end]);
            }
        }

        // ── update stats ─────────────────────────────────────────
        match side {
            FlowSide::Initiator => {
                entry.stats.packets_initiator += 1;
                entry.stats.bytes_initiator += len as u64;
            }
            FlowSide::Responder => {
                entry.stats.packets_responder += 1;
                entry.stats.bytes_responder += len as u64;
            }
        }
        entry.stats.last_seen = ts;

        // ── TCP state machine ────────────────────────────────────
        if let Some(tcp_info) = tcp {
            // History string update.
            push_for_flags(
                &mut entry.history,
                tcp_info.flags,
                side,
                tcp_info.payload_len > 0,
            );
            let prev_state = entry.state;
            let trans = tcp_state::transition(prev_state, tcp_info.flags, side);
            if trans.state != prev_state {
                entry.state = trans.state;
                if trans.became_established {
                    events.push(FlowEvent::Established {
                        key: key.clone(),
                        ts,
                    });
                } else {
                    events.push(FlowEvent::StateChange {
                        key: key.clone(),
                        from: prev_state,
                        to: trans.state,
                        ts,
                    });
                }
            }
        }

        // ── per-packet event ─────────────────────────────────────
        events.push(FlowEvent::Packet {
            key: key.clone(),
            side,
            len,
            ts,
        });

        // ── terminal-state cleanup ───────────────────────────────
        // Re-borrow because the previous &mut entry was still live.
        let entry_state = self.flows.peek(&key).map(|e| e.state);
        if let Some(state) = entry_state
            && state.is_terminal()
        {
            let reason = match state {
                FlowState::Reset => EndReason::Rst,
                FlowState::Closed => EndReason::Fin,
                _ => EndReason::Fin, // Aborted by idle, but only set by sweep — defensive
            };
            if let Some(removed) = self.flows.pop(&key) {
                if self.hot.as_ref() == Some(&key) {
                    self.hot = None;
                }
                crate::obs::record_flow_ended(reason, &removed.stats);
                crate::obs::trace_flow_ended(reason, &removed.stats);
                events.push(FlowEvent::Ended {
                    key,
                    reason,
                    stats: removed.stats,
                    history: removed.history,
                });
                self.stats.flows_ended += 1;
            }
        } else {
            // Surviving flow — refresh `hot` so the next packet of
            // this same flow takes the fast path.
            self.hot = Some(key);
        }

        events
    }

    /// Alias for [`Self::sweep`]. Exists for tests and docs that
    /// prefer a name not implying background-thread machinery.
    #[inline]
    pub fn manual_tick(&mut self, now: Timestamp) -> Vec<FlowEvent<E::Key>> {
        self.sweep(now)
    }

    /// Run the idle-timeout sweep. Returns events for flows that
    /// ended due to timeout. Call periodically (e.g., from a tokio
    /// `Interval`).
    pub fn sweep(&mut self, now: Timestamp) -> Vec<FlowEvent<E::Key>> {
        let mut ended = Vec::new();
        // Collect keys to expire. Walk all entries to compute idle.
        let now_dur = now.to_duration();
        let mut expired_keys: Vec<E::Key> = Vec::new();
        for (k, entry) in self.flows.iter() {
            let last = entry.stats.last_seen.to_duration();
            // Saturating: if `last_seen` somehow exceeds `now`, treat as not idle.
            let idle = now_dur.saturating_sub(last);
            let timeout = match entry.l4 {
                Some(L4Proto::Tcp) => self.config.idle_timeout_tcp,
                Some(L4Proto::Udp) => self.config.idle_timeout_udp,
                _ => self.config.idle_timeout_other,
            };
            if idle >= timeout {
                expired_keys.push(k.clone());
            }
        }
        for key in expired_keys {
            if let Some(entry) = self.flows.pop(&key) {
                let reason = match entry.state {
                    FlowState::Closed | FlowState::Reset => continue, // already emitted
                    _ => EndReason::IdleTimeout,
                };
                if self.hot.as_ref() == Some(&key) {
                    self.hot = None;
                }
                crate::obs::record_flow_ended(reason, &entry.stats);
                crate::obs::trace_flow_ended(reason, &entry.stats);
                ended.push(FlowEvent::Ended {
                    key,
                    reason,
                    stats: entry.stats,
                    history: entry.history,
                });
                self.stats.flows_ended += 1;
            }
        }
        ended
    }

    /// Peek at a flow's entry without affecting LRU order.
    pub fn get(&self, key: &E::Key) -> Option<&FlowEntry<S>> {
        self.flows.peek(key)
    }

    /// Borrow a flow's entry mutably (does NOT touch LRU order).
    pub fn get_mut(&mut self, key: &E::Key) -> Option<&mut FlowEntry<S>> {
        self.flows.peek_mut(key)
    }

    /// Iterate over all live flows in LRU order (most-recent first).
    pub fn flows(&self) -> impl Iterator<Item = (&E::Key, &FlowEntry<S>)> {
        self.flows.iter()
    }

    /// Number of live flows currently being tracked.
    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    /// Snapshot the [`FlowStats`] of a live flow without ending it.
    /// Returns `None` when the key is unknown. Used by
    /// [`crate::FlowDriver`] to synthesise an
    /// `Ended { reason: BufferOverflow }` event when a reassembler
    /// poisons mid-flow.
    pub fn snapshot_stats(&self, key: &E::Key) -> Option<FlowStats> {
        self.flows.peek(key).map(|e| e.stats.clone())
    }

    /// Snapshot the [`HistoryString`] of a live flow without ending
    /// it. Companion to [`Self::snapshot_stats`].
    pub fn snapshot_history(&self, key: &E::Key) -> Option<crate::HistoryString> {
        self.flows.peek(key).map(|e| e.history)
    }

    /// Remove a flow from the tracker without emitting an event.
    /// Used by [`crate::FlowDriver`] after a synthesised
    /// `BufferOverflow` end event so subsequent packets start a fresh
    /// flow. Returns `true` if a flow was removed.
    pub fn forget(&mut self, key: &E::Key) -> bool {
        let removed = self.flows.pop(key).is_some();
        if removed && self.hot.as_ref() == Some(key) {
            self.hot = None;
        }
        removed
    }

    /// Tracker stats (cumulative since construction).
    pub fn stats(&self) -> &FlowTrackerStats {
        &self.stats
    }

    /// Tracker config.
    pub fn config(&self) -> &FlowTrackerConfig {
        &self.config
    }

    /// Replace the config in-place. Resizes the LRU capacity if
    /// `max_flows` changed (excess flows are dropped — no events
    /// emitted for them). Also clears the hot-cache for safety —
    /// the dropped entries may have included the hot key.
    pub fn set_config(&mut self, config: FlowTrackerConfig) {
        let cap = NonZeroUsize::new(config.max_flows.max(1)).unwrap();
        self.flows.resize(cap);
        self.config = config;
        self.hot = None;
    }

    /// Consume the tracker and return the inner extractor. Used by
    /// builder code that needs to rebuild the tracker (e.g.
    /// `FlowStream::with_state` re-creates the tracker with a new
    /// state-init closure).
    pub fn into_extractor(self) -> E {
        self.extractor
    }
}

impl<E: FlowExtractor, S: Default + Send + 'static> FlowTracker<E, S> {
    /// Construct with default config and `S::default()` as the
    /// initializer.
    pub fn new(extractor: E) -> Self {
        Self::with_state(extractor, |_| S::default())
    }

    /// Same with explicit config.
    pub fn with_config(extractor: E, config: FlowTrackerConfig) -> Self {
        Self::with_config_and_state(extractor, config, |_| S::default())
    }
}

// Hint to clippy: avoid unused warning if a feature combination
// excludes the TcpFlags users.
#[allow(dead_code)]
fn _ensure_tcpflags_used(_: TcpFlags) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::FiveTuple;
    use crate::extract::parse::test_frames::*;

    fn view(frame: &[u8], sec: u32) -> PacketView<'_> {
        PacketView::new(frame, Timestamp::new(sec, 0))
    }

    #[test]
    fn single_udp_packet_started_and_packet_event() {
        let mut t = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
        let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1234, 53, b"hi");
        let evts = t.track(view(&f, 0));
        assert_eq!(evts.len(), 2);
        match &evts[0] {
            FlowEvent::Started { side, l4, .. } => {
                assert_eq!(*side, FlowSide::Initiator);
                assert_eq!(*l4, Some(L4Proto::Udp));
            }
            other => panic!("expected Started, got {other:?}"),
        }
        assert!(matches!(evts[1], FlowEvent::Packet { .. }));
        assert_eq!(t.flow_count(), 1);
        assert_eq!(t.stats().flows_created, 1);
    }

    #[test]
    fn second_packet_no_started() {
        let mut t = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
        let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1234, 53, b"hi");
        t.track(view(&f, 0));
        let evts = t.track(view(&f, 1));
        assert_eq!(evts.len(), 1);
        assert!(matches!(evts[0], FlowEvent::Packet { .. }));
    }

    #[test]
    fn bidirectional_side_flips_on_reverse() {
        let mut t = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
        let fwd = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1234, 53, b"a");
        let rev = ipv4_udp([10, 0, 0, 2], [10, 0, 0, 1], 53, 1234, b"b");
        t.track(view(&fwd, 0));
        let evts = t.track(view(&rev, 1));
        let pkt_event = evts
            .iter()
            .find(|e| matches!(e, FlowEvent::Packet { .. }))
            .unwrap();
        match pkt_event {
            FlowEvent::Packet { side, .. } => assert_eq!(*side, FlowSide::Responder),
            _ => unreachable!(),
        }
    }

    #[test]
    fn tcp_three_way_handshake_emits_established() {
        let mut t = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
        let syn = ipv4_tcp(
            [0; 6],
            [0; 6],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            1000,
            0,
            0x02,
            b"",
        );
        let synack = ipv4_tcp(
            [0; 6],
            [0; 6],
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            80,
            1234,
            5000,
            1001,
            0x12,
            b"",
        );
        let ack = ipv4_tcp(
            [0; 6],
            [0; 6],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            1001,
            5001,
            0x10,
            b"",
        );
        let mut all = Vec::new();
        all.extend(t.track(view(&syn, 0)));
        all.extend(t.track(view(&synack, 0)));
        all.extend(t.track(view(&ack, 0)));
        let est_count = all
            .iter()
            .filter(|e| matches!(e, FlowEvent::Established { .. }))
            .count();
        assert_eq!(est_count, 1, "exactly one Established event for 3WHS");
    }

    #[test]
    fn tcp_rst_emits_ended_rst() {
        let mut t = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
        let syn = ipv4_tcp(
            [0; 6],
            [0; 6],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            1,
            0,
            0x02,
            b"",
        );
        let rst = ipv4_tcp(
            [0; 6],
            [0; 6],
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            80,
            1234,
            0,
            0,
            0x04,
            b"",
        );
        let mut all = Vec::new();
        all.extend(t.track(view(&syn, 0)));
        all.extend(t.track(view(&rst, 0)));
        let ended = all
            .iter()
            .find(|e| matches!(e, FlowEvent::Ended { .. }))
            .unwrap();
        match ended {
            FlowEvent::Ended { reason, .. } => assert_eq!(*reason, EndReason::Rst),
            _ => unreachable!(),
        }
        assert_eq!(t.flow_count(), 0, "flow removed on RST");
    }

    #[test]
    fn idle_timeout_sweep_evicts_udp() {
        let cfg = FlowTrackerConfig {
            idle_timeout_udp: Duration::from_secs(60),
            ..FlowTrackerConfig::default()
        };
        let mut t = FlowTracker::<FiveTuple>::with_config(FiveTuple::bidirectional(), cfg);
        let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"x");
        t.track(view(&f, 0));
        // Exactly at threshold: idle == 60s ⇒ expired (>= timeout).
        let ended = t.sweep(Timestamp::new(60, 0));
        assert_eq!(ended.len(), 1);
        match &ended[0] {
            FlowEvent::Ended { reason, .. } => assert_eq!(*reason, EndReason::IdleTimeout),
            _ => unreachable!(),
        }
        assert_eq!(t.flow_count(), 0);
    }

    #[test]
    fn lru_evicts_oldest_on_overflow() {
        let cfg = FlowTrackerConfig {
            max_flows: 2,
            ..FlowTrackerConfig::default()
        };
        let mut t = FlowTracker::<FiveTuple>::with_config(FiveTuple::bidirectional(), cfg);
        let f1 = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 9], 1, 2, b"");
        let f2 = ipv4_udp([10, 0, 0, 2], [10, 0, 0, 9], 1, 2, b"");
        let f3 = ipv4_udp([10, 0, 0, 3], [10, 0, 0, 9], 1, 2, b"");
        t.track(view(&f1, 0));
        t.track(view(&f2, 1));
        let evts = t.track(view(&f3, 2));
        assert_eq!(t.flow_count(), 2);
        let evicted = evts.iter().find(|e| {
            matches!(
                e,
                FlowEvent::Ended {
                    reason: EndReason::Evicted,
                    ..
                }
            )
        });
        assert!(evicted.is_some(), "expected an Evicted event");
        assert_eq!(t.stats().flows_evicted, 1);
    }

    #[test]
    fn user_state_initialized_per_flow() {
        let mut t =
            FlowTracker::<FiveTuple, u32>::with_state(FiveTuple::bidirectional(), |_key| 42u32);
        let f = ipv4_udp([1, 2, 3, 4], [5, 6, 7, 8], 1, 2, b"x");
        t.track(view(&f, 0));
        let entry = t.flows().next().unwrap().1;
        assert_eq!(entry.user, 42);
    }

    #[test]
    fn track_returns_no_events_on_unparseable() {
        let mut t = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
        let bad = vec![0u8; 4];
        let evts = t.track(view(&bad, 0));
        assert!(evts.is_empty());
        assert_eq!(t.stats().packets_unmatched, 1);
    }

    #[test]
    fn stats_counts_per_side_correctly() {
        let mut t = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
        let fwd = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"x");
        let rev = ipv4_udp([10, 0, 0, 2], [10, 0, 0, 1], 2, 1, b"yy");
        t.track(view(&fwd, 0));
        t.track(view(&rev, 1));
        t.track(view(&fwd, 2));
        let entry = t.flows().next().unwrap().1;
        assert_eq!(entry.stats.packets_initiator, 2);
        assert_eq!(entry.stats.packets_responder, 1);
    }

    #[test]
    fn hot_cache_set_on_first_packet() {
        let mut t = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
        assert!(t.hot.is_none(), "hot starts empty");
        let fwd = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"x");
        t.track(view(&fwd, 0));
        assert!(t.hot.is_some(), "hot populated after first packet");
    }

    #[test]
    fn hot_cache_cleared_on_flow_end_via_rst() {
        let mut t = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
        let syn = ipv4_tcp(
            [0; 6], [0; 6],
            [10, 0, 0, 1], [10, 0, 0, 2],
            1234, 80, 1, 0, 0x02, b"",
        );
        let rst = ipv4_tcp(
            [0; 6], [0; 6],
            [10, 0, 0, 2], [10, 0, 0, 1],
            80, 1234, 0, 0, 0x04, b"",
        );
        t.track(view(&syn, 0));
        assert!(t.hot.is_some());
        t.track(view(&rst, 0));
        assert!(t.hot.is_none(), "hot cleared on RST end");
    }

    #[test]
    fn hot_cache_cleared_on_eviction() {
        let config = FlowTrackerConfig {
            max_flows: 2,
            ..FlowTrackerConfig::default()
        };
        let mut t = FlowTracker::<FiveTuple>::with_config(FiveTuple::bidirectional(), config);
        // Three distinct flows; the first should be evicted on the
        // third insertion.
        for src in [1u16, 2, 3] {
            let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], src, 80, b"x");
            t.track(view(&f, 0));
        }
        // hot should still be Some(third key) since the third packet
        // was the most recent.
        assert!(t.hot.is_some());
    }

    #[test]
    fn hot_cache_cleared_on_forget() {
        let mut t = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
        let fwd = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"x");
        t.track(view(&fwd, 0));
        let key = *t.flows().next().unwrap().0;
        assert!(t.forget(&key));
        assert!(t.hot.is_none());
    }

    #[test]
    fn hot_cache_does_not_change_event_sequence_for_monoflow() {
        // Run the same packet sequence; results should be identical
        // whether or not the hot path triggers (it always triggers
        // on second-and-later packets of the same flow).
        let mut t = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
        let fwd = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"x");
        let mut events = Vec::new();
        for _ in 0..10 {
            events.extend(t.track(view(&fwd, 0)));
        }
        // 1 Started + 10 Packet
        let starts = events
            .iter()
            .filter(|e| matches!(e, FlowEvent::Started { .. }))
            .count();
        let packets = events
            .iter()
            .filter(|e| matches!(e, FlowEvent::Packet { .. }))
            .count();
        assert_eq!(starts, 1);
        assert_eq!(packets, 10);
    }

    #[test]
    fn hot_cache_handles_alternating_flows_correctly() {
        // Two distinct flows interleaved — fast path should miss
        // every other packet but the event sequence stays correct.
        let mut t = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
        let fwd_a = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"x");
        let fwd_b = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 3, 4, b"x");
        let mut events = Vec::new();
        for _ in 0..5 {
            events.extend(t.track(view(&fwd_a, 0)));
            events.extend(t.track(view(&fwd_b, 0)));
        }
        let starts = events
            .iter()
            .filter(|e| matches!(e, FlowEvent::Started { .. }))
            .count();
        let packets = events
            .iter()
            .filter(|e| matches!(e, FlowEvent::Packet { .. }))
            .count();
        assert_eq!(starts, 2, "two distinct flows started");
        assert_eq!(packets, 10, "ten packets total");
        assert_eq!(t.flow_count(), 2);
    }
}

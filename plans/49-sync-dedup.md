# Plan 49 — Sync-side content-hash dedup

## Summary

Loopback captures (`tcpdump -i lo` and equivalents) duplicate
every packet — `PACKET_OUTGOING` + `PACKET_HOST` is the kernel's
loopback model, and AF_PACKET captures see both. netring's async
side already ships a `Dedup` primitive + `flow_stream(...).with_dedup(...)`
builder for this. The sync side (`FlowDriver`, `FlowSessionDriver`,
offline pcap replay via `PcapFlowSource`) has no equivalent.

This plan adds:

1. A `flowscope::dedup::Dedup` primitive in flowscope — a small
   content-hash + time-window ring buffer that decides whether
   to keep a `PacketView` based on `(hash(frame), len)` recurrence
   within `window`.
2. `FlowDriver::with_dedup(Dedup)` and
   `FlowSessionDriver::with_dedup(Dedup)` builders.
3. A `Dedup::loopback()` constructor with tuned defaults (1 ms
   window, 256-entry ring) matching netring's existing
   `Dedup::loopback()`.

The flowscope-side `Dedup` is purely content-hash-based (no
direction signal), because `PacketView` doesn't carry the
Outgoing/Host kernel-direction information that the netring side
uses. For `lo` captures with content-hash-only dedup, a 1 ms
window is empirically tight enough to dedupe re-injected loopback
copies without false-deduping legitimate retransmits.

## Status

Not started. Targets 0.3.0 ([Plan 45](./45-release-0.3.0.md)).

## Prerequisites

- None. New module.

## Out of scope

- Direction-based dedup (`PACKET_OUTGOING` vs `PACKET_HOST`).
  That's Linux-AF_PACKET-specific and lives in netring's `Packet`
  type. flowscope sources its input from `PacketView` which is
  platform-agnostic; we can't and shouldn't pull kernel direction
  into the core types.
- Auto-dedup on `PcapFlowSource`. The user opts in explicitly on
  the driver. Different pcap sources have different needs (a
  `tcpdump -i lo` capture wants dedup; a `tcpdump -i eth0` capture
  usually doesn't).
- A `DedupBatch` borrowed-iterator variant. Sync consumers don't
  need it — they iterate one packet at a time anyway. The
  netring side has it for async batching efficiency; sync is
  always a single packet per `track()` call.
- Cross-flow correlation. Each `Dedup` instance is independent of
  any flow context. Apply before extraction, not after.

---

## Files

### NEW

- `src/dedup.rs` — `Dedup` primitive (content-hash + ring buffer).

### MODIFIED

- `src/lib.rs` — register the new module behind a feature flag
  (or keep it always-on; see Implementation steps).
- `src/driver.rs` — `with_dedup` builder method; check before
  `track`.
- `src/session_driver.rs` — same.
- `Cargo.toml` — possibly a new `dedup` Cargo feature for
  zero-cost-when-off (or rely on the always-on path; see below).
- `CHANGELOG.md` — 0.3.0 entry.
- `docs/SESSION_GUIDE.md` — new "Loopback dedup" subsection.

---

## API

### `src/dedup.rs`

```rust
//! Content-hash deduplication of packet views.
//!
//! Each [`Dedup`] instance maintains a small ring buffer of
//! `(hash(frame), len, timestamp)` triples. [`Dedup::keep`]
//! returns `false` when the incoming view matches a recent entry
//! within the configured time window — useful for stripping the
//! duplicate halves that loopback captures emit.
//!
//! The match criterion is `hash(frame) == h && len == l && ts_now -
//! ts_seen <= window` — three signals to avoid false dedupes on
//! coincidental hash collisions.

use std::collections::VecDeque;
use std::time::Duration;

use crate::Timestamp;
use crate::view::PacketView;

/// Number of recent entries to remember by default. ~24 B per
/// entry — `Dedup::default()` is ~6 KiB resident.
pub const DEFAULT_RING_SIZE: usize = 256;

/// Recurrence window for the default loopback profile.
pub const DEFAULT_LOOPBACK_WINDOW: Duration = Duration::from_millis(1);

/// Bounded content-hash dedup. Cheap to construct; cheap per
/// packet (~one hash + one short linear scan).
#[derive(Debug)]
pub struct Dedup {
    window: Duration,
    ring: VecDeque<Entry>,
    capacity: usize,
    dropped: u64,
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    hash: u64,
    len: u32,
    ts: Timestamp,
}

impl Dedup {
    /// Construct a content-hash dedup with explicit window and
    /// ring size.
    pub fn new(window: Duration, capacity: usize) -> Self {
        Self {
            window,
            capacity: capacity.max(1),
            ring: VecDeque::with_capacity(capacity.max(1)),
            dropped: 0,
        }
    }

    /// Tuned defaults for loopback (`tcpdump -i lo` / AF_PACKET on
    /// `lo`): 1 ms window, 256-entry ring.
    pub fn loopback() -> Self {
        Self::new(DEFAULT_LOOPBACK_WINDOW, DEFAULT_RING_SIZE)
    }

    /// Returns `true` to keep the view, `false` to drop it as a
    /// duplicate. Updates the internal ring either way.
    pub fn keep(&mut self, view: PacketView<'_>) -> bool {
        let hash = hash_frame(view.frame);
        let len = view.frame.len() as u32;
        // Walk most-recent first; ring is small so linear scan is fine.
        for entry in self.ring.iter() {
            if entry.hash == hash
                && entry.len == len
                && view.timestamp.saturating_sub(entry.ts) <= self.window
            {
                self.dropped += 1;
                self.push_entry(Entry { hash, len, ts: view.timestamp });
                return false;
            }
        }
        self.push_entry(Entry { hash, len, ts: view.timestamp });
        true
    }

    /// Number of views dropped as duplicates since construction.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Current ring occupancy.
    pub fn buffered(&self) -> usize {
        self.ring.len()
    }

    fn push_entry(&mut self, e: Entry) {
        if self.ring.len() >= self.capacity {
            self.ring.pop_front();
        }
        self.ring.push_back(e);
    }
}

impl Default for Dedup {
    fn default() -> Self {
        Self::loopback()
    }
}

fn hash_frame(frame: &[u8]) -> u64 {
    use std::hash::{Hasher, BuildHasher};
    // Reuse the project's existing ahash dep — already pulled in
    // by the tracker feature. Fast non-cryptographic hash, no
    // new transitive deps.
    let mut hasher = ahash::RandomState::with_seeds(0, 0, 0, 0).build_hasher();
    hasher.write(frame);
    hasher.finish()
}
```

> **Hash function choice**: `ahash` is already a tracker dep; no
> new transitive deps. Use a fixed-seed instance (zeros) so dedup
> behaviour is deterministic across runs. Performance: ~100 ns
> for a 1500-byte packet on modern x86 — well below netring's
> per-packet latency budget.

### `Timestamp::saturating_sub` (small helper)

If `Timestamp` doesn't already have `saturating_sub(other) ->
Duration`, add it as part of this plan. The plan's `keep` method
needs it.

```rust
impl Timestamp {
    /// Saturating duration from `other` to `self`. Returns
    /// `Duration::ZERO` when `self` precedes `other`.
    pub fn saturating_sub(self, other: Timestamp) -> Duration {
        self.to_duration().saturating_sub(other.to_duration())
    }
}
```

### `src/driver.rs`, `src/session_driver.rs`

```rust
impl<E, F, S> FlowDriver<E, F, S> { /* ... */
    /// Filter incoming `PacketView`s through a content-hash
    /// dedup before extraction. Views the dedup classifies as
    /// duplicates produce zero events.
    pub fn with_dedup(mut self, dedup: Dedup) -> Self {
        self.dedup = Some(dedup);
        self
    }

    /// Borrow the dedup state for stats (`.dropped()`,
    /// `.buffered()`). `None` when no dedup is configured.
    pub fn dedup(&self) -> Option<&Dedup> {
        self.dedup.as_ref()
    }
}
```

In `track`:

```rust
pub fn track(&mut self, view: PacketView<'_>) -> FlowEvents<E::Key> {
    if let Some(dedup) = self.dedup.as_mut() {
        if !dedup.keep(view) {
            return FlowEvents::new();
        }
    }
    // ... existing logic ...
}
```

### Feature gate

The dedup module pulls in `std::collections::VecDeque` only —
no new transitive deps (ahash is already in). I'd ship it
unconditionally rather than behind a feature, given how lightweight
it is.

If feature-gating is preferred for compile-time minimisation:

```toml
[features]
dedup = []  # always-on conceptually; gate kept for users who
            # want a strictly minimal build surface
```

**Recommendation: ship unconditionally.** ~120 LOC, no deps; the
feature-gate overhead isn't worth the savings.

---

## Implementation steps

1. **Create `src/dedup.rs`** with `Dedup` struct and impl as
   sketched.
2. **Add `Timestamp::saturating_sub`** if not present.
3. **Wire `dedup: Option<Dedup>` field** on `FlowDriver` and
   `FlowSessionDriver`. Default `None`. Add `with_dedup` builder
   and `dedup()` accessor.
4. **Hook into `track`**: check `dedup.keep(view)` before doing
   anything else. Drop the view if the dedup says so.
5. **Unit tests** for `Dedup` itself (see Tests).
6. **Integration tests** that drive a duplicated-packet stream
   through `FlowDriver` and verify only one set of events fires.
7. **Update SESSION_GUIDE.md** — new "Loopback dedup" subsection
   pointing at `Dedup::loopback()` and explaining when to use it.
8. **CHANGELOG entry**.

---

## Tests

### `src/dedup.rs` (unit)

```rust
#[test]
fn keeps_first_drops_duplicate_within_window() {
    let mut d = Dedup::loopback();
    let frame = [1u8, 2, 3, 4];
    assert!(d.keep(PacketView::new(&frame, Timestamp::new(0, 0))));
    assert!(!d.keep(PacketView::new(&frame, Timestamp::new(0, 500_000)))); // 500 µs later
    assert_eq!(d.dropped(), 1);
}

#[test]
fn keeps_recurrence_after_window() {
    let mut d = Dedup::new(Duration::from_millis(1), 256);
    let frame = [1u8, 2, 3];
    assert!(d.keep(PacketView::new(&frame, Timestamp::new(0, 0))));
    // 2 ms later — outside the 1 ms window.
    assert!(d.keep(PacketView::new(&frame, Timestamp::new(0, 2_000_000))));
    assert_eq!(d.dropped(), 0);
}

#[test]
fn different_frames_pass_through() {
    let mut d = Dedup::loopback();
    let f1 = [1u8, 2, 3];
    let f2 = [4u8, 5, 6];
    assert!(d.keep(PacketView::new(&f1, Timestamp::new(0, 0))));
    assert!(d.keep(PacketView::new(&f2, Timestamp::new(0, 100_000))));
    assert_eq!(d.dropped(), 0);
}

#[test]
fn ring_bounded() {
    let mut d = Dedup::new(Duration::from_millis(1), 2);
    let f1 = [1u8];
    let f2 = [2u8];
    let f3 = [3u8];
    d.keep(PacketView::new(&f1, Timestamp::new(0, 0)));
    d.keep(PacketView::new(&f2, Timestamp::new(0, 100_000)));
    d.keep(PacketView::new(&f3, Timestamp::new(0, 200_000)));
    assert_eq!(d.buffered(), 2);
    // f1 has aged out of the ring; a duplicate of it now is NOT
    // detected (false negative). Documented behaviour.
    assert!(d.keep(PacketView::new(&f1, Timestamp::new(0, 300_000))));
}

#[test]
fn same_hash_different_len_kept() {
    // Theoretical hash collision: two different-length frames
    // shouldn't dedupe. Constructing a real collision is hard;
    // this test asserts the contract via a synthetic collision
    // injected through a custom hasher. Skipped if too fiddly.
}
```

### `src/driver.rs` (integration)

```rust
#[test]
fn driver_dedup_filters_duplicate_packets() {
    let mut d = FlowDriver::<_, _>::new(
        FiveTuple::bidirectional(),
        BufferedReassemblerFactory::default(),
    )
    .with_dedup(Dedup::loopback());
    let frame = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"x");
    let evs1 = d.track(view(&frame, 0));
    // Same frame, 100 µs later (well within 1 ms window).
    let evs2 = d.track(PacketView::new(&frame, Timestamp::new(0, 100_000)));
    assert!(!evs1.is_empty(), "first copy generates events");
    assert!(evs2.is_empty(), "second copy is dropped silently");
    assert_eq!(d.dedup().unwrap().dropped(), 1);
}

#[test]
fn driver_without_dedup_processes_both_copies() {
    let mut d = FlowDriver::<_, _>::new(
        FiveTuple::bidirectional(),
        BufferedReassemblerFactory::default(),
    );
    let frame = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"x");
    let evs1 = d.track(view(&frame, 0));
    let evs2 = d.track(PacketView::new(&frame, Timestamp::new(0, 100_000)));
    assert!(!evs1.is_empty());
    assert!(!evs2.is_empty(), "no dedup → both copies fully processed");
}
```

### Doctest

```rust
/// ```
/// use std::time::Duration;
/// use flowscope::{Dedup, PacketView, Timestamp};
///
/// let mut d = Dedup::new(Duration::from_millis(1), 256);
/// let frame = [1u8, 2, 3, 4];
/// assert!(d.keep(PacketView::new(&frame, Timestamp::new(0, 0))));
/// // Same frame 500 µs later — duplicate.
/// assert!(!d.keep(PacketView::new(&frame, Timestamp::new(0, 500_000))));
/// assert_eq!(d.dropped(), 1);
/// ```
```

---

## Acceptance criteria

- [ ] `src/dedup.rs` exists with the public `Dedup` type and
      tested implementation.
- [ ] `Dedup::loopback()` constructs the tuned defaults (1 ms /
      256 entries).
- [ ] `FlowDriver::with_dedup` /
      `FlowSessionDriver::with_dedup` builders work; default
      behaviour (no dedup) is unchanged.
- [ ] `dedup()` accessor exposes the dropped/buffered counters
      on both drivers.
- [ ] `Timestamp::saturating_sub` exists.
- [ ] SESSION_GUIDE.md "Loopback dedup" subsection added.
- [ ] CHANGELOG entry under 0.3.0.
- [ ] `cargo clippy --all-features --all-targets -- -D warnings` clean.

---

## Risks

1. **Hash collision false dedupes.** With ahash + a 64-bit hash
   and a frame-length cross-check, the collision probability is
   negligible for practical packet sizes. Documented; users
   concerned can use a wider hash (out of scope here).
2. **Ring size vs frame rate.** A 256-entry ring sized for 1 ms
   gives ~256 kpps tolerance before old entries roll off. Above
   that, duplicates spaced >ring/rate apart are missed. Doc the
   trade-off; suggest larger rings for high-rate captures.
3. **Initial seed determinism.** Using `ahash::RandomState::with_seeds(0,...)`
   makes hashing deterministic — good for testing and reproducible
   dedup behaviour, slightly bad for hash-flood resistance. Since
   the input is captured network traffic and the dedup is on the
   data-path receiver side (not a server-side cache), hash-flood
   isn't a concern.
4. **Parity with netring.** netring's `Dedup` includes direction
   matching (`Outgoing` vs `Host`). flowscope's version doesn't —
   `PacketView` carries no direction. Document the difference;
   `Dedup::loopback()` defaults are still useful, just slightly
   less aggressive than netring's.
5. **Cost on the hot path.** ~100 ns hash + 256-entry linear scan
   (~100 ns worst case, mostly cache-resident). Total <1 µs per
   packet — well below netring's per-packet ingress cost. Verify
   with the criterion harness once Plan 41 micro-benches exist.

---

## Effort

- LOC: ~250 (dedup module + driver wiring + tests).
- Time: 1 day.

---

## Provenance

Reported as item #6 in `flowscope-feedback-2026-05-14.md`
(des-rs team). They run `tcpdump -i lo` captures through their
offline `des-pcap-decode` binary and currently get every PUBEVT
twice because the sync flowscope path has no dedup equivalent
to netring's `with_dedup(Dedup::loopback())`. This plan closes
the sync/async asymmetry.

The design follows
[`plans/high-level-features-design.md`](./high-level-features-design.md)'s
Layer-2 free-standing primitive recommendation, restricted to
the content-hash-only branch (since `PacketView` doesn't carry
kernel direction).

# Plan 111 — 0.10 quick wins

## Summary

Ship the small additive helpers identified across multiple
example postmortem themes as a single PR. Pure additions; no
breakage. Estimated 300 LoC, 6 hours of work, but removes
~5 % of every observability example's LoC.

Themes addressed:

- **Theme 1** — `Timestamp` arithmetic ergonomics.
- **Theme 3** — `FlowStats` rollup helpers.
- **Theme 4 (partial)** — Display impls and helper methods on
  the layer enum.

Detailed coverage of theme 4 lives in plan 110 (rustdoc).
Themes 5, 6, 7, 8 + the rest of 2 have their own plans.

## Status

**Ready to implement.** Targets 0.10.0. The "ship early"
plan — recommended landing first in the cycle so the rest of
the 0.10 plans can lean on the helpers.

## Prerequisites

None.

## Out of scope

- Anything large enough to deserve its own plan (101-110).
- Changes to existing method names or behaviour.
- New features beyond the ergonomic additions listed.

---

## Additions

### `Timestamp` (`src/timestamp.rs`)

```rust
impl Timestamp {
    /// Convert to Unix epoch seconds with nanosecond precision.
    /// Inverse of [`Self::from_unix_f64`].
    pub fn to_unix_f64(self) -> f64 {
        self.sec as f64 + self.nsec as f64 / 1e9
    }

    /// Construct from Unix epoch seconds. Truncates / rounds
    /// the fractional part to a u32 nanosecond.
    pub fn from_unix_f64(secs: f64) -> Self {
        let s = secs.trunc() as u32;
        let n = (secs.fract() * 1e9) as u32;
        Self::new(s, n)
    }

    /// Signed delta in seconds: `self - other`.
    /// Negative if `self` is earlier.
    pub fn relative_to(self, other: Timestamp) -> f64 {
        self.to_unix_f64() - other.to_unix_f64()
    }

    /// Construct from `std::time::SystemTime`.
    pub fn from_system_time(ts: SystemTime) -> Self;
}

impl Display for Timestamp {
    /// `"{sec}.{nsec:09}"` — Zeek-compatible timestamp shape.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:09}", self.sec, self.nsec)
    }
}
```

### `FlowStats` (`src/event.rs`)

```rust
impl FlowStats {
    /// `bytes_initiator + bytes_responder`.
    pub fn total_bytes(&self) -> u64 {
        self.bytes_initiator + self.bytes_responder
    }

    /// `packets_initiator + packets_responder`.
    pub fn total_packets(&self) -> u64 {
        self.packets_initiator + self.packets_responder
    }

    /// `retransmits_initiator + retransmits_responder`.
    pub fn total_retransmits(&self) -> u64 {
        self.retransmits_initiator + self.retransmits_responder
    }

    /// Retransmits as a fraction of total packets, or
    /// `0.0` if no packets.
    pub fn retransmit_rate(&self) -> f64 {
        let total = self.total_packets();
        if total == 0 {
            0.0
        } else {
            self.total_retransmits() as f64 / total as f64
        }
    }

    /// `last_seen - started` as `Duration`.
    pub fn duration(&self) -> Duration {
        self.last_seen.to_duration().saturating_sub(self.started.to_duration())
    }

    /// `duration()` as f64 seconds — convenience for the
    /// arithmetic patterns.
    pub fn duration_secs(&self) -> f64 {
        self.duration().as_secs_f64()
    }
}
```

### `EndReason` (`src/event.rs`)

```rust
impl EndReason {
    /// Snake-case identifier matching the 0.8 serde wire format.
    /// E.g. `"fin"` / `"rst"` / `"idle_timeout"` /
    /// `"buffer_overflow"` / `"parse_error"`.
    pub fn as_str(&self) -> &'static str { … }
}

impl Display for EndReason {
    /// Snake-case via `as_str`.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
```

(Note: `as_zeek_state()` lands with plan 101, not here.)

### `LayerKind` (`src/layers/kind.rs`)

```rust
impl LayerKind {
    pub const fn is_l2(self) -> bool;
    pub const fn is_l3(self) -> bool;
    pub const fn is_l4(self) -> bool;
    pub const fn is_tunnel(self) -> bool;
}
```

### `Layer<'_>` (`src/layers/mod.rs`)

```rust
impl<'a> Display for Layer<'a> {
    /// One-line summary like `ipv4 src=10.0.0.1 dst=10.0.0.2 proto=6`.
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result { … }
}
```

### `LayerStack` (`src/layers/fast.rs`)

```rust
impl LayerStack {
    /// Number of populated slots.
    pub fn depth(&self) -> usize;

    /// Iterate the kinds populated.
    pub fn iter_kinds(&self) -> impl Iterator<Item = LayerKind> + '_;
}
```

### `KeyIndexed` (`src/correlate/indexed.rs`)

```rust
impl<K, V> KeyIndexed<K, V> where K: Hash + Eq {
    /// Read-only get — does NOT bump LRU recency.
    /// Cheaper for outer-scope `&self` access.
    pub fn peek(&self, k: &K, now: Timestamp) -> Option<&V>;
}
```

---

## Files

```
src/timestamp.rs           # 4 new methods + Display
src/event.rs               # 6 new methods + EndReason::as_str + Display
src/layers/kind.rs         # 4 new const predicates
src/layers/mod.rs          # Display for Layer
src/layers/fast.rs         # depth + iter_kinds for LayerStack
src/correlate/indexed.rs   # peek
tests/quick_wins.rs        # NEW — coverage for every addition
examples/*                 # opportunistically use the new helpers (no required migration)
docs/recipes.md            # no change needed; rustdoc covers it
CHANGELOG.md               # 0.10 entry
```

## Implementation steps

1. Land `Timestamp` additions + Display. Update rustdoc with
   doctest.
2. Land `FlowStats` rollup helpers. Doctest.
3. Land `EndReason::as_str()` + `Display`.
4. Land `LayerKind` predicates.
5. Land `Layer<'_>::Display`.
6. Land `LayerStack::depth()` + `iter_kinds()`.
7. Land `KeyIndexed::peek()`.
8. `tests/quick_wins.rs` — one section per addition.
9. CHANGELOG entry under 0.10.0 "Added".

## Tests

`tests/quick_wins.rs`:

```rust
- Timestamp::to_unix_f64 and from_unix_f64 round-trip.
- FlowStats::total_bytes / total_packets / retransmit_rate /
  duration_secs match the manual computation.
- EndReason::as_str returns snake-case strings.
- LayerKind::is_l2/l3/l4/tunnel match the layer_number
  groups.
- Layer<'_>::Display produces a one-line summary
  containing layer-specific fields.
- LayerStack::depth matches the number of populated slots
  on a Eth+IPv4+TCP frame.
- KeyIndexed::peek does NOT mutate LRU; verify via two
  consecutive insert/peek/insert that maintains order.
```

## Acceptance criteria

- ~20 new public methods (counted across the modules).
- ~12 test scenarios pass.
- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- `cargo doc --all-features --no-deps` clean.
- CHANGELOG entry under 0.10.0 "Added".

## Risks

- **Adding many small methods at once.** No individual risk;
  the sweep nature means the PR is easy to review by section.

## Effort

| Section | LoC | Hours |
|---------|-----|-------|
| Timestamp additions + Display | ~50 | 1 |
| FlowStats rollup helpers | ~80 | 1.5 |
| EndReason::as_str + Display | ~30 | 0.5 |
| LayerKind predicates | ~25 | 0.5 |
| Layer<'_>::Display | ~80 | 2 |
| LayerStack depth + iter_kinds | ~40 | 1 |
| KeyIndexed::peek | ~20 | 0.5 |
| Tests | ~180 | 3 |
| Docs touch + CHANGELOG | ~30 | 0.5 |
| **Total** | **~535 LoC** | **~10 hours** |

## Provenance

Postmortem themes 1 + 3 + part of 4. The "quick wins" sprint
called out in the report:

> ### Quick wins (each <100 LoC, <2h) — pre-0.10
>
> - `Timestamp::to_unix_f64()` / `from_unix_f64()` / `Display`
> - `FlowStats::total_bytes()` / `total_packets()` /
>   `total_retransmits()` / `retransmit_rate()` / `duration()`
> - `EndReason::as_str()` (snake_case)
> - `KeyIndexed::peek()` (non-mutating)
> - `Layer<'_>::Display` impl
> - `HttpResponse::status_class()` / `is_2xx()` / `is_5xx()`
>   *(moved to plan 110 since it lives in the rustdoc landing-
>   page work)*
> - `LayerStack::depth()` / `iter_kinds()`
> - `LayerKind::is_l2/l3/l4/tunnel()` predicates
>
> These are pure additions; no breakage.

`EndReason::as_zeek_state()` was originally proposed here too
but moved to plan 101 (emit module) where it logically lives
alongside the Zeek `conn.log` writer.

The "<2h" estimate per item in the postmortem covered the
individual additions; this plan groups them at ~10h total
because of the test coverage overhead.

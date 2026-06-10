# Plan 127 — `Timestamp::write_iso8601` + optional `chrono` interop

## Summary

Add ISO 8601 / RFC 3339 rendering to `Timestamp`:

1. `Timestamp::write_iso8601(&mut impl io::Write) -> io::Result<()>`
   — zero-allocation hand-rolled emit (no chrono dep). Output
   shape: `"2026-06-10T12:34:56.789012345Z"` (UTC, 9-digit
   fractional second).
2. `Timestamp::to_iso8601(&self) -> String` — allocating
   convenience wrapper.
3. Optional `chrono` feature adding `From<DateTime<Utc>> for
   Timestamp` + `TryFrom<Timestamp> for DateTime<Utc>` so
   downstream crates that already use chrono can interop
   without rolling their own conversion.

Used by the EVE writer (plan 123), `FlowEventNdjsonWriter`'s
optional timestamp formatting, and any consumer wanting a log-
ship-friendly Timestamp render.

## Status

Not started.

## Prerequisites

None.

## Out of scope

- **`time` crate interop.** Add if a consumer asks.
- **Local-time rendering.** UTC only. flowscope timestamps are
  always UTC by convention (matches netring's wall-clock).
- **Sub-nanosecond / picosecond.** `Timestamp::nsec` is `u32`;
  9-digit fractional seconds covers the full range.
- **ISO 8601 _basic_ format** (no separators): hyphens + colons
  only.
- **Other Display variants.** The existing
  `<Timestamp as Display>` (currently `sec.nsec`) stays — this
  plan adds named methods, not a Display change.

## Files

| Action | Path | Purpose |
|---|---|---|
| Modify | `src/timestamp.rs` | `write_iso8601` + `to_iso8601` methods; chrono interop behind cfg |
| Modify | `Cargo.toml` | `chrono = { version = "0.4", default-features = false, features = ["clock"], optional = true }`; `chrono = ["dep:chrono"]` feature |

## API

```rust
use std::io::{self, Write};

impl Timestamp {
    /// Write the timestamp as ISO 8601 / RFC 3339 (UTC, 9-digit
    /// fractional second). Hand-rolled — no chrono dependency,
    /// zero allocations.
    ///
    /// Example output: `"2026-06-10T12:34:56.789012345Z"`.
    pub fn write_iso8601<W: Write>(&self, w: &mut W) -> io::Result<()> { /* … */ }

    /// Allocating wrapper around [`Self::write_iso8601`]. Returns
    /// the rendered string. Equivalent to `let mut s =
    /// String::new(); ts.write_iso8601(&mut s).unwrap(); s` but
    /// pre-sized to 30 bytes.
    pub fn to_iso8601(&self) -> String { /* … */ }
}

#[cfg(feature = "chrono")]
impl From<chrono::DateTime<chrono::Utc>> for Timestamp { /* … */ }

#[cfg(feature = "chrono")]
impl TryFrom<Timestamp> for chrono::DateTime<chrono::Utc> {
    type Error = chrono::OutOfRangeError;
    fn try_from(ts: Timestamp) -> Result<Self, Self::Error> { /* … */ }
}
```

## Implementation steps

1. **Date algorithm**: implement the civil-from-days
   conversion (Howard Hinnant's algorithm — algorithm at
   <https://howardhinnant.github.io/date_algorithms.html>). The
   relevant fragment:
   ```rust
   fn civil_from_days(z: i32) -> (i32, u32, u32) {
       let z = z + 719_468;
       let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
       let doe = (z - era * 146_097) as u32;
       let yoe = (doe - doe/1460 + doe/36_524 - doe/146_096) / 365;
       let y = yoe as i32 + era * 400;
       let doy = doe - (365 * yoe + yoe/4 - yoe/100);
       let mp = (5 * doy + 2) / 153;
       let d = doy - (153 * mp + 2)/5 + 1;
       let m = if mp < 10 { mp + 3 } else { mp - 9 };
       (y + i32::from(m <= 2), m, d)
   }
   ```
   Adapted to `u32` epoch seconds: `let days = sec / 86_400;
   let (y, m, d) = civil_from_days(days as i32);` + hour /
   minute / second / nanosecond breakdown.
2. **`write_iso8601`**: writes 30 ASCII bytes — fixed-width
   `YYYY-MM-DDTHH:MM:SS.NNNNNNNNNZ`. Use `itoa`-style
   zero-padded writes; no allocations.
3. **`to_iso8601`**: `let mut s =
   String::with_capacity(30); self.write_iso8601(&mut s).unwrap(); s`.
4. **Chrono interop**:
   ```rust
   impl From<chrono::DateTime<chrono::Utc>> for Timestamp {
       fn from(dt: chrono::DateTime<chrono::Utc>) -> Self {
           Self::new(dt.timestamp() as u32, dt.timestamp_subsec_nanos())
       }
   }
   impl TryFrom<Timestamp> for chrono::DateTime<chrono::Utc> {
       type Error = chrono::OutOfRangeError;
       fn try_from(ts: Timestamp) -> Result<Self, Self::Error> {
           chrono::DateTime::from_timestamp(ts.sec as i64, ts.nsec)
               .ok_or(chrono::OutOfRangeError {})
       }
   }
   ```
   (The exact `OutOfRangeError` path may need adjustment; chrono's
   `from_timestamp` returns `Option`. We construct a sentinel
   `OutOfRangeError` via the public chrono API; if chrono doesn't
   expose it, fall back to a custom `flowscope::timestamp::ConversionError`.)
5. **Tests**: known epochs + round-trip fixtures.
6. **CHANGELOG**: new methods + the optional chrono feature.

## Tests

- `iso8601_epoch_zero` → `"1970-01-01T00:00:00.000000000Z"`.
- `iso8601_known_date` → fixture `Timestamp::new(1717932896, 123_456_789)`
  → `"2024-06-09T11:34:56.123456789Z"` (or whatever the actual
  date is for the picked epoch second).
- `iso8601_leap_day_fixture` — a date in Feb 29 of a leap
  year (e.g. 2024-02-29).
- `iso8601_y2038_safe` — `Timestamp::new(u32::MAX, 0)` (year
  2106; doesn't panic, renders correctly).
- `to_iso8601_matches_write_iso8601` — both APIs produce equal
  output.
- `to_iso8601_pre_allocates_30_bytes` — capacity check.
- `write_iso8601_zero_alloc` (counting allocator from
  `benches/support/counting_allocator.rs`) — confirms zero
  allocations during render. Gated on `cfg(test)`.
- **Gated on `feature = "chrono"`**:
  `chrono_roundtrip_preserves_nanos` — `Timestamp` →
  `DateTime<Utc>` → `Timestamp` is a no-op for in-range values.
- **Optional cross-check (gated on `feature = "chrono"`)**:
  `iso8601_matches_chrono_to_rfc3339_micros` — for 50 fixture
  dates, hand-rolled output matches
  `chrono::DateTime::to_rfc3339_opts(SecondsFormat::Nanos,
  true)`. Catches algorithm bugs.

## Acceptance criteria

- `cargo build` (no features) builds.
- `cargo build --features chrono` builds.
- `cargo test --features chrono` clean.
- `write_iso8601` is verified zero-allocation by the counting
  allocator test.
- chrono cross-check tests pass for 50 fixture dates.
- `chrono` feature off by default; offline-pcap users + embedded
  consumers don't pull it in.
- CHANGELOG entry documents the methods + feature.

## Risks

- **R1: Date algorithm correctness.** Year/month/day-from-
  epoch is non-trivial. Mitigation: 50-fixture cross-check
  against chrono catches drift. The Howard Hinnant algorithm
  is well-tested; we're just porting.
- **R2: `Timestamp::sec` is `u32`.** Range is 1970-01-01 to
  2106-02-07. Pre-1970 or post-2106 isn't representable today
  — not a new constraint, just inherited. Document the range
  in the new methods' rustdoc.
- **R3: chrono `OutOfRangeError` public API**. chrono may not
  expose `OutOfRangeError` constructor publicly. Mitigation:
  fall back to a thin `flowscope::timestamp::ConversionError`
  if needed. Reverts to using `Result<…, ConversionError>`.

## Effort

| Step | LoC | Hours |
|---|---|---|
| Date algorithm + tests | 80 | 3 |
| `write_iso8601` writer + tests | 50 | 1.5 |
| `to_iso8601` + cap test | 20 | 0.5 |
| chrono interop + tests | 40 | 1 |
| Cargo.toml + CHANGELOG | 10 | 0.5 |
| Cross-check tests against chrono | 40 | 1.5 |
| **Total** | **~240** | **~8 hours (1 day)** |

The wishlist's "½ day" estimate is optimistic; cross-check
testing realistically takes the bench up to ~1 day.

## Provenance

EVE format requires ISO 8601 timestamps. NDJSON dashboards
(Elasticsearch, OpenSearch, Splunk, Loki, ClickHouse) expect
the same. Today's `Timestamp::Display` is `"sec.nsec"` — useful
for debugging but not for log shippers. Plan 123 (EVE writer)
depends on this; landing 127 first lets 123's implementation
just call `ts.write_iso8601(&mut self.scratch)`.

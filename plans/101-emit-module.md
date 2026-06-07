# Plan 101 — `flowscope::emit` — structured event sinks

## Summary

Ship a `flowscope::emit` module with built-in writers for the
three log formats every flow-analysis pipeline ends up
emitting:

- **CSV** — `flows.csv` for spreadsheets / DuckDB / pandas.
- **NDJSON** — Elasticsearch / Loki / ClickHouse ingest.
- **Zeek `conn.log`** — drop-in for existing Zeek pipelines.

Each writer takes a `Write` sink and an event stream, handles
header / field / quoting / escaping correctly, and lets a
~10-LoC example replace the 30-80 LoC of hand-rolled
formatting in the three current export examples.

Theme 8 from
[`plans/100-examples-postmortem.md`](./100-examples-postmortem.md).

## Status

**Ready to implement.** Targets 0.10.0. No dependencies on
other 0.10 plans.

## Prerequisites

- The `serde` Cargo feature (already exists, gated by
  `dep:serde`). NDJSON uses `serde_json`; CSV writes directly
  (no `csv` crate dep).

## Out of scope

- **Reading log formats.** Out of scope; flowscope is
  observe-only. Consumers wanting to replay CSV/JSON write
  their own iterator.
- **Other log formats.** Suricata's `eve.json`, Fluentd's
  format, Splunk HEC, etc. The three shipped formats cover
  the common cases; add more if a consumer asks. Suricata
  `eve.json` is structurally close to NDJSON with a
  flowscope-specific schema; the NDJSON writer is the
  starting point.
- **Streaming export over the network.** Writers take a
  `Write` sink — pipe into a TCP socket / HTTP client / etc.
  on the consumer side. flowscope doesn't ship a network
  emitter.
- **Compression / rotation.** The `Write` abstraction lets
  consumers wrap with `flate2::write::GzEncoder` or similar.
  Built-in rotation is a future plan if it surfaces as a
  pain point.
- **Per-protocol log shapes** (`http.log`, `dns.log`,
  `tls.log` Zeek-style). The 0.10 cut ships `conn.log`
  (flow-level) only. Per-protocol versions land in a
  follow-up plan once the conn.log shape is proven.

---

## Files

```
src/emit/mod.rs                # module entry + Writer trait
src/emit/csv.rs                # FlowEventCsvWriter<W>
src/emit/ndjson.rs             # FlowEventNdjsonWriter<W>
src/emit/zeek.rs               # ZeekConnLogWriter<W>
src/event.rs                   # EndReason::as_str (snake_case) + as_zeek_state
Cargo.toml                     # new `emit-csv`, `emit-ndjson`, `emit-zeek` features
                               # (or one umbrella `emit` feature; see Q1)
tests/emit_csv.rs              # output shape + escaping coverage
tests/emit_ndjson.rs           # ndjson + serde feature interaction
tests/emit_zeek.rs             # Zeek format compliance
examples/flow_csv_export.rs    # MIGRATED — 60 LoC → 15 LoC
examples/flow_json_export.rs   # MIGRATED — 45 LoC → 15 LoC
examples/zeek_style_conn_log.rs # MIGRATED — 80 LoC → 15 LoC
docs/recipes.md                # add "Structured event export" section
CHANGELOG.md                   # 0.10 entry
```

## Design questions

### Q1: One feature or three?

**Option A — one `emit` feature.** Pulls in `serde_json` + the
small writers all behind one flag. Simpler to discover.

**Option B — three sub-features (`emit-csv`, `emit-ndjson`,
`emit-zeek`).** Lets users pull only what they need. The
NDJSON path is the only one with a heavyweight transitive dep
(`serde_json` is ~70k LoC of generated code).

**Locked decision: B.** Granular features stay consistent with
the existing `ja3` / `ja4` / `serde` per-feature pattern. The
umbrella `emit` feature is a Cargo feature alias for all
three.

### Q2: Static schema or `Serialize` events?

CSV writers need a fixed column list. Options:

- **Hardcoded schema** — `FlowEventCsvWriter` writes a fixed
  header and a fixed row layout. Inflexible but discoverable.
- **`Serialize`-driven** — use `serde` to drive a CSV writer
  generically. Powerful but pulls in `csv` (3rd-party crate)
  and produces unexpected columns for nested structs.

**Locked decision: hardcoded for `FlowEvent::Ended`.** The
0.10 cut ships a fixed schema matching the existing
`flow_csv_export` example. Customisation comes from
`flowscope::emit::Schema` (a future plan, if asked).

### Q3: What event variants does each writer handle?

The current examples only emit `FlowEvent::Ended`. Three
options for the new writers:

- **Ended-only** — matches existing examples; simplest.
- **All variants** — emit headers for `Started`, `Packet`,
  `Ended`, anomalies. Verbose.
- **Configurable** — `with_emit_started(bool)`,
  `with_emit_packets(bool)`.

**Locked decision: configurable, default Ended-only.**
Matches existing example output without surprising consumers
who upgrade.

### Q4: Should NDJSON include all `FlowEvent` variants?

NDJSON is cheap to filter post-emit (with `jq`). The decision:
emit every variant of `FlowEvent` as a separate JSON object,
discriminated by the existing `type` tag from the 0.8 serde
lock.

---

## API

### Common trait

```rust
// src/emit/mod.rs
pub trait FlowEventSink {
    type Error;
    fn write_event<K: Serialize>(&mut self, ev: &FlowEvent<K>) -> Result<(), Self::Error>;
    fn finish(self) -> Result<(), Self::Error>;
}
```

Each concrete writer impls this; the trait lets generic
consumer code work over any of them.

### CSV writer

```rust
// src/emit/csv.rs
pub struct FlowEventCsvWriter<W: Write> { /* … */ }

#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct CsvOptions {
    /// Emit a `Started` row per flow start (default `false`).
    pub emit_started: bool,
    /// Use tabs instead of commas (default `false`).
    pub tab_separated: bool,
}

impl<W: Write> FlowEventCsvWriter<W> {
    pub fn new(write: W) -> std::io::Result<Self> { … }
    pub fn with_options(write: W, opts: CsvOptions) -> std::io::Result<Self> { … }

    pub fn write_event<K: Serialize>(&mut self, ev: &FlowEvent<K>) -> std::io::Result<()> { … }
    pub fn flush(&mut self) -> std::io::Result<()> { … }
    pub fn finish(self) -> std::io::Result<W> { … }
}
```

**Column schema (`Ended` rows):**

```text
start_sec, end_sec, duration_sec, proto, src_ip, src_port,
dst_ip, dst_port, pkts_init, pkts_resp, bytes_init, bytes_resp,
retransmits_init, retransmits_resp, end_reason
```

Plus optional `flow_event_kind` column when `emit_started` is
`true` (so consumers can filter rows by `Started` / `Ended`).

### NDJSON writer

```rust
// src/emit/ndjson.rs
pub struct FlowEventNdjsonWriter<W: Write> { /* … */ }

#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct NdjsonOptions {
    /// Pretty-print (one indented JSON per line). Default false.
    pub pretty: bool,
    /// Include `Packet` events (high volume). Default false.
    pub include_packets: bool,
}

impl<W: Write> FlowEventNdjsonWriter<W> {
    pub fn new(write: W) -> Self { … }
    pub fn with_options(write: W, opts: NdjsonOptions) -> Self { … }

    pub fn write_event<K: Serialize>(&mut self, ev: &FlowEvent<K>) -> std::io::Result<()> { … }
    pub fn flush(&mut self) -> std::io::Result<()> { … }
    pub fn finish(self) -> std::io::Result<W> { … }
}
```

Output: one JSON object per line, using flowscope's existing
serde wire format (snake_case + adjacent tagging on tuple
variants — locked since 0.8.0).

### Zeek `conn.log` writer

```rust
// src/emit/zeek.rs
pub struct ZeekConnLogWriter<W: Write> { /* … */ }

#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct ZeekOptions {
    /// Include the Zeek-style `#fields` / `#types` headers
    /// (default `true`). Disable for appending to an existing log.
    pub emit_headers: bool,
    /// UID prefix (default "C"; some pipelines want a custom one).
    pub uid_prefix: &'static str,
}

impl<W: Write> ZeekConnLogWriter<W> {
    pub fn new(write: W) -> std::io::Result<Self> { … }
    pub fn with_options(write: W, opts: ZeekOptions) -> std::io::Result<Self> { … }

    pub fn write_event<K: Serialize>(&mut self, ev: &FlowEvent<K>) -> std::io::Result<()> { … }
    pub fn finish(self) -> std::io::Result<W> { … }
}
```

Schema matches Zeek's canonical `conn.log` field order:

```text
ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto duration
orig_bytes resp_bytes conn_state history orig_pkts resp_pkts
```

Tab-separated. UID auto-generated as `{uid_prefix}{8-hex-digit
sequence}`.

### `EndReason` snake-case helpers

```rust
// src/event.rs
impl EndReason {
    /// Snake-case identifier matching the 0.8 serde wire format.
    /// E.g. `"fin"` / `"rst"` / `"idle_timeout"`.
    pub fn as_str(&self) -> &'static str { … }

    /// Map to Zeek's `conn_state` codes.
    /// E.g. `EndReason::Fin` → `"SF"`, `Rst` → `"RSTO"`,
    /// `IdleTimeout` → `"OTH"`, `BufferOverflow` → `"S0"`.
    pub fn as_zeek_state(&self) -> &'static str { … }
}
```

Both are pure functions; no allocation. Add to the
`flowscope::prelude` for discoverability.

---

## Implementation steps

1. **Add Cargo features** — `emit-csv`, `emit-ndjson`,
   `emit-zeek`, plus an umbrella `emit` alias. Wire
   `serde_json = { version = "1", optional = true }` (already
   a dev-dependency; promote to a runtime dep behind the
   `emit-ndjson` flag).
2. **Add `src/emit/mod.rs`** with the public trait + module
   declarations.
3. **Implement `FlowEventCsvWriter`** with a manual quoting /
   escaping helper (no `csv` dep). Test coverage:
   - Empty input → header only.
   - Single Ended event → header + 1 row.
   - Fields containing commas / quotes / newlines → properly
     RFC 4180 quoted.
   - `with_options(... { tab_separated: true })` → tabs.
4. **Implement `FlowEventNdjsonWriter`** via `serde_json::to_string`
   per event. Test:
   - One line per event.
   - All `FlowEvent` variants serialize.
   - Round-trip via `serde_json::from_str` recovers the
     original.
5. **Implement `ZeekConnLogWriter`** with Zeek-compliant
   header + UID generation. Test:
   - Tab separation.
   - `#fields` / `#types` lines.
   - End-reason → conn_state mapping for every variant.
   - `zeek-cut`-compatible output (verified via doc snippet).
6. **Add `EndReason::as_str()` + `as_zeek_state()`** on the
   existing enum.
7. **Migrate three example files** — `flow_csv_export.rs`,
   `flow_json_export.rs`, `zeek_style_conn_log.rs` — to use
   the new writers.
8. **Update `docs/recipes.md`** with a "Structured event
   export" section showing all three.
9. **CHANGELOG entry** under 0.10.0 "Added".

## Tests

`tests/emit_csv.rs`:

- Header + 1 Ended row → expected exact output.
- Quoting: a key with comma → RFC-4180-quoted column.
- Quoting: a key with newline → quoted with escaped newline.
- Quoting: a key with embedded quotes → properly doubled.
- `with_options(.. emit_started: true ..)` → extra
  `flow_event_kind` column with values `"started"` / `"ended"`.
- Tab-separated mode → tabs instead of commas.

`tests/emit_ndjson.rs`:

- Per-event one-line output.
- Round-trip via `serde_json::from_str` recovers the original.
- `include_packets: false` skips `FlowEvent::Packet`.
- `pretty: true` indents (whitespace asserted).

`tests/emit_zeek.rs`:

- Output passes a minimal `zeek-cut`-shaped parser (we ship a
  small parser inline in the test).
- Every `EndReason` variant maps to a non-empty `conn_state`.
- UID generation: 10 events produce 10 distinct UIDs.

## Acceptance criteria

- Three writers ship behind their respective Cargo features.
- `EndReason::as_str()` + `as_zeek_state()` ship under the
  default features (no extra feature gate — they're stable
  string mappings).
- Three example files migrate; output byte-equivalent to the
  pre-migration shape.
- New rustdoc-visible `docs/recipes.md` "Structured event
  export" section.
- 6 + 4 + 3 = 13 new integration tests.
- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- CHANGELOG entry.

## Risks

- **CSV escaping bugs.** Hand-rolled escaping is error-prone.
  Mitigation: extensive `tests/emit_csv.rs` coverage; test
  output is byte-compared against pre-computed expected
  strings.
- **Zeek format drift.** Zeek updates its log format
  occasionally. Mitigation: pin to the 4.0+ schema (stable
  since 2021); document the version in module docs.
- **`serde_json` dependency churn.** Already a dev-dependency
  in flowscope; promotion to runtime dep is just a Cargo.toml
  edit.

## Effort

| Surface | LoC | Hours |
|---------|-----|-------|
| `src/emit/mod.rs` + Writer trait | ~60 | 1 |
| `FlowEventCsvWriter` + escaping | ~180 | 4 |
| `FlowEventNdjsonWriter` | ~80 | 2 |
| `ZeekConnLogWriter` + UID + state map | ~200 | 4 |
| `EndReason::as_str()` + `as_zeek_state()` | ~50 | 1 |
| Tests (13 scenarios across 3 files) | ~360 | 6 |
| Example migrations (3 files, -300 LoC net) | ~−180 net | 2 |
| `docs/recipes.md` + CHANGELOG | ~80 | 1 |
| **Total** | **~830 LoC** | **~21 hours** |

## Provenance

Postmortem theme 8:

> Export to standard log formats is hand-rolled every time.
> CSV, NDJSON, Zeek conn.log are 30-80 LoC of mostly
> mechanical formatting that belongs in the crate.

Specific reductions in the example footprints:

| Example | Before | After |
|---------|--------|-------|
| `flow_csv_export.rs` | 86 LoC | ~15 LoC |
| `flow_json_export.rs` | 47 LoC | ~15 LoC |
| `zeek_style_conn_log.rs` | 100 LoC | ~15 LoC |

Total example LoC saved: ~190.

# Plan 146 — File hash sinks

## Summary

Stream-hashing sinks attached to the reassembler that compute
SHA-256 / MD5 over reassembled payload windows and emit hashes
plus optional MIME-type detection. The DFIR / IR consumer
ask: "what files crossed the wire and what were their hashes?"
— without storing the files themselves.

Two shipped sinks:

- **`Sha256Sink`** — SHA-256 over a configurable payload window
  (default: full TCP stream, both directions; configurable per-
  message-body via `HttpExchangeParser` plumbing).
- **`Md5Sink`** — same shape, MD5 for legacy interop (VirusTotal,
  Suricata `file_md5`, ClamAV cache).

Both reuse `flowscope::detect::signatures` to classify the
first ~64 B of the window as MIME / file-magic, attaching the
classification to the emitted hash event.

Behind a new `file-hash` feature pulling `sha2` + `md-5` (the
latter is already a `tls` ja3 dep, so it's free if `tls` is on).

## Status

Not started.

## Prerequisites

- **Plan 130** (KeyFields trait) — file-hash event carries
  flow key; emit writers route via KeyFields.

## Out of scope

- **File extraction / storage.** Hashes only. Suricata's
  `file-store` writes file bytes to disk; we don't.
- **Antivirus / YARA matching.** Out of scope; consumer
  ships their own AV against the hashes we emit.
- **SMB / FTP / SMTP file carving.** No parsers yet. The hooks
  exposed here will work for those parsers when they land.
- **Streaming decompression (gzip / br / zstd).** Hashing the
  raw on-wire bytes; consumers can wrap the sink for
  decompressed-content hashing.
- **MIME-type sniffing beyond the signature registry.** The
  `detect::signatures` registry covers ~10 protocols / file
  types (HTTP, TLS, DNS, … + PE/ELF/PDF/PNG/JPEG/GIF/ZIP/
  GZIP). For more, consumers integrate `file` /
  `libmagic-rs`.

## Pre-1.0 breaks

None. Additive.

## Files

| Action | Path | Purpose |
|---|---|---|
| New | `src/detect/file/mod.rs` | Re-exports |
| New | `src/detect/file/sha256.rs` | `Sha256Sink` |
| New | `src/detect/file/md5.rs` | `Md5Sink` |
| New | `src/detect/file/types.rs` | `FileHashEvent`, `FileType` enum |
| Modify | `src/segment_reassembler.rs` | Optional `&mut dyn FileHashSink` hook on `drain()` |
| Modify | `src/reassembler.rs` | `Reassembler::with_hash_sink<S: FileHashSink>(self, sink: S)` chainable |
| Modify | `src/http/exchange.rs` | `HttpExchangeParser` emits a `FileHashEvent` when its body sink is non-None |
| Modify | `src/detect/signatures.rs` | Expand registry with PE/ELF/PDF/PNG/JPEG/GIF/ZIP/GZIP magic detectors (some already shipped — verify + add the missing) |
| Modify | `src/lib.rs` | `pub use detect::file::{Sha256Sink, Md5Sink, FileHashSink, FileHashEvent, FileType};` |
| Modify | `Cargo.toml` | `file-hash = ["reassembler", "dep:sha2", "dep:md-5"]` |
| New | `tests/detect_file_hash.rs` | Streaming hash tests + MIME classification |
| New | `examples/02-forensics/file_hashes.rs` | Pcap → list of (flow, sha256, md5, mime) per identifiable payload |
| New | `docs/file-hash.md` | Hook architecture + plumbing recipe |
| Modify | `CHANGELOG.md` | 0.12 entry |

## API

### `FileHashSink` trait

```rust
// src/detect/file/mod.rs

/// Trait for streaming-hash sinks attached to a reassembler
/// or session parser body channel.
///
/// One sink per (flow, direction). Construction is consumer-
/// driven; flowscope ships [`Sha256Sink`] and [`Md5Sink`].
///
/// On flow close: drain via [`Self::finish`] returning the
/// computed [`FileHashEvent`].
pub trait FileHashSink {
    /// Hash algorithm name (e.g. "sha256", "md5"). Stable.
    fn algorithm(&self) -> &'static str;

    /// Feed payload bytes. Cheap — typically one `update`
    /// call per reassembled drain.
    fn update(&mut self, bytes: &[u8]);

    /// Drain current hash + MIME classification. Resets the
    /// sink for the next payload window.
    fn finish(&mut self) -> FileHashEvent;

    /// Total bytes hashed since last finish.
    fn bytes_hashed(&self) -> u64;
}
```

### `Sha256Sink` / `Md5Sink`

```rust
// src/detect/file/sha256.rs

use sha2::{Digest, Sha256};

pub struct Sha256Sink {
    hasher: Sha256,
    bytes: u64,
    mime_probe: [u8; 64],
    mime_probe_len: usize,
}

impl Sha256Sink {
    pub fn new() -> Self { … }
}

impl FileHashSink for Sha256Sink {
    fn algorithm(&self) -> &'static str { "sha256" }
    fn update(&mut self, bytes: &[u8]) { … }
    fn finish(&mut self) -> FileHashEvent { … }
    fn bytes_hashed(&self) -> u64 { self.bytes }
}
```

```rust
// src/detect/file/md5.rs

pub struct Md5Sink { /* same shape, md5 hasher */ }
```

### `FileHashEvent` + `FileType`

```rust
// src/detect/file/types.rs

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FileHashEvent {
    /// Hash algorithm name.
    pub algorithm: &'static str,
    /// Hash digest, hex-encoded.
    pub hash_hex: String,
    /// Total bytes hashed.
    pub bytes: u64,
    /// Best-effort MIME classification from the first ~64 B
    /// of payload.
    pub file_type: FileType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileType {
    Unknown,
    Pe,           // Portable Executable (Windows .exe / .dll)
    Elf,          // ELF (Linux binaries)
    MachO,        // Mach-O (macOS binaries)
    Pdf,
    Png,
    Jpeg,
    Gif,
    Webp,
    Zip,          // also covers .docx / .xlsx / .pptx
    Gzip,
    Bzip2,
    Xz,
    Mp4,          // ISO Base Media (also .m4a / .mov)
    Mp3,
    Sqlite3,
    Json,         // heuristic
    Html,         // heuristic
    Xml,          // heuristic
    Text,         // catch-all: looks like UTF-8
}
```

### Reassembler integration

```rust
// src/reassembler.rs

pub trait Reassembler {
    // ... existing methods ...

    /// Attach a hash sink. Sink receives every byte the
    /// reassembler hands out via `drain()`.
    fn with_hash_sink<S: FileHashSink + Send + 'static>(
        &mut self,
        sink: S,
    );

    /// Drain the active hash sink (one-shot; sink is reset
    /// after).
    fn drain_hash(&mut self) -> Option<FileHashEvent>;
}
```

### HttpExchangeParser body-hash plumbing

```rust
// src/http/exchange.rs

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HttpExchange {
    // ... existing fields ...

    /// File-hash of the response body, when an
    /// `HttpExchangeParser` was constructed with a body hash
    /// sink config.
    pub response_body_hash: Option<FileHashEvent>,
    pub request_body_hash: Option<FileHashEvent>,
}

impl HttpExchangeParser {
    pub fn with_body_hash<S: FileHashSink + Clone + Send + 'static>(
        mut self, sink: S,
    ) -> Self { … }
}
```

## Implementation steps

### Phase 1: Sink trait + Sha256 + Md5

1. `Cargo.toml`: add `file-hash` feature; `sha2 = "0.10"`
   (already a `ja4` dep for some impls), `md-5 = "0.10"`
   (already a `ja3` dep). With `tls-fingerprints` enabled
   they're free.
2. `src/detect/file/types.rs`: `FileHashEvent`, `FileType`.
3. `src/detect/file/sha256.rs` + `md5.rs`: sink impls.
4. MIME classification: store first 64 B in a `[u8; 64]`
   buffer; on `finish()`, run through
   `detect::signatures::registry()` to identify the file type.

### Phase 2: Reassembler plumbing

5. `src/reassembler.rs`: `Reassembler::with_hash_sink` chainable
   API on `BufferedReassembler`. Internal: `Option<Box<dyn
   FileHashSink + Send>>`.
6. On `drain()`, feed bytes to the sink before returning them
   to the caller (or do it after; verify by test).

### Phase 3: HttpExchangeParser plumbing

7. `src/http/exchange.rs`: `HttpExchangeParser::with_body_hash`.
   On each `HttpResponse` body completion, finalize the sink
   and attach the `FileHashEvent` to the emitted
   `HttpExchange`.

### Phase 4: Magic signature expansion

8. `src/detect/signatures.rs`: audit existing magic
   detectors against the `FileType` enum. Add the missing:
   PE (MZ + offset to "PE\0\0"), ELF (0x7f ELF), Mach-O (FE
   ED FA CE / CE FA ED FE), Webp (RIFF...WEBP), Mp4 (skip
   8 B, "ftyp"), Sqlite3 ("SQLite format 3"), JSON / HTML /
   XML heuristics.

### Phase 5: Tests + example + docs

9. Synthetic-payload tests:
   - SHA-256 of `b"hello"` matches known hex.
   - PE magic on `MZ` payload classifies as `FileType::Pe`.
   - Zip magic on `PK\x03\x04` classifies as `FileType::Zip`.
   - Unknown payload classifies as `Text` or `Unknown`.
10. Reassembler integration test: feed reassembled segments
    through `with_hash_sink`, finalise, assert event.
11. HTTP body hash test: parse a pcap with a known
    image / executable download, verify hash + file_type.
12. `examples/02-forensics/file_hashes.rs`: pcap → CSV of
    (flow, sha256, md5, mime, bytes).
13. `docs/file-hash.md`: hook architecture + plumbing recipe
    + MIME classification limits.

## Tests

### Unit

- `sha256::tests::known_input_yields_canonical_hex`
- `md5::tests::known_input_yields_canonical_hex`
- `types::tests::pe_magic_classifies_as_pe`
- `types::tests::elf_magic_classifies_as_elf`
- `types::tests::pdf_magic_classifies_as_pdf`
- `types::tests::zip_magic_classifies_as_zip`
- `types::tests::unknown_bytes_classify_as_unknown`

### Integration

- `tests/detect_file_hash.rs::reassembled_stream_emits_hash_on_drain`
- `tests/detect_file_hash.rs::sliding_window_emits_per_window_hash`
- `tests/detect_file_hash.rs::http_response_body_hash_attached_to_exchange`
- `tests/detect_file_hash.rs::known_file_in_pcap_matches_expected_sha256`

## Acceptance criteria

- `cargo build --features file-hash` clean.
- `cargo test --features file-hash,pcap,http` clean.
- `cargo clippy --features file-hash --all-targets -- -D warnings`
  clean.
- New `file-hash` CI matrix entry.
- A pcap with a known file download (e.g. a 1 KB PNG) produces
  the matching SHA-256.
- `examples/02-forensics/file_hashes.rs` runs end-to-end.
- `docs/file-hash.md` complete.
- Bench: `Sha256Sink::update` throughput documented in
  `docs/performance.md` — target: ≥ 200 MB/s on commodity
  hardware (sha2 crate baseline).

## Risks

- **R1: Per-byte hashing cost.** SHA-256 ≈ 5 ns/byte = 200
  MB/s. At 1 Gbps line rate that's 12.5% of one core just on
  hashing. Documented; gating per-flow via `with_hash_sink`
  is the consumer's lever to keep cost bounded.
- **R2: Sliding-window semantics.** Calling `finish()` mid-
  stream loses the running hash for the prior window. The
  shipped API does one-shot-then-reset; if a consumer wants
  sliding windows they wrap `Sha256Sink` themselves.
- **R3: HTTP body chunking / `Transfer-Encoding: chunked`
  reassembly.** `HttpExchangeParser` already accumulates bodies
  per RFC 9112; sink hooks fire on body-completion. Document
  that pipelined / streamed responses get one hash event per
  body.
- **R4: `Box<dyn FileHashSink>` cost.** One indirect call per
  sink update. Negligible at 200 MB/s; documented.
- **R5: File-type false positives on heuristic types.**
  `Json` / `Html` / `Xml` / `Text` classifiers are heuristic;
  binaries-with-text-prefix can misclassify. Document; suggest
  consumers ignore those classes if they care.

## Effort

| Step | LoC | Hours |
|---|---|---|
| `FileHashSink` trait + Sha256 + Md5 impls | 200 | 4 |
| `FileType` enum + MIME classifiers (signature additions) | 250 | 5 |
| Reassembler plumbing | 120 | 3 |
| HttpExchangeParser body-hash plumbing | 150 | 3 |
| Tests (7 unit + 4 integration) | 300 | 6 |
| Example + docs/file-hash.md | 150 | 3 |
| CHANGELOG | 30 | 0.5 |
| **Total** | **~1200** | **~24.5 hours (~3 days)** |

## Provenance

netring 0.21 wishlist (Phase J §"File extraction / hashing").
0.12 audit Tier-2 ("DFIR/IR teams care; medium ROI"). Suricata
`file_md5` / `file_sha256` is heavily used in DFIR pipelines;
ZeekFile-MD5 / VirusTotal hash matching is the canonical IR
workflow. flowscope shipping streaming hashes makes the
flowscope → SIEM → VirusTotal pipeline a one-step recipe
instead of a Zeek-or-Suricata staging tier.

References:
- Suricata `file.md5` keyword:
  `docs.suricata.io/en/latest/file-extraction/file-extraction.html`
- VirusTotal hash query API:
  `developers.virustotal.com/reference/files`
- ClamAV hash format:
  `docs.clamav.net/manual/Signatures/HashSignatures.html`
- File magic registry (libmagic):
  `github.com/file/file/blob/master/magic/Magdir`

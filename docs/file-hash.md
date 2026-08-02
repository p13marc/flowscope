# File hash sinks (`file-hash` feature)

`flowscope::detect::file::{Sha256Sink, Md5Sink}` provide
streaming hash computation over reassembled payload windows,
with best-effort MIME / file-type classification from the
first ~64 bytes.

The DFIR / IR pipeline ask: "what files crossed the wire and
what were their hashes?" — without storing the file bytes
themselves. Suricata's `file_md5` / `file_sha256` keywords
cover the same recipe; flowscope ships the equivalent as a
consumer-driven sink trait.

Behind the `file-hash` Cargo feature. New in 0.12.0 (plan 146).

```toml
flowscope = { version = "0.23", features = ["file-hash", "tls-fingerprints"] }
```

With `tls-fingerprints` enabled (which pulls `sha2` + `md-5`),
`file-hash` adds **zero new transitive dependencies**.

## The `FileHashSink` trait

```rust,ignore
pub trait FileHashSink {
    fn algorithm(&self) -> &'static str;   // "sha256" or "md5"
    fn update(&mut self, bytes: &[u8]);    // feed bytes
    fn finish(&mut self) -> FileHashEvent; // finalize + reset
    fn bytes_hashed(&self) -> u64;
}
```

Two shipped impls: `Sha256Sink` and `Md5Sink`. Build your own
if you need BLAKE3 / xxHash / SHA-1.

## `FileHashEvent`

```rust,ignore
#[non_exhaustive]
pub struct FileHashEvent {
    pub algorithm: &'static str,  // "sha256" / "md5"
    pub hash_hex: String,         // lowercase hex digest
    pub bytes: u64,               // total bytes hashed
    pub file_type: FileType,      // MIME / file-type guess
}
```

## `FileType` classification

Best-effort, magic-byte-only. Returns `FileType::Unknown` for
unrecognised content.

| Magic | `FileType` |
|---|---|
| `89 50 4E 47 0D 0A 1A 0A` | `Png` |
| `FF D8 FF` | `Jpeg` |
| `GIF87a` / `GIF89a` | `Gif` |
| `RIFF` + `WEBP` | `Webp` |
| `PK\x03\x04` / `PK\x05\x06` / `PK\x07\x08` | `Zip` (also `.docx` / `.xlsx` / `.jar`) |
| `1F 8B` | `Gzip` |
| `BZh` | `Bzip2` |
| `FD 37 7A 58 5A 00` | `Xz` |
| `%PDF` | `Pdf` |
| `7F 45 4C 46` | `Elf` |
| `MZ` (DOS stub) | `Pe` |
| `FE ED FA CE` / `CE FA ED FE` / `FE ED FA CF` / `CF FA ED FE` | `MachO` |
| bytes 4-8 = `ftyp` | `Mp4` |
| `ID3` / `FF FB` / `FF F3` | `Mp3` |
| `SQLite format 3\0` | `Sqlite3` |

Classifications missed by the current detector: text-shaped
formats (HTML / JSON / XML / plaintext) — flowscope's
`detect::shannon_entropy` and `detect::is_high_entropy`
primitives are the right building blocks for those.

## Usage recipe — HTTP body hashing

Pair with `HttpExchangeParser` and feed response bodies through
the sink:

```rust,ignore
use flowscope::detect::file::{Sha256Sink, FileHashSink};

let mut sink = Sha256Sink::new();
sink.update(http_response.body);
let evt = sink.finish();
println!("hash={} type={:?} bytes={}",
    evt.hash_hex, evt.file_type, evt.bytes);
```

## Usage recipe — TCP reassembler drain

For arbitrary reassembled streams (HTTP body extraction is just
one consumer), drive the sink from the reassembler's drain
output:

```rust,ignore
let mut sink = Sha256Sink::new();
for chunk in reassembler.drain() {
    sink.update(&chunk);
}
let evt = sink.finish();
```

## Cost notes

SHA-256 throughput on commodity x86_64 hardware is ~200-300
MB/s per core via the `sha2` crate (which uses SHA-NI when
available). At 1 Gbps line rate that's ~12-15% of one core.

MD5 throughput is comparable.

The 64-byte MIME probe is constant-overhead (one bounds check
per `update` call); it does not allocate.

## Out of scope

- **File extraction / storage.** Hashes only — flowscope does
  not write payload bytes to disk. For that, plug
  Suricata-style file-store on top.
- **YARA / AV matching.** Bring your own AV against the hashes
  we emit.
- **Streaming decompression** (gzip / br / zstd). Hashes are
  over raw on-wire bytes; consumers wanting decompressed-
  content hashes wrap the sink at their decompression
  boundary.
- **Encrypted-content hashing.** TLS-encrypted bytes hash to
  the ciphertext; consumers wanting plaintext hashes need
  session keys (out of scope for a passive observer).

## References

- [Suricata `file.md5` / `file.sha256` keywords](https://docs.suricata.io/en/latest/file-extraction/file-extraction.html)
- [VirusTotal hash query API](https://developers.virustotal.com/reference/files)
- [ClamAV hash signature format](https://docs.clamav.net/manual/Signatures/HashSignatures.html)
- [libmagic file-type signatures](https://github.com/file/file/blob/master/magic/Magdir)

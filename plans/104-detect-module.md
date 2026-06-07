# Plan 104 — `flowscope::detect` — lightweight detection primitives

## Summary

Ship a small `flowscope::detect` module with the half-dozen
detection primitives the example-writing pass surfaced as
"every detector reinvents this":

- **`shannon_entropy(&[u8]) -> f64`** — DNS tunnel detection,
  fingerprinting noise.
- **`ngram_distribution(&[u8], n) -> NgramDist`** — frequency
  distribution for further analysis.
- **`is_base64ish(&str) -> bool`** — base64-shaped string
  detection.
- **`is_hex_string(&str) -> bool`** — hex-shaped string
  detection.
- **`hamming_distance(&[u8], &[u8]) -> usize`** — fixed-length
  byte comparison.
- **`is_high_entropy(&[u8], threshold) -> bool`** — shorthand
  for `shannon_entropy(b) >= threshold`.

Theme 5 follow-up. Keep this module deliberately minimal —
detection logic compounds quickly and we want the building
blocks, not the whole tower.

## Status

**Ready to implement.** Targets 0.10.0.

## Prerequisites

None.

## Out of scope

- **ML-shaped detection** (classification, clustering). Too
  domain-specific for the core crate.
- **Regex-based detection.** Consumers use `regex` directly.
- **Known-bad signature lists** (Suricata rule format,
  Snort signatures). Belongs in a threat-intel sister crate.
- **YARA-style rule engine.** Same.
- **Statistical anomaly detection** (variance, z-score).
  Useful, but the bar should be high — only ship when a
  consumer needs them.

---

## API

```rust
// src/detect/mod.rs

/// Shannon entropy in bits per byte. `0.0` for empty.
/// Range: `[0.0, 8.0]`.
pub fn shannon_entropy(bytes: &[u8]) -> f64;

/// `true` iff `shannon_entropy(bytes) >= threshold`.
/// Shortcut for the common pattern.
pub fn is_high_entropy(bytes: &[u8], threshold: f64) -> bool;

/// `true` iff every char in `s` is in the base64 alphabet
/// (`A-Z a-z 0-9 + / =`) and the length is reasonable
/// (≥ 16 chars).
pub fn is_base64ish(s: &str) -> bool;

/// `true` iff every char in `s` is `[0-9a-fA-F]` and the
/// length is reasonable (≥ 16 chars).
pub fn is_hex_string(s: &str) -> bool;

/// Hamming distance between two equal-length byte slices.
/// Returns `None` if lengths differ.
pub fn hamming_distance(a: &[u8], b: &[u8]) -> Option<usize>;

/// N-gram distribution over the input bytes.
pub fn ngram_distribution(bytes: &[u8], n: usize) -> NgramDist;

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct NgramDist {
    pub n: usize,
    pub samples: u64,
    pub counts: HashMap<Vec<u8>, u64>,
}

impl NgramDist {
    /// Most-common N-gram + its count.
    pub fn mode(&self) -> Option<(&Vec<u8>, u64)>;

    /// Entropy of the n-gram distribution (in bits per n-gram).
    pub fn entropy(&self) -> f64;

    /// Number of distinct n-grams seen.
    pub fn distinct(&self) -> usize;
}
```

---

## Files

```
src/detect/mod.rs            # six functions + NgramDist
tests/detect.rs              # coverage
examples/dns_tunnel_detector.rs   # MIGRATED to use shannon_entropy
docs/recipes.md              # extend correlate / detect recipe section
CHANGELOG.md                 # 0.10 entry
```

## Implementation steps

1. Add `src/detect/mod.rs` with the six functions + NgramDist.
2. Wire `pub mod detect` in `src/lib.rs`.
3. `tests/detect.rs`:
   - `shannon_entropy(b"AAAA")` = 0.0 (uniform → low entropy).
   - `shannon_entropy(b"abcd")` > 1.99 (max 2.0 for 4 chars).
   - `is_base64ish("AAAA====")` = true.
   - `is_hex_string("deadbeef")` = true.
   - `hamming_distance(b"foo", b"fob")` = Some(1).
   - `ngram_distribution(b"aaab", 2)` → {"aa": 2, "ab": 1}.
4. Migrate `examples/dns_tunnel_detector.rs` to use the
   shipped helper.
5. CHANGELOG entry under 0.10.0 "Added".

## Acceptance criteria

- Six functions ship.
- Example migrated; LoC down ~15.
- 6+ tests pass.
- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- CHANGELOG entry.

## Risks

- **Module sprawl.** `detect` is a slippery slope — every new
  use case wants a new helper. Mitigation: hard "consumer
  must ask" rule for additions beyond the initial six.
  Document the rule in `docs/recipes.md`.

## Effort

| Surface | LoC | Hours |
|---------|-----|-------|
| Six functions + NgramDist | ~150 | 3 |
| Tests | ~120 | 2 |
| Example migration | ~−15 net | 0.5 |
| Docs + CHANGELOG | ~40 | 0.5 |
| **Total** | **~295 LoC** | **~6 hours** |

## Provenance

Postmortem theme 5:

> Wrote Shannon entropy in 13 lines. Common enough it should
> ship. … These are pre-1.0 add. Don't overcommit — keep it
> to the half-dozen building blocks every detector reaches
> for.

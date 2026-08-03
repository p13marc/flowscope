//! HPACK encoding (RFC 7541) — the forward direction.
//!
//! [`HpackEncoder`] is the counterpart to the decoder inside
//! [`Http2Parser`](super::Http2Parser), for a proxy that modifies a
//! header and has to re-emit the field block.

use bytes::Bytes;

use super::error::Http2Error;
use super::hpack::{DynamicTable, MAX_FIELDS_PER_BLOCK, STATIC_TABLE, entry_size};
use super::huffman;

/// How a field may be compressed (RFC 7541 §6.2, §7.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum HeaderSensitivity {
    /// May enter the dynamic table and be referenced by index later.
    /// The default, and where all the compression comes from.
    #[default]
    Indexable,
    /// Compressed, but never added to the table (§6.2.2). For
    /// high-cardinality values that would only churn it. An
    /// intermediary is still free to index it.
    NotIndexed,
    /// Never indexed (§6.2.3): not added here, and intermediaries are
    /// forbidden from adding it either. The representation for
    /// anything an attacker must not be able to guess a byte at a
    /// time.
    Sensitive,
}

/// When to Huffman-code a string literal (RFC 7541 §5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum HuffmanPolicy {
    /// Emit whichever of Huffman and raw is shorter. The only choice
    /// that can never make a block bigger.
    #[default]
    WhenSmaller,
    /// Never Huffman-code. Larger on the wire; useful when the
    /// receiver is a human or a debugging tool.
    Never,
}

/// Classifies a field for [`HpackEncoder::with_sensitivity`].
///
/// A plain `fn` pointer rather than a boxed closure, so
/// [`HpackEncoder`] keeps `Debug + Clone + Send + Sync` like every
/// other parser type in the crate.
pub type SensitivityFn = fn(name: &[u8], value: &[u8]) -> HeaderSensitivity;

/// The default classifier: never-index credential-bearing fields, do
/// not index high-cardinality ones, index everything else.
///
/// # Why `cookie` is on the never-index list
///
/// It is also the field where indexing pays best, so this costs real
/// bytes. The reason it is still the default: an inline proxy
/// typically pools *one* backend connection across many clients, so
/// one HPACK dynamic table ends up carrying every client's cookies.
/// A CRIME-family oracle — inject a guess, watch the block shrink
/// when the guess is right — then reads one tenant's session cookie
/// out of another tenant's request. Override with
/// [`HpackEncoder::with_sensitivity`] if your deployment is
/// single-tenant, or split cookies into crumbs and mark only the
/// session crumb sensitive.
pub fn default_sensitivity(name: &[u8], _value: &[u8]) -> HeaderSensitivity {
    match name {
        b"authorization" | b"proxy-authorization" | b"cookie" | b"set-cookie" => {
            HeaderSensitivity::Sensitive
        }
        // Effectively unique per message: indexing them evicts
        // entries that would have been reused, and buys nothing.
        b":path" | b"date" | b"etag" | b"if-none-match" | b"last-modified" | b"content-length"
        | b"x-request-id" | b"traceparent" => HeaderSensitivity::NotIndexed,
        _ => HeaderSensitivity::Indexable,
    }
}

/// Where a field sits in the index space (RFC 7541 §2.3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Match {
    /// Name and value both matched at this index.
    Full(u64),
    /// Only the name matched.
    Name(u64),
    None,
}

/// Static table first, then dynamic — so a field present in both gets
/// the low, permanent index rather than one eviction can invalidate.
///
/// A linear scan. The static half is 61 entries filtered by a
/// length-and-first-byte mismatch on the first comparison; the
/// dynamic half is bounded by the encoder's own table size, which
/// defaults to 4 KiB (≤128 entries) precisely so this stays cheap. A
/// reverse index would have to be a `OnceLock` or a new dependency
/// for the static half — the names are not sorted, so `binary_search`
/// is out — and for the dynamic half would need absolute insertion
/// sequence numbers, because indices are positional from the front
/// and every insert shifts them all.
fn find(table: &DynamicTable, name: &[u8], value: &[u8]) -> Match {
    let mut name_only: Option<u64> = None;
    for (i, (n, v)) in STATIC_TABLE.iter().enumerate() {
        if n.as_bytes() != name {
            continue;
        }
        let idx = (i + 1) as u64;
        if v.as_bytes() == value {
            return Match::Full(idx);
        }
        name_only.get_or_insert(idx);
    }
    for (i, (n, v)) in table.iter().enumerate() {
        if n.as_ref() != name {
            continue;
        }
        let idx = (STATIC_TABLE.len() + 1 + i) as u64;
        if v.as_ref() == value {
            return Match::Full(idx);
        }
        name_only.get_or_insert(idx);
    }
    name_only.map_or(Match::None, Match::Name)
}

/// Write an HPACK variable-length integer with a `prefix_bits`-bit
/// prefix, OR-ing `flags` into the unused high bits (RFC 7541 §5.1).
///
/// The exact inverse of the decoder's `decode_int`: that reads
/// `first & mask` and, when it saturates, *adds* the continuation
/// groups to `mask` — so this subtracts `mask` before splitting into
/// 7-bit groups.
pub(crate) fn encode_int(out: &mut Vec<u8>, value: u64, prefix_bits: u8, flags: u8) {
    debug_assert!((1..=8).contains(&prefix_bits));
    let mask = u64::from((1u16 << prefix_bits) - 1);
    debug_assert_eq!(
        u64::from(flags) & mask,
        0,
        "flags must not overlap the prefix"
    );
    if value < mask {
        out.push(flags | value as u8);
        return;
    }
    out.push(flags | mask as u8);
    let mut rest = value - mask;
    while rest >= 128 {
        out.push((rest as u8 & 0x7f) | 0x80);
        rest >>= 7;
    }
    out.push(rest as u8);
}

/// Write a string literal, Huffman-coded if the policy allows and it
/// is strictly shorter (RFC 7541 §5.2).
fn encode_string(out: &mut Vec<u8>, s: &[u8], policy: HuffmanPolicy) {
    if policy == HuffmanPolicy::WhenSmaller {
        let n = huffman::encoded_len(s);
        if n < s.len() {
            encode_int(out, n as u64, 7, 0x80);
            huffman::encode_into(out, s);
            return;
        }
    }
    encode_int(out, s.len() as u64, 7, 0x00);
    out.extend_from_slice(s);
}

/// The pseudo-headers HTTP/2 defines (RFC 9113 §8.3).
const PSEUDO: &[&[u8]] = &[
    b":method",
    b":scheme",
    b":authority",
    b":path",
    b":status",
    b":protocol",
];

/// Connection-specific fields HTTP/2 forbids (RFC 9113 §8.2.2).
const FORBIDDEN: &[&[u8]] = &[
    b"connection",
    b"keep-alive",
    b"proxy-connection",
    b"transfer-encoding",
    b"upgrade",
];

/// Refuse a field that could not legally be sent.
///
/// Always on, no knob. A proxy that re-emits CRLF inside a value has
/// built the h2→h1 downgrade smuggling primitive, and one that emits
/// an uppercase name or a `Connection` header has built a block the
/// peer must reject. Producing either is never the intent.
fn validate_field(name: &[u8], value: &[u8], seen_regular: &mut bool) -> Result<(), Http2Error> {
    if name.is_empty() {
        return Err(Http2Error::InvalidHeaderField);
    }
    let is_pseudo = name[0] == b':';
    if is_pseudo {
        if !PSEUDO.contains(&name) {
            return Err(Http2Error::InvalidHeaderField);
        }
        // §8.3: pseudo-headers precede every regular field.
        if *seen_regular {
            return Err(Http2Error::InvalidHeaderField);
        }
    } else {
        *seen_regular = true;
        if FORBIDDEN.contains(&name) {
            return Err(Http2Error::InvalidHeaderField);
        }
        // §8.2.2: `te` may be present, but only as `trailers`.
        if name == b"te" && value != b"trailers" {
            return Err(Http2Error::InvalidHeaderField);
        }
    }
    // §8.2.1: names are lowercase tokens. A colon is legal only at
    // position 0, already handled above.
    for (i, &b) in name.iter().enumerate() {
        let ok = b.is_ascii_lowercase()
            || b.is_ascii_digit()
            || matches!(
                b,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
            )
            || (i == 0 && b == b':');
        if !ok {
            return Err(Http2Error::InvalidHeaderField);
        }
    }
    // §8.2.1: no NUL, CR, or LF anywhere; no leading or trailing
    // space or horizontal tab.
    if value.iter().any(|&b| matches!(b, 0 | b'\r' | b'\n')) {
        return Err(Http2Error::InvalidHeaderField);
    }
    if let (Some(&first), Some(&last)) = (value.first(), value.last())
        && (matches!(first, b' ' | b'\t') || matches!(last, b' ' | b'\t'))
    {
        return Err(Http2Error::InvalidHeaderField);
    }
    Ok(())
}

/// The largest a field can encode to: the representation byte plus up
/// to two index continuation bytes, and a 7-bit-prefix length for
/// each of name and value. Huffman and indexing only ever shrink it.
fn max_encoded_len(name: &[u8], value: &[u8]) -> usize {
    4 + 5 + name.len() + 5 + value.len()
}

/// HPACK encoder for one direction of one connection.
///
/// # This is a model of the peer's decoder
///
/// The dynamic table this holds is not bookkeeping — it is what the
/// decoder at the far end believes. Every block this encoder produces
/// must be **actually sent, in order**: a block that is built and
/// then dropped leaves the two tables permanently out of step, and
/// the corruption surfaces frames later, on an unrelated stream. Use
/// one encoder per direction, and do not share it.
///
/// ```
/// use bytes::Bytes;
/// use flowscope::FlowSide;
/// use flowscope::http2::{
///     Http2Event, Http2Parser, HpackEncoder, PREFACE, write_headers,
/// };
///
/// let mut enc = HpackEncoder::new();
/// let fields = vec![
///     (Bytes::from_static(b":method"), Bytes::from_static(b"GET")),
///     (Bytes::from_static(b":scheme"), Bytes::from_static(b"https")),
///     (Bytes::from_static(b":authority"), Bytes::from_static(b"api.example")),
///     (Bytes::from_static(b":path"), Bytes::from_static(b"/v1/things")),
/// ];
/// let block = enc.encode(&fields).expect("encodable");
/// let frames = write_headers(1, &block, true, 16_384).expect("framable");
///
/// // Round-trip it through the parser to prove it is on-the-wire h2.
/// let mut p = Http2Parser::new();
/// p.push(FlowSide::Initiator, &Bytes::from_static(PREFACE));
/// p.push(FlowSide::Initiator, &Bytes::from(frames));
///
/// let Some(Http2Event::Head(head)) = p.next_event() else {
///     panic!("expected a head")
/// };
/// assert_eq!(head.authority(), Some("api.example"));
/// assert_eq!(head.path(), Some("/v1/things"));
/// ```
#[derive(Debug, Clone)]
pub struct HpackEncoder {
    table: DynamicTable,
    /// What the peer's decoder currently believes the limit to be.
    signalled_size: usize,
    /// The limit we want in force for the next block.
    target_size: usize,
    /// Smallest limit that has applied since the last signal — §4.2
    /// requires signalling it too, not just the final value.
    min_since_signal: usize,
    huffman: HuffmanPolicy,
    sensitivity: SensitivityFn,
    max_block_bytes: usize,
}

/// HTTP/2's default `SETTINGS_HEADER_TABLE_SIZE` (RFC 9113 §6.5.2).
const DEFAULT_TABLE_SIZE: usize = 4096;

impl Default for HpackEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl HpackEncoder {
    /// A new encoder at the HTTP/2 default table size (4096 bytes),
    /// the default indexing policy, and Huffman when it helps.
    pub fn new() -> Self {
        Self {
            table: DynamicTable::new(DEFAULT_TABLE_SIZE, DEFAULT_TABLE_SIZE),
            signalled_size: DEFAULT_TABLE_SIZE,
            target_size: DEFAULT_TABLE_SIZE,
            min_since_signal: DEFAULT_TABLE_SIZE,
            huffman: HuffmanPolicy::default(),
            sensitivity: default_sensitivity,
            max_block_bytes: 64 * 1024,
        }
    }

    /// Cap the table this encoder will use, whatever the peer allows.
    ///
    /// RFC 7541 explicitly permits using less than the peer offers. A
    /// larger table buys little extra compression, costs a linear
    /// scan per field, and widens the window a CRIME-family oracle
    /// operates in.
    #[must_use]
    pub fn with_max_table_size(mut self, n: usize) -> Self {
        self.table = DynamicTable::new(n.min(self.table.max_size()), n);
        self.target_size = self.target_size.min(n);
        self.signalled_size = self.signalled_size.min(n);
        self.min_since_signal = self.min_since_signal.min(n);
        self
    }

    /// Choose when string literals are Huffman-coded.
    #[must_use]
    pub fn with_huffman(mut self, policy: HuffmanPolicy) -> Self {
        self.huffman = policy;
        self
    }

    /// Replace the per-field indexing policy. See
    /// [`default_sensitivity`] for what the default does and why.
    #[must_use]
    pub fn with_sensitivity(mut self, f: SensitivityFn) -> Self {
        self.sensitivity = f;
        self
    }

    /// Cap one encoded field block. Default 64 KiB, matching the
    /// decoder's `max_header_block_bytes`.
    #[must_use]
    pub fn with_max_block_bytes(mut self, n: usize) -> Self {
        self.max_block_bytes = n;
        self
    }

    /// Apply the peer's `SETTINGS_HEADER_TABLE_SIZE` (RFC 9113
    /// §6.5.2), as reported by
    /// [`Http2Event::Settings`](super::Http2Event::Settings).
    ///
    /// The change takes effect as a size-update instruction at the
    /// start of the next block.
    pub fn set_peer_max_table_size(&mut self, n: usize) {
        // We may always use less than the peer allows; never more.
        let effective = n.min(self.table.hard_max_size());
        self.min_since_signal = self.min_since_signal.min(effective);
        self.target_size = effective;
    }

    /// Bytes currently accounted to the dynamic table.
    pub fn table_size(&self) -> usize {
        self.table.size()
    }

    /// Entries currently held in the dynamic table.
    pub fn table_len(&self) -> usize {
        self.table.len()
    }

    /// Encode one complete field block.
    pub fn encode(&mut self, fields: &[(Bytes, Bytes)]) -> Result<Vec<u8>, Http2Error> {
        let mut out = Vec::new();
        self.encode_into(fields, &mut out)?;
        Ok(out)
    }

    /// As [`encode`](Self::encode), appending to `out`.
    ///
    /// **All or nothing.** On error nothing is written and the
    /// dynamic table has not moved, so the encoder stays usable and
    /// in step with the peer. That matters more than it looks: if
    /// encoding bailed halfway, the table would hold inserts for
    /// fields whose bytes never reached the wire, which is permanent
    /// desync — the exact failure this type exists to prevent.
    ///
    /// It is achieved by bounding the output before touching
    /// anything, rather than by rolling back. Deferring the inserts
    /// to end-of-block would be wrong: the peer's decoder inserts as
    /// it goes, so an insert early in a block can evict an entry a
    /// later field in the same block references by index.
    pub fn encode_into(
        &mut self,
        fields: &[(Bytes, Bytes)],
        out: &mut Vec<u8>,
    ) -> Result<(), Http2Error> {
        // Mirror the decoder's own ceiling: never emit a block our
        // own decoder would refuse.
        if fields.len() > MAX_FIELDS_PER_BLOCK {
            return Err(Http2Error::HeaderListTooLong);
        }
        let mut seen_regular = false;
        // Room for two size-update instructions (§4.2).
        let mut bound = 8usize;
        for (n, v) in fields {
            validate_field(n, v, &mut seen_regular)?;
            bound = bound.saturating_add(max_encoded_len(n, v));
        }
        if bound > self.max_block_bytes {
            return Err(Http2Error::HeaderListTooLong);
        }
        // Past this point nothing can fail, so the table and `out`
        // move together or not at all.
        self.emit_size_updates(out);
        for (n, v) in fields {
            self.encode_field(n, v, out);
        }
        Ok(())
    }

    /// Emit the §6.3 size updates the peer has not yet been told
    /// about.
    fn emit_size_updates(&mut self, out: &mut Vec<u8>) {
        if self.min_since_signal < self.signalled_size {
            // §4.2: the smallest size that applied in the interval
            // has to be signalled too. Skipping it leaves the peer's
            // decoder holding entries we already evicted.
            encode_int(out, self.min_since_signal as u64, 5, 0x20);
            self.table.set_max_size(self.min_since_signal);
            self.signalled_size = self.min_since_signal;
        }
        if self.target_size != self.signalled_size {
            encode_int(out, self.target_size as u64, 5, 0x20);
            self.table.set_max_size(self.target_size);
            self.signalled_size = self.target_size;
        }
        self.min_since_signal = self.signalled_size;
    }

    fn encode_field(&mut self, name: &[u8], value: &[u8], out: &mut Vec<u8>) {
        let sens = (self.sensitivity)(name, value);
        let m = find(&self.table, name, value);

        // §6.1 Indexed. A *static* full match reveals nothing — that
        // table is public and constant. A *dynamic* one proves the
        // value repeated, which is the CRIME-family oracle, so a
        // sensitive field never takes it.
        if let Match::Full(i) = m
            && (i as usize <= STATIC_TABLE.len() || sens != HeaderSensitivity::Sensitive)
        {
            encode_int(out, i, 7, 0x80);
            return;
        }

        let name_idx = match m {
            Match::Full(i) | Match::Name(i) => i,
            Match::None => 0,
        };
        // §4.4: indexing an entry over half the table evicts most of
        // what is useful for one value. Degrade rather than churn.
        let indexable = sens == HeaderSensitivity::Indexable
            && entry_size(name, value) * 2 <= self.table.max_size();

        let (prefix, flags) = match (indexable, sens) {
            (true, _) => (6, 0x40),                             // §6.2.1
            (false, HeaderSensitivity::Sensitive) => (4, 0x10), // §6.2.3
            (false, _) => (4, 0x00),                            // §6.2.2
        };
        encode_int(out, name_idx, prefix, flags);
        if name_idx == 0 {
            encode_string(out, name, self.huffman);
        }
        encode_string(out, value, self.huffman);

        if indexable {
            // Eagerly, and in order: the peer's decoder does the
            // same, and a later field in this very block may
            // reference what this insert evicts.
            self.table
                .insert(Bytes::copy_from_slice(name), Bytes::copy_from_slice(value));
        }
    }

    /// Start with the peer already believing a non-default table
    /// size, so the RFC Appendix C vectors — which set it out of band
    /// — can be reproduced byte for byte.
    ///
    /// Crate-private on purpose: a public "pretend the peer already
    /// knows" constructor is a desync generator.
    #[cfg(test)]
    fn with_signalled_table_size(mut self, n: usize) -> Self {
        self.table = DynamicTable::new(n, n);
        self.signalled_size = n;
        self.target_size = n;
        self.min_since_signal = n;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http2::hpack::HpackDecoder;

    fn b(s: &[u8]) -> Bytes {
        Bytes::copy_from_slice(s)
    }

    fn fields(pairs: &[(&str, &str)]) -> Vec<(Bytes, Bytes)> {
        pairs
            .iter()
            .map(|(n, v)| (b(n.as_bytes()), b(v.as_bytes())))
            .collect()
    }

    /// The RFC's vectors assume "index everything indexable".
    fn rfc_sensitivity(_: &[u8], _: &[u8]) -> HeaderSensitivity {
        HeaderSensitivity::Indexable
    }

    fn rfc_encoder() -> HpackEncoder {
        HpackEncoder::new()
            .with_sensitivity(rfc_sensitivity)
            .with_huffman(HuffmanPolicy::Never)
    }

    // ── §5.1 integers ────────────────────────────────────────────

    #[test]
    fn integers_match_the_rfc_examples() {
        let mut v = Vec::new();
        encode_int(&mut v, 10, 5, 0); // C.1.1
        assert_eq!(v, [0x0a]);

        v.clear();
        encode_int(&mut v, 1337, 5, 0); // C.1.2
        assert_eq!(v, [0x1f, 0x9a, 0x0a]);

        v.clear();
        encode_int(&mut v, 42, 8, 0); // C.1.3
        assert_eq!(v, [0x2a]);
    }

    #[test]
    fn integers_round_trip_at_every_prefix_width() {
        use crate::http2::hpack::decode_int_for_test as decode_int;
        // The decoder refuses a continuation that would need a 63-bit
        // shift, rather than wrapping into a plausible-looking index
        // — so 2^63 − 1 is the largest value the pair can carry, and
        // the boundary is worth pinning from this side too.
        const MAX_REPRESENTABLE: u64 = (1u64 << 63) - 1;
        for prefix in 1..=8u8 {
            let mask = (1u64 << prefix) - 1;
            for v in [
                0,
                1,
                mask.saturating_sub(1),
                mask,
                mask + 1,
                255,
                1337,
                u64::from(u32::MAX),
                MAX_REPRESENTABLE,
            ] {
                let mut buf = Vec::new();
                encode_int(&mut buf, v, prefix, 0);
                let (got, rest) = decode_int(&buf, prefix).expect("decodes");
                assert_eq!(got, v, "prefix {prefix}, value {v}");
                assert!(rest.is_empty(), "prefix {prefix}, value {v}");
            }
            // Past that the decoder refuses rather than wraps.
            let mut buf = Vec::new();
            encode_int(&mut buf, u64::MAX, prefix, 0);
            assert_eq!(
                decode_int(&buf, prefix),
                Err(Http2Error::HpackIntegerOverflow),
                "prefix {prefix}"
            );
        }
    }

    #[test]
    fn flags_survive_the_prefix() {
        // The representation bits live in the prefix's unused high
        // bits; a value that saturates the prefix must not clobber
        // them.
        let mut v = Vec::new();
        encode_int(&mut v, 1337, 5, 0x20);
        assert_eq!(v[0] & 0xe0, 0x20, "the size-update pattern survives");
        assert_eq!(v, [0x3f, 0x9a, 0x0a]);
    }

    // ── Appendix C, encode direction ─────────────────────────────

    #[test]
    fn c_2_1_literal_with_indexing() {
        let mut e = rfc_encoder();
        let out = e
            .encode(&fields(&[("custom-key", "custom-header")]))
            .unwrap();
        assert_eq!(
            out,
            [
                0x40, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65, 0x79, 0x0d, 0x63,
                0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72,
            ]
        );
        assert_eq!(e.table_size(), 55);
    }

    #[test]
    fn c_2_2_literal_without_indexing() {
        let mut e = HpackEncoder::new().with_huffman(HuffmanPolicy::Never);
        // `:path` is NotIndexed under the default policy, which is
        // exactly the representation C.2.2 pins.
        let out = e.encode(&fields(&[(":path", "/sample/path")])).unwrap();
        assert_eq!(
            out,
            [
                0x04, 0x0c, 0x2f, 0x73, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2f, 0x70, 0x61, 0x74, 0x68,
            ]
        );
        assert_eq!(e.table_len(), 0, "it must not enter the table");
    }

    #[test]
    fn c_2_3_literal_never_indexed() {
        let e = HpackEncoder::new().with_huffman(HuffmanPolicy::Never);
        // `password` is not on the default sensitive list, so ask for
        // it explicitly — C.2.3's whole point is the never-index bit.
        fn sensitive(_: &[u8], _: &[u8]) -> HeaderSensitivity {
            HeaderSensitivity::Sensitive
        }
        let out = e
            .with_sensitivity(sensitive)
            .encode(&fields(&[("password", "secret")]))
            .unwrap();
        assert_eq!(
            out,
            [
                0x10, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x06, 0x73, 0x65, 0x63,
                0x72, 0x65, 0x74,
            ]
        );
    }

    #[test]
    fn c_2_4_indexed_field() {
        let mut e = rfc_encoder();
        let out = e.encode(&fields(&[(":method", "GET")])).unwrap();
        assert_eq!(out, [0x82]);
    }

    /// C.3: three requests sharing one dynamic table. The strongest
    /// test available — it pins eviction ordering and index
    /// arithmetic byte for byte across blocks.
    #[test]
    fn c_3_request_sequence_without_huffman() {
        let mut e = rfc_encoder();

        let first = e
            .encode(&fields(&[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
            ]))
            .unwrap();
        assert_eq!(
            first,
            [
                0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70,
                0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
            ]
        );
        assert_eq!(e.table_size(), 57);

        let second = e
            .encode(&fields(&[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
                ("cache-control", "no-cache"),
            ]))
            .unwrap();
        assert_eq!(
            second,
            [
                0x82, 0x86, 0x84, 0xbe, 0x58, 0x08, 0x6e, 0x6f, 0x2d, 0x63, 0x61, 0x63, 0x68, 0x65,
            ]
        );
        assert_eq!(e.table_size(), 110);

        let third = e
            .encode(&fields(&[
                (":method", "GET"),
                (":scheme", "https"),
                (":path", "/index.html"),
                (":authority", "www.example.com"),
                ("custom-key", "custom-value"),
            ]))
            .unwrap();
        assert_eq!(
            third,
            [
                0x82, 0x87, 0x85, 0xbf, 0x40, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b,
                0x65, 0x79, 0x0c, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x76, 0x61, 0x6c, 0x75,
                0x65,
            ]
        );
        assert_eq!(e.table_size(), 164);
    }

    /// C.4: the same sequence Huffman-coded. `WhenSmaller` reproduces
    /// it because every string in C.4 is strictly shorter Huffmaned.
    #[test]
    fn c_4_request_sequence_with_huffman() {
        let mut e = HpackEncoder::new().with_sensitivity(rfc_sensitivity);

        let first = e
            .encode(&fields(&[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
            ]))
            .unwrap();
        assert_eq!(
            first,
            [
                0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab,
                0x90, 0xf4, 0xff,
            ]
        );
        assert_eq!(e.table_size(), 57);

        let second = e
            .encode(&fields(&[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
                ("cache-control", "no-cache"),
            ]))
            .unwrap();
        assert_eq!(
            second,
            [
                0x82, 0x86, 0x84, 0xbe, 0x58, 0x86, 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf
            ]
        );
        assert_eq!(e.table_size(), 110);
    }

    /// C.5: responses with a 256-byte table, so eviction actually
    /// bites. Set out of band by the RFC, hence the test-only
    /// constructor.
    #[test]
    fn c_5_response_sequence_evicts() {
        let mut e = rfc_encoder().with_signalled_table_size(256);

        let first = e
            .encode(&fields(&[
                (":status", "302"),
                ("cache-control", "private"),
                ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                ("location", "https://www.example.com"),
            ]))
            .unwrap();
        assert_eq!(
            first,
            [
                0x48, 0x03, 0x33, 0x30, 0x32, 0x58, 0x07, 0x70, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65,
                0x61, 0x1d, 0x4d, 0x6f, 0x6e, 0x2c, 0x20, 0x32, 0x31, 0x20, 0x4f, 0x63, 0x74, 0x20,
                0x32, 0x30, 0x31, 0x33, 0x20, 0x32, 0x30, 0x3a, 0x31, 0x33, 0x3a, 0x32, 0x31, 0x20,
                0x47, 0x4d, 0x54, 0x6e, 0x17, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77,
                0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
            ]
        );
        assert_eq!(e.table_size(), 222);

        let second = e
            .encode(&fields(&[
                (":status", "307"),
                ("cache-control", "private"),
                ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                ("location", "https://www.example.com"),
            ]))
            .unwrap();
        assert_eq!(second, [0x48, 0x03, 0x33, 0x30, 0x37, 0xc1, 0xc0, 0xbf]);
        assert_eq!(e.table_size(), 222);
    }

    // ── Policy ───────────────────────────────────────────────────

    /// Pinned separately from the RFC vectors, which run under
    /// `rfc_sensitivity`: a future policy tweak must not be able to
    /// break the security property while those keep passing.
    #[test]
    fn credential_fields_are_never_indexed_by_default() {
        for name in [
            "authorization",
            "proxy-authorization",
            "cookie",
            "set-cookie",
        ] {
            let mut e = HpackEncoder::new();
            let out = e.encode(&fields(&[(name, "s3cret-value")])).unwrap();
            assert_eq!(
                out[0] & 0xf0,
                0x10,
                "{name} must use the never-indexed representation, got {:#04x}",
                out[0]
            );
            assert_eq!(e.table_len(), 0, "{name} must not enter the table");
        }
    }

    /// The CRIME regression: even when a sensitive field is already
    /// in the dynamic table, it must be re-emitted as a literal
    /// rather than as a one-byte index. An index would let an
    /// attacker who can inject a guess watch the block shrink when
    /// the guess is right.
    #[test]
    fn a_sensitive_field_never_takes_a_dynamic_index() {
        fn sometimes(name: &[u8], _: &[u8]) -> HeaderSensitivity {
            if name == b"x-secret" {
                HeaderSensitivity::Sensitive
            } else {
                HeaderSensitivity::Indexable
            }
        }
        let mut e = HpackEncoder::new().with_huffman(HuffmanPolicy::Never);
        // Seed the table with the exact pair, indexed.
        e.encode(&fields(&[("x-secret", "hunter2")])).unwrap();
        let seeded = e.table_len();
        e = e.with_sensitivity(sometimes);
        let out = e.encode(&fields(&[("x-secret", "hunter2")])).unwrap();
        assert!(
            out.len() > 1,
            "a sensitive repeat must be a literal, not an index: {out:?}"
        );
        assert_eq!(out[0] & 0xf0, 0x10, "and never-indexed at that");
        assert_eq!(e.table_len(), seeded, "and must not grow the table");
    }

    #[test]
    fn an_entry_over_half_the_table_is_not_indexed() {
        let mut e = HpackEncoder::new().with_max_table_size(128);
        let big = "v".repeat(80);
        e.encode(&fields(&[("x-big", &big)])).unwrap();
        assert_eq!(
            e.table_len(),
            0,
            "indexing it would evict everything useful for one value"
        );
    }

    #[test]
    fn representations_are_chosen_per_field() {
        let mut e = rfc_encoder().with_huffman(HuffmanPolicy::Never);
        // Static full match -> one byte.
        assert_eq!(e.encode(&fields(&[(":method", "GET")])).unwrap(), [0x82]);
        // Static name-only match -> 0x40 | 7 for :method.
        let out = e.encode(&fields(&[(":method", "PATCH")])).unwrap();
        assert_eq!(out[0], 0x42);
        // Unknown name -> 0x40 0x00 then two literals.
        let mut fresh = rfc_encoder().with_huffman(HuffmanPolicy::Never);
        let out = fresh.encode(&fields(&[("x-novel", "v")])).unwrap();
        assert_eq!(&out[..2], &[0x40, 0x07]);
    }

    // ── Size updates (§4.2 / §6.3) ───────────────────────────────

    #[test]
    fn shrinking_the_table_emits_a_size_update() {
        let mut e = HpackEncoder::new();
        e.set_peer_max_table_size(0);
        let out = e.encode(&fields(&[(":method", "GET")])).unwrap();
        assert_eq!(out, [0x20, 0x82], "a 0 size update, then the field");
    }

    /// §4.2: when several sizes applied between blocks, the *minimum*
    /// must be signalled as well as the final value. Skipping it
    /// leaves the peer holding entries we already evicted.
    #[test]
    fn the_minimum_size_in_the_interval_is_also_signalled() {
        let mut e = HpackEncoder::new();
        e.set_peer_max_table_size(100);
        e.set_peer_max_table_size(4096);
        let out = e.encode(&fields(&[(":method", "GET")])).unwrap();
        // 100 in a 5-bit prefix: 0x3f 0x45. Then 4096: 0x3f 0xe1 0x1f.
        assert_eq!(out, [0x3f, 0x45, 0x3f, 0xe1, 0x1f, 0x82]);

        // And a decoder ends up where we think it does.
        let mut d = HpackDecoder::new(4096, 64 * 1024);
        assert_eq!(d.decode(&out).unwrap().len(), 1);
    }

    #[test]
    fn a_raise_above_our_own_ceiling_emits_nothing() {
        let mut e = HpackEncoder::new().with_max_table_size(4096);
        e.set_peer_max_table_size(1024 * 1024);
        let out = e.encode(&fields(&[(":method", "GET")])).unwrap();
        assert_eq!(out, [0x82], "we never claim more than we will use");
    }

    // ── Validation and refusal ───────────────────────────────────

    #[test]
    fn malformed_fields_are_refused() {
        let cases: &[(&str, &str, &str)] = &[
            ("Content-Type", "text/plain", "uppercase name"),
            ("", "v", "empty name"),
            ("x bad", "v", "space in name"),
            (":bogus", "v", "unknown pseudo-header"),
            ("x-ok", "a\r\nInjected: 1", "CRLF in value"),
            ("x-ok", "a\0b", "NUL in value"),
            ("x-ok", " leading", "leading space"),
            ("x-ok", "trailing ", "trailing space"),
            ("connection", "keep-alive", "connection-specific"),
            ("transfer-encoding", "chunked", "connection-specific"),
            ("te", "gzip", "te other than trailers"),
        ];
        for (n, v, why) in cases {
            let mut e = HpackEncoder::new();
            assert_eq!(
                e.encode(&fields(&[(n, v)])),
                Err(Http2Error::InvalidHeaderField),
                "{why}"
            );
        }
        // `te: trailers` is the one permitted form.
        let mut e = HpackEncoder::new();
        assert!(e.encode(&fields(&[("te", "trailers")])).is_ok());
    }

    #[test]
    fn a_pseudo_header_after_a_regular_field_is_refused() {
        let mut e = HpackEncoder::new();
        assert_eq!(
            e.encode(&fields(&[("x-ok", "v"), (":method", "GET")])),
            Err(Http2Error::InvalidHeaderField)
        );
    }

    #[test]
    fn oversized_blocks_are_refused() {
        let mut e = HpackEncoder::new();
        let many: Vec<(Bytes, Bytes)> = (0..MAX_FIELDS_PER_BLOCK + 1)
            .map(|i| (b(format!("x-{i}").as_bytes()), b(b"v")))
            .collect();
        assert_eq!(e.encode(&many), Err(Http2Error::HeaderListTooLong));

        let mut e = HpackEncoder::new().with_max_block_bytes(64);
        let big = "v".repeat(1024);
        assert_eq!(
            e.encode(&fields(&[("x-big", &big)])),
            Err(Http2Error::HeaderListTooLong)
        );
    }

    /// The reason refusal is all-or-nothing: a half-encoded block
    /// would leave the table holding inserts whose bytes never
    /// reached the wire.
    #[test]
    fn a_refused_block_leaves_the_encoder_usable() {
        let mut e = HpackEncoder::new().with_huffman(HuffmanPolicy::Never);
        let before = e.table_size();
        assert!(
            e.encode(&fields(&[("x-fine", "v"), ("Bad-Name", "v"),]))
                .is_err()
        );
        assert_eq!(e.table_size(), before, "the refusal moved nothing");

        // The next block must decode against a decoder that only ever
        // saw *it* — proof the tables never diverged.
        let out = e.encode(&fields(&[("x-after", "w")])).unwrap();
        let mut d = HpackDecoder::new(4096, 64 * 1024);
        assert_eq!(d.decode(&out).unwrap(), vec![(b(b"x-after"), b(b"w"))]);
    }

    // ── Lockstep with the decoder ────────────────────────────────

    #[test]
    fn encoder_and_decoder_tables_stay_in_lockstep() {
        let mut e = HpackEncoder::new().with_sensitivity(rfc_sensitivity);
        let mut d = HpackDecoder::new(4096, 64 * 1024);
        let blocks = [
            vec![(":method", "GET"), (":authority", "a.example")],
            vec![
                (":method", "POST"),
                (":authority", "a.example"),
                ("x-a", "1"),
            ],
            vec![(":authority", "b.example"), ("x-a", "1"), ("x-b", "2")],
            vec![("x-c", "3")],
        ];
        for (i, blk) in blocks.iter().enumerate() {
            let f = fields(blk);
            let wire = e.encode(&f).unwrap();
            assert_eq!(d.decode(&wire).unwrap(), f, "block {i} round-trips");
            assert_eq!(e.table_len(), d.len(), "block {i}: table depth diverged");
            assert_eq!(
                e.table.snapshot(),
                d.table().snapshot(),
                "block {i}: table contents diverged"
            );
        }
    }
}

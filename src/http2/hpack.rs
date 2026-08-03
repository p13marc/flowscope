//! HPACK header decompression (RFC 7541).
//!
//! HPACK is stateful in a way that matters for a passive observer:
//! the encoder and decoder share a dynamic table built incrementally
//! from **every** field block on the connection, in order. Skipping a
//! block you do not care about desynchronises the table and corrupts
//! every later block. So the decoder must be fed everything, and it
//! must survive being fed something malformed without losing that
//! state or growing without bound.
//!
//! Hand-rolled rather than pulled in: the static table is a fixed 61
//! entries, the integer and string codings are small, and the
//! Huffman table is generated below — about 400 lines total against a
//! dependency whose maintenance would sit on flowscope's critical
//! path for a feature that is off by default.

use bytes::Bytes;

use super::error::Http2Error;

/// The RFC 7541 Appendix A static table, indices 1–61.
///
/// Index 0 is unused; entries are `(name, value)` with an empty value
/// where the table defines only a name.
pub(crate) const STATIC_TABLE: &[(&str, &str)] = &[
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/// One decoded header field.
pub(crate) type Field = (Bytes, Bytes);

/// Per-entry overhead the dynamic-table size accounting adds
/// (RFC 7541 §4.1).
pub(crate) const ENTRY_OVERHEAD: usize = 32;

/// A field block's field-count ceiling, independent of the peer's
/// `SETTINGS_MAX_HEADER_LIST_SIZE`, so a malicious peer cannot make
/// one block allocate without bound. The encoder mirrors it, so
/// flowscope never emits a block its own decoder would refuse.
pub(crate) const MAX_FIELDS_PER_BLOCK: usize = 256;

/// An entry's accounted size (RFC 7541 §4.1).
pub(crate) fn entry_size(name: &[u8], value: &[u8]) -> usize {
    name.len() + value.len() + ENTRY_OVERHEAD
}

/// The HPACK dynamic table (RFC 7541 §2.3.2).
///
/// Shared by [`HpackDecoder`] and
/// [`HpackEncoder`](super::hpack_encode::HpackEncoder) on purpose.
/// The encoder's copy is a *model of the peer's decoder*: if the two
/// applied §4.1 accounting or §4.4 eviction even slightly
/// differently, every later field block on the connection would
/// decode to plausible-looking nonsense. One implementation of the
/// rules is the only way to make that structurally impossible.
#[derive(Debug, Clone)]
pub(crate) struct DynamicTable {
    /// Most-recently-added first, as the index space requires.
    entries: std::collections::VecDeque<Field>,
    /// Current accounted size, per RFC 7541 §4.1.
    size: usize,
    /// The limit the peer's `SETTINGS_HEADER_TABLE_SIZE` sets.
    max_size: usize,
    /// A hard ceiling the peer cannot raise, whatever it advertises.
    hard_max_size: usize,
}

impl DynamicTable {
    pub(crate) fn new(max_size: usize, hard_max_size: usize) -> Self {
        Self {
            entries: std::collections::VecDeque::new(),
            size: 0,
            max_size: max_size.min(hard_max_size),
            hard_max_size,
        }
    }

    pub(crate) fn max_size(&self) -> usize {
        self.max_size
    }

    pub(crate) fn hard_max_size(&self) -> usize {
        self.hard_max_size
    }

    /// Bytes currently accounted to the table.
    pub(crate) fn size(&self) -> usize {
        self.size
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Entry `i`, newest first — the dynamic half of the index space.
    pub(crate) fn get(&self, i: usize) -> Option<&Field> {
        self.entries.get(i)
    }

    /// Newest first, for the encoder's reverse lookup.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &Field> {
        self.entries.iter()
    }

    /// Apply a new size limit, evicting down to it.
    pub(crate) fn set_max_size(&mut self, n: usize) {
        self.max_size = n.min(self.hard_max_size);
        self.evict();
    }

    /// Add an entry, evicting from the back until it fits.
    pub(crate) fn insert(&mut self, name: Bytes, value: Bytes) {
        let sz = entry_size(&name, &value);
        // §4.4: an entry larger than the whole table empties it and
        // is not added.
        if sz > self.max_size {
            self.entries.clear();
            self.size = 0;
            return;
        }
        self.size += sz;
        self.entries.push_front((name, value));
        self.evict();
    }

    fn evict(&mut self) {
        while self.size > self.max_size {
            match self.entries.pop_back() {
                Some((n, v)) => {
                    self.size = self.size.saturating_sub(entry_size(&n, &v));
                }
                None => {
                    self.size = 0;
                    break;
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> Vec<Field> {
        self.entries.iter().cloned().collect()
    }
}

/// HPACK decoder for one direction of one connection.
///
/// Must be fed every field block in receive order — see the module
/// docs for why.
#[derive(Debug, Clone)]
pub(crate) struct HpackDecoder {
    table: DynamicTable,
}

impl HpackDecoder {
    pub(crate) fn new(max_size: usize, hard_max_size: usize) -> Self {
        Self {
            table: DynamicTable::new(max_size, hard_max_size),
        }
    }

    /// Apply a `SETTINGS_HEADER_TABLE_SIZE` change from the peer.
    pub(crate) fn set_max_size(&mut self, n: usize) {
        self.table.set_max_size(n);
    }

    /// Number of entries currently held — for tests and diagnostics.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.table.len()
    }

    /// The table itself, for lockstep assertions against an encoder.
    #[cfg(test)]
    pub(crate) fn table(&self) -> &DynamicTable {
        &self.table
    }

    /// Decode one complete field block.
    ///
    /// On error the dynamic table is left as it stands: the entries
    /// added before the failure are real, and the peer's encoder
    /// believes in them. Resetting would guarantee corruption of
    /// every later block instead of merely risking it — the caller
    /// should treat an error as fatal to the connection.
    pub(crate) fn decode(&mut self, mut buf: &[u8]) -> Result<Vec<Field>, Http2Error> {
        let mut out = Vec::new();
        while !buf.is_empty() {
            if out.len() >= MAX_FIELDS_PER_BLOCK {
                return Err(Http2Error::HeaderListTooLong);
            }
            let first = buf[0];
            if first & 0x80 != 0 {
                // 6.1 Indexed Header Field.
                let (idx, rest) = decode_int(buf, 7)?;
                buf = rest;
                out.push(self.resolve(idx)?);
            } else if first & 0x40 != 0 {
                // 6.2.1 Literal with Incremental Indexing.
                let (name, value, rest) = self.decode_literal(buf, 6)?;
                buf = rest;
                self.table.insert(name.clone(), value.clone());
                out.push((name, value));
            } else if first & 0x20 != 0 {
                // 6.3 Dynamic Table Size Update.
                let (n, rest) = decode_int(buf, 5)?;
                buf = rest;
                let n = usize::try_from(n).map_err(|_| Http2Error::HpackInvalidIndex)?;
                if n > self.table.hard_max_size() {
                    return Err(Http2Error::HpackTableSizeExceeded);
                }
                self.table.set_max_size(n);
            } else {
                // 6.2.2 / 6.2.3 Literal without / never indexed.
                let (name, value, rest) = self.decode_literal(buf, 4)?;
                buf = rest;
                out.push((name, value));
            }
        }
        Ok(out)
    }

    /// Decode a literal field whose name may be indexed.
    fn decode_literal<'a>(
        &self,
        buf: &'a [u8],
        prefix: u8,
    ) -> Result<(Bytes, Bytes, &'a [u8]), Http2Error> {
        let (idx, rest) = decode_int(buf, prefix)?;
        let (name, rest) = if idx == 0 {
            decode_string(rest)?
        } else {
            let (n, _) = self.resolve(idx)?;
            (n, rest)
        };
        let (value, rest) = decode_string(rest)?;
        Ok((name, value, rest))
    }

    /// Resolve an index into the static or dynamic table.
    fn resolve(&self, idx: u64) -> Result<Field, Http2Error> {
        if idx == 0 {
            return Err(Http2Error::HpackInvalidIndex);
        }
        let idx = usize::try_from(idx).map_err(|_| Http2Error::HpackInvalidIndex)?;
        if idx <= STATIC_TABLE.len() {
            let (n, v) = STATIC_TABLE[idx - 1];
            return Ok((
                Bytes::from_static(n.as_bytes()),
                Bytes::from_static(v.as_bytes()),
            ));
        }
        self.table
            .get(idx - STATIC_TABLE.len() - 1)
            .cloned()
            .ok_or(Http2Error::HpackInvalidIndex)
    }
}

/// Decode an HPACK variable-length integer with an `prefix`-bit
/// prefix (RFC 7541 §5.1).
fn decode_int(buf: &[u8], prefix: u8) -> Result<(u64, &[u8]), Http2Error> {
    let Some(&first) = buf.first() else {
        return Err(Http2Error::HpackTruncated);
    };
    let mask = (1u16 << prefix) - 1;
    let mut value = u64::from(u16::from(first) & mask);
    if value < u64::from(mask) {
        return Ok((value, &buf[1..]));
    }
    let mut shift = 0u32;
    let mut i = 1usize;
    loop {
        let Some(&b) = buf.get(i) else {
            return Err(Http2Error::HpackTruncated);
        };
        i += 1;
        // Refuse a continuation long enough to overflow rather than
        // wrapping into a plausible-looking index.
        if shift >= 63 {
            return Err(Http2Error::HpackIntegerOverflow);
        }
        value = value
            .checked_add(u64::from(b & 0x7f) << shift)
            .ok_or(Http2Error::HpackIntegerOverflow)?;
        shift += 7;
        if b & 0x80 == 0 {
            return Ok((value, &buf[i..]));
        }
    }
}

/// Decode a length-prefixed string literal, Huffman-decoding it if
/// the H bit is set (RFC 7541 §5.2).
fn decode_string(buf: &[u8]) -> Result<(Bytes, &[u8]), Http2Error> {
    let Some(&first) = buf.first() else {
        return Err(Http2Error::HpackTruncated);
    };
    let huffman = first & 0x80 != 0;
    let (len, rest) = decode_int(buf, 7)?;
    let len = usize::try_from(len).map_err(|_| Http2Error::HpackIntegerOverflow)?;
    if rest.len() < len {
        return Err(Http2Error::HpackTruncated);
    }
    let (raw, tail) = rest.split_at(len);
    let out = if huffman {
        Bytes::from(super::huffman::decode(raw)?)
    } else {
        Bytes::copy_from_slice(raw)
    };
    Ok((out, tail))
}

/// `decode_int` for the encoder's round-trip test, which lives in a
/// sibling module.
#[cfg(test)]
pub(crate) fn decode_int_for_test(buf: &[u8], prefix: u8) -> Result<(u64, &[u8]), Http2Error> {
    decode_int(buf, prefix)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dec() -> HpackDecoder {
        HpackDecoder::new(4096, 65536)
    }

    fn as_pairs(fields: &[Field]) -> Vec<(String, String)> {
        fields
            .iter()
            .map(|(n, v)| {
                (
                    String::from_utf8_lossy(n).into_owned(),
                    String::from_utf8_lossy(v).into_owned(),
                )
            })
            .collect()
    }

    // ── RFC 7541 Appendix C worked examples ───────────────────────

    #[test]
    fn c_2_1_literal_with_indexing() {
        // custom-key: custom-header
        let wire = [
            0x40, 0x0a, b'c', b'u', b's', b't', b'o', b'm', b'-', b'k', b'e', b'y', 0x0d, b'c',
            b'u', b's', b't', b'o', b'm', b'-', b'h', b'e', b'a', b'd', b'e', b'r',
        ];
        let mut d = dec();
        let got = d.decode(&wire).unwrap();
        assert_eq!(
            as_pairs(&got),
            vec![("custom-key".into(), "custom-header".into())]
        );
        assert_eq!(d.len(), 1, "incremental indexing adds an entry");
    }

    #[test]
    fn c_2_2_literal_without_indexing() {
        // :path: /sample/path
        let wire = [
            0x04, 0x0c, b'/', b's', b'a', b'm', b'p', b'l', b'e', b'/', b'p', b'a', b't', b'h',
        ];
        let mut d = dec();
        let got = d.decode(&wire).unwrap();
        assert_eq!(
            as_pairs(&got),
            vec![(":path".into(), "/sample/path".into())]
        );
        assert_eq!(d.len(), 0, "this form must not index");
    }

    #[test]
    fn c_2_4_indexed_field() {
        // Static index 2 → :method: GET
        let mut d = dec();
        let got = d.decode(&[0x82]).unwrap();
        assert_eq!(as_pairs(&got), vec![(":method".into(), "GET".into())]);
    }

    #[test]
    fn c_3_request_sequence_shares_the_dynamic_table() {
        // The three requests of Appendix C.3, which only decode
        // correctly if the table carries across blocks.
        let mut d = dec();

        let first = [
            0x82, 0x86, 0x84, 0x41, 0x0f, b'w', b'w', b'w', b'.', b'e', b'x', b'a', b'm', b'p',
            b'l', b'e', b'.', b'c', b'o', b'm',
        ];
        assert_eq!(
            as_pairs(&d.decode(&first).unwrap()),
            vec![
                (":method".into(), "GET".into()),
                (":scheme".into(), "http".into()),
                (":path".into(), "/".into()),
                (":authority".into(), "www.example.com".into()),
            ]
        );

        let second = [
            0x82, 0x86, 0x84, 0xbe, 0x58, 0x08, b'n', b'o', b'-', b'c', b'a', b'c', b'h', b'e',
        ];
        assert_eq!(
            as_pairs(&d.decode(&second).unwrap()),
            vec![
                (":method".into(), "GET".into()),
                (":scheme".into(), "http".into()),
                (":path".into(), "/".into()),
                (":authority".into(), "www.example.com".into()),
                ("cache-control".into(), "no-cache".into()),
            ],
            "index 0xbe must resolve through the dynamic table built by the first block"
        );
    }

    #[test]
    fn c_4_huffman_coded_request() {
        // Appendix C.4.1 — the same request, Huffman-encoded.
        let wire = [
            0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab,
            0x90, 0xf4, 0xff,
        ];
        let mut d = dec();
        assert_eq!(
            as_pairs(&d.decode(&wire).unwrap()),
            vec![
                (":method".into(), "GET".into()),
                (":scheme".into(), "http".into()),
                (":path".into(), "/".into()),
                (":authority".into(), "www.example.com".into()),
            ]
        );
    }

    // ── integer coding ────────────────────────────────────────────

    #[test]
    fn integers_round_trip_the_rfc_examples() {
        // §C.1.1: 10 in a 5-bit prefix.
        assert_eq!(decode_int(&[0x0a], 5).unwrap().0, 10);
        // §C.1.2: 1337 in a 5-bit prefix.
        assert_eq!(decode_int(&[0x1f, 0x9a, 0x0a], 5).unwrap().0, 1337);
        // §C.1.3: 42 in an 8-bit prefix.
        assert_eq!(decode_int(&[0x2a], 8).unwrap().0, 42);
    }

    #[test]
    fn a_continuation_that_would_overflow_is_refused() {
        // Ten 0xff continuation bytes: a decoder that wraps produces
        // a plausible small index from nonsense.
        let wire = [
            0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
        ];
        assert!(matches!(
            decode_int(&wire, 5),
            Err(Http2Error::HpackIntegerOverflow)
        ));
    }

    #[test]
    fn a_truncated_integer_is_refused() {
        assert!(matches!(
            decode_int(&[0x1f, 0x80], 5),
            Err(Http2Error::HpackTruncated)
        ));
        assert!(matches!(
            decode_int(&[], 5),
            Err(Http2Error::HpackTruncated)
        ));
    }

    // ── table discipline ──────────────────────────────────────────

    #[test]
    fn index_zero_and_out_of_range_are_refused() {
        let mut d = dec();
        assert!(matches!(
            d.decode(&[0x80]),
            Err(Http2Error::HpackInvalidIndex)
        ));
        // 62 is the first dynamic slot, empty here.
        assert!(matches!(
            d.decode(&[0xbe]),
            Err(Http2Error::HpackInvalidIndex)
        ));
    }

    #[test]
    fn the_dynamic_table_evicts_to_stay_within_its_size() {
        // A table just big enough for one entry.
        let mut d = HpackDecoder::new(64, 65536);
        for i in 0..8u8 {
            let name = [b'a' + i];
            let wire = [&[0x40, 0x01][..], &name[..], &[0x01, b'v'][..]].concat();
            d.decode(&wire).unwrap();
        }
        assert!(
            d.len() <= 2,
            "eviction must bound the table, got {}",
            d.len()
        );
    }

    #[test]
    fn an_entry_larger_than_the_table_empties_it() {
        // RFC 7541 §4.4.
        let mut d = HpackDecoder::new(64, 65536);
        d.decode(&[0x40, 0x01, b'a', 0x01, b'v']).unwrap();
        assert_eq!(d.len(), 1);
        let big = [b'x'; 100];
        let wire = [&[0x40, 0x01, b'b'][..], &[0x64][..], &big[..]].concat();
        d.decode(&wire).unwrap();
        assert_eq!(d.len(), 0, "an oversized entry clears the table");
    }

    #[test]
    fn a_peer_cannot_raise_the_table_above_the_hard_cap() {
        let mut d = HpackDecoder::new(4096, 8192);
        // Dynamic table size update to 16 KiB, past the 8 KiB cap.
        let wire = [0x3f, 0xe1, 0x7f];
        assert!(matches!(
            d.decode(&wire),
            Err(Http2Error::HpackTableSizeExceeded)
        ));
    }

    #[test]
    fn settings_can_shrink_the_table_and_evict() {
        let mut d = dec();
        for i in 0..4u8 {
            let name = [b'a' + i];
            let wire = [&[0x40, 0x01][..], &name[..], &[0x01, b'v'][..]].concat();
            d.decode(&wire).unwrap();
        }
        assert_eq!(d.len(), 4);
        d.set_max_size(0);
        assert_eq!(d.len(), 0, "shrinking to zero evicts everything");
    }

    #[test]
    fn a_block_with_too_many_fields_is_refused() {
        // 300 indexed fields — past MAX_FIELDS_PER_BLOCK.
        let wire = vec![0x82u8; 300];
        let mut d = dec();
        assert!(matches!(
            d.decode(&wire),
            Err(Http2Error::HeaderListTooLong)
        ));
    }

    #[test]
    fn never_panics_on_arbitrary_input() {
        for seed in 0..64u8 {
            let bytes: Vec<u8> = (0..96u8)
                .map(|i| i.wrapping_mul(seed).wrapping_add(seed))
                .collect();
            let mut d = dec();
            let _ = d.decode(&bytes);
        }
    }
}

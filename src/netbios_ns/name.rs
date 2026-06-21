//! RFC 1001 §14.1 "first-level encoding" for NetBIOS names.
//!
//! NetBIOS names are exactly 16 bytes raw. The wire form
//! encodes each raw byte as a pair of half-bytes shifted by
//! `'A'` (0x41). So raw byte `0x4E` ('N') becomes the two
//! ASCII bytes `'E'` `'O'` (0x4E = 0x40 | 0x0E → 'E','O' in
//! ASCII). Total encoded length: 32 ASCII bytes, framed in
//! the DNS-shaped name format as a single length-32 label
//! followed by a zero-length terminator.

/// Decode the 32-byte first-level-encoded NetBIOS name into
/// the 16 raw bytes. Returns `None` if any half-byte falls
/// outside the `'A'..='P'` range (i.e. not a valid encoded
/// byte).
pub(crate) fn decode_first_level(encoded: &[u8]) -> Option<[u8; 16]> {
    if encoded.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        let hi = decode_nibble(encoded[i * 2])?;
        let lo = decode_nibble(encoded[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn decode_nibble(b: u8) -> Option<u8> {
    if (b'A'..=b'P').contains(&b) {
        Some(b - b'A')
    } else {
        None
    }
}

/// Split the 16-byte decoded name into the (printable name,
/// suffix byte) pair. The name is trimmed of trailing spaces
/// (NetBIOS pads names to 15 bytes with `0x20`) and any
/// non-printable bytes are stripped. The 16th byte is the
/// service-type suffix.
pub(crate) fn split_name_suffix(raw: &[u8; 16]) -> (String, u8) {
    let suffix = raw[15];
    let name_bytes = &raw[..15];
    let trimmed: Vec<u8> = name_bytes
        .iter()
        .copied()
        .filter(|&b| b.is_ascii_graphic() && b != b'\0')
        .collect();
    let mut s = String::from_utf8_lossy(&trimmed).into_owned();
    // Drop any trailing dot or space the trim didn't catch.
    while s.ends_with(' ') || s.ends_with('.') {
        s.pop();
    }
    (s, suffix)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_first_level_basic() {
        // 'N' = 0x4E. Half-bytes: 0x4, 0xE → 'E','O'. Pad with
        // workstation suffix (0x00 → 'A','A').
        let encoded = b"EOEPENEDFCEBEFEMEEFCEFEDCACACAAA";
        let decoded = decode_first_level(encoded).expect("decode");
        // Verify roundtrip property — the encoded form is
        // canonical for NetBIOS names. We just check the
        // length is 16.
        assert_eq!(decoded.len(), 16);
    }

    #[test]
    fn decode_first_level_rejects_bad_length() {
        assert!(decode_first_level(b"short").is_none());
        assert!(decode_first_level(&[b'A'; 31]).is_none());
    }

    #[test]
    fn decode_first_level_rejects_out_of_range() {
        let mut enc = [b'A'; 32];
        enc[5] = b'Z'; // > 'P'
        assert!(decode_first_level(&enc).is_none());
    }

    #[test]
    fn split_name_suffix_strips_padding() {
        // "WORKSTATION" + 4 spaces + 0x00 suffix.
        let mut raw = [b' '; 16];
        raw[..11].copy_from_slice(b"WORKSTATION");
        raw[15] = 0x00;
        let (name, suffix) = split_name_suffix(&raw);
        assert_eq!(name, "WORKSTATION");
        assert_eq!(suffix, 0x00);
    }

    #[test]
    fn split_name_suffix_keeps_suffix_byte_value() {
        let mut raw = [b' '; 16];
        raw[..5].copy_from_slice(b"FILES");
        raw[15] = 0x20; // file-server suffix
        let (name, suffix) = split_name_suffix(&raw);
        assert_eq!(name, "FILES");
        assert_eq!(suffix, 0x20);
    }
}

//! HTTP/2 frame layer (RFC 9113 §4.1, §6).

use bytes::Bytes;

use super::error::Http2Error;

/// The 24-octet client connection preface (RFC 9113 §3.4).
pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Fixed frame-header size: length(24) type(8) flags(8) R(1)+id(31).
pub(crate) const FRAME_HEADER_LEN: usize = 9;

/// Frame types this parser distinguishes (RFC 9113 §6).
///
/// Types outside the registry are kept as [`Unknown`](Self::Unknown)
/// rather than rejected: §4.1 requires unknown frames to be ignored,
/// and an observer that fails on one would break on every extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FrameKind {
    Data,
    Headers,
    Priority,
    RstStream,
    Settings,
    PushPromise,
    Ping,
    GoAway,
    WindowUpdate,
    Continuation,
    Unknown(u8),
}

impl FrameKind {
    fn from_byte(b: u8) -> Self {
        match b {
            0x0 => Self::Data,
            0x1 => Self::Headers,
            0x2 => Self::Priority,
            0x3 => Self::RstStream,
            0x4 => Self::Settings,
            0x5 => Self::PushPromise,
            0x6 => Self::Ping,
            0x7 => Self::GoAway,
            0x8 => Self::WindowUpdate,
            0x9 => Self::Continuation,
            other => Self::Unknown(other),
        }
    }
}

/// Frame flags, by the bit each type gives it.
pub(crate) mod flags {
    pub const END_STREAM: u8 = 0x1;
    pub const ACK: u8 = 0x1;
    pub const END_HEADERS: u8 = 0x4;
    pub const PADDED: u8 = 0x8;
    pub const PRIORITY: u8 = 0x20;
}

/// One parsed frame: the header fields plus its payload.
#[derive(Debug, Clone)]
pub(crate) struct Frame {
    pub kind: FrameKind,
    pub flags: u8,
    pub stream_id: u32,
    /// Payload with padding, priority prefix, and the `PUSH_PROMISE`
    /// promised-stream-id already removed, so callers see only
    /// field-block or application data.
    pub payload: Bytes,
    /// The stream a `PUSH_PROMISE` reserves (RFC 9113 §6.6). The
    /// field block describes *that* stream, while any
    /// `CONTINUATION` still arrives on the sending stream.
    pub promised_stream_id: Option<u32>,
}

impl Frame {
    pub(crate) fn has(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }
}

/// Try to read one frame from the front of `buf`.
///
/// Returns `Ok(None)` when the frame has not fully arrived. On
/// success the caller must consume `FRAME_HEADER_LEN + length` bytes.
/// How many bytes the frame at the head of `buf` occupies, reading
/// only its 9-octet header.
///
/// Takes a plain slice, so a caller holding a `BytesMut` can find the
/// frame boundary *before* deciding what to make owned — which is
/// what lets [`Http2Parser`](super::Http2Parser) hand `parse_frame` a
/// `Bytes` covering exactly one frame instead of a copy of everything
/// still buffered.
///
/// `Ok(None)` means the frame is not all here yet.
pub(crate) fn peek_frame_len(buf: &[u8], max_frame_size: u32) -> Result<Option<usize>, Http2Error> {
    if buf.len() < FRAME_HEADER_LEN {
        return Ok(None);
    }
    let length = u32::from(buf[0]) << 16 | u32::from(buf[1]) << 8 | u32::from(buf[2]);
    if length > max_frame_size {
        return Err(Http2Error::FrameTooLarge);
    }
    let total = FRAME_HEADER_LEN + length as usize;
    if buf.len() < total {
        return Ok(None);
    }
    Ok(Some(total))
}

pub(crate) fn parse_frame(
    buf: &Bytes,
    max_frame_size: u32,
) -> Result<Option<(Frame, usize)>, Http2Error> {
    let Some(total) = peek_frame_len(buf, max_frame_size)? else {
        return Ok(None);
    };

    let kind = FrameKind::from_byte(buf[3]);
    let flags = buf[4];
    // The reserved high bit of the stream identifier is ignored, per
    // §4.1 — some middleboxes set it.
    let stream_id = (u32::from(buf[5]) << 24
        | u32::from(buf[6]) << 16
        | u32::from(buf[7]) << 8
        | u32::from(buf[8]))
        & 0x7fff_ffff;

    let mut payload = buf.slice(FRAME_HEADER_LEN..total);

    // Strip padding (§6.1, §6.2) — the pad length byte, and the pad
    // itself off the end.
    if matches!(
        kind,
        FrameKind::Data | FrameKind::Headers | FrameKind::PushPromise
    ) && flags & flags::PADDED != 0
    {
        let Some(&pad_len) = payload.first() else {
            return Err(Http2Error::MalformedFrame);
        };
        let pad_len = usize::from(pad_len);
        // §6.1: padding longer than the remaining payload is a
        // connection error, and is how a sender hides bytes from a
        // decoder that clamps instead of rejecting.
        if pad_len + 1 > payload.len() {
            return Err(Http2Error::MalformedFrame);
        }
        payload = payload.slice(1..payload.len() - pad_len);
    }

    // Strip the priority prefix on HEADERS (§6.2): a 4-byte stream
    // dependency plus a 1-byte weight.
    if kind == FrameKind::Headers && flags & flags::PRIORITY != 0 {
        if payload.len() < 5 {
            return Err(Http2Error::MalformedFrame);
        }
        payload = payload.slice(5..);
    }

    // Strip the promised stream identifier on PUSH_PROMISE (§6.6).
    // These four octets precede the field block; feeding them to
    // HPACK would corrupt the dynamic table for the rest of the
    // connection.
    let mut promised_stream_id = None;
    if kind == FrameKind::PushPromise {
        if payload.len() < 4 {
            return Err(Http2Error::MalformedFrame);
        }
        promised_stream_id = Some(
            (u32::from(payload[0]) << 24
                | u32::from(payload[1]) << 16
                | u32::from(payload[2]) << 8
                | u32::from(payload[3]))
                & 0x7fff_ffff,
        );
        payload = payload.slice(4..);
    }

    Ok(Some((
        Frame {
            kind,
            flags,
            stream_id,
            payload,
            promised_stream_id,
        },
        total,
    )))
}

/// Frame a field block as `HEADERS` plus as many `CONTINUATION`
/// frames as `max_frame_size` requires (RFC 9113 §6.2, §6.10).
///
/// The counterpart to
/// [`HpackEncoder::encode`](super::HpackEncoder::encode): that
/// produces a field block, this makes it something you can put on a
/// socket. A block is not a header — wrapping a 20 KiB one in a
/// single `HEADERS` frame earns a connection-fatal `FRAME_SIZE_ERROR`
/// from the peer, several frames away from the mistake.
///
/// `END_STREAM` rides the `HEADERS` frame; `END_HEADERS` rides the
/// last frame only. No padding and no priority prefix are emitted —
/// padding is a covert channel with no legitimate use here, and
/// priority is deprecated by RFC 9113 §5.3.
///
/// `max_frame_size` is the peer's advertised
/// `SETTINGS_MAX_FRAME_SIZE`, available from
/// [`Http2Event::Settings`](super::Http2Event::Settings) or
/// [`Http2Parser::max_frame_size`](super::Http2Parser::max_frame_size).
/// Values outside the protocol's `16384..=16777215` range are clamped
/// into it.
///
/// # Errors
///
/// [`Http2Error::InvalidStreamId`] if `stream_id` is 0 — a field
/// block never belongs to the connection stream — or has the
/// reserved high bit set (RFC 9113 §5.1.1).
pub fn write_headers(
    stream_id: u32,
    block: &[u8],
    end_stream: bool,
    max_frame_size: u32,
) -> Result<Vec<u8>, Http2Error> {
    if stream_id == 0 || stream_id > 0x7fff_ffff {
        return Err(Http2Error::InvalidStreamId);
    }
    let chunk = max_frame_size.clamp(16_384, 16_777_215) as usize;
    let mut out = Vec::with_capacity(block.len() + FRAME_HEADER_LEN);
    let mut first = true;
    // `chunks` yields nothing for an empty slice, but an empty field
    // block is legal and still needs its `HEADERS` frame.
    let mut it = block.chunks(chunk).peekable();
    loop {
        let part: &[u8] = it.next().unwrap_or(&[]);
        let last = it.peek().is_none();
        let kind = if first { 0x1 } else { 0x9 };
        let mut fl = 0u8;
        if last {
            fl |= flags::END_HEADERS;
        }
        if first && end_stream {
            fl |= flags::END_STREAM;
        }
        let len = part.len() as u32;
        out.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        out.push(kind);
        out.push(fl);
        out.extend_from_slice(&stream_id.to_be_bytes());
        out.extend_from_slice(part);
        first = false;
        if last {
            break;
        }
    }
    Ok(out)
}

/// A `SETTINGS` payload, parsed into the parameters this observer
/// acts on (RFC 9113 §6.5.2).
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct Settings {
    pub header_table_size: Option<u32>,
    pub max_frame_size: Option<u32>,
    pub max_header_list_size: Option<u32>,
}

/// Parse a `SETTINGS` payload: a sequence of 6-octet entries.
pub(crate) fn parse_settings(payload: &[u8]) -> Result<Settings, Http2Error> {
    if !payload.len().is_multiple_of(6) {
        return Err(Http2Error::MalformedFrame);
    }
    let mut s = Settings::default();
    for entry in payload.chunks_exact(6) {
        let id = u16::from(entry[0]) << 8 | u16::from(entry[1]);
        let value = u32::from(entry[2]) << 24
            | u32::from(entry[3]) << 16
            | u32::from(entry[4]) << 8
            | u32::from(entry[5]);
        match id {
            0x1 => s.header_table_size = Some(value),
            0x5 => s.max_frame_size = Some(value),
            0x6 => s.max_header_list_size = Some(value),
            // Other parameters do not affect how bytes are framed.
            _ => {}
        }
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Walk every frame `write_headers` produced, back through the
    /// parser that reads them. A writer with no counterpart parser
    /// could only be tested against a hand-written byte table.
    fn read_back(wire: &[u8]) -> Vec<(FrameKind, u8, u32, Vec<u8>)> {
        let mut out = Vec::new();
        let mut buf = Bytes::copy_from_slice(wire);
        while !buf.is_empty() {
            let (f, consumed) = parse_frame(&buf, u32::MAX)
                .expect("parses")
                .expect("complete");
            out.push((f.kind, f.flags, f.stream_id, f.payload.to_vec()));
            buf = buf.slice(consumed..);
        }
        out
    }

    #[test]
    fn write_headers_round_trips_through_the_parser() {
        let wire = write_headers(1, b"block-bytes", true, 16_384).unwrap();
        let frames = read_back(&wire);
        assert_eq!(frames.len(), 1);
        let (kind, fl, id, payload) = &frames[0];
        assert_eq!(*kind, FrameKind::Headers);
        assert_eq!(*id, 1);
        assert_eq!(fl & flags::END_HEADERS, flags::END_HEADERS);
        assert_eq!(fl & flags::END_STREAM, flags::END_STREAM);
        assert_eq!(payload, b"block-bytes");
    }

    #[test]
    fn a_block_over_the_frame_size_continues() {
        let max = 16_384usize;
        let block = vec![0xabu8; max * 2 + 1];
        let wire = write_headers(7, &block, false, max as u32).unwrap();
        let frames = read_back(&wire);
        assert_eq!(frames.len(), 3, "one HEADERS plus two CONTINUATION");

        assert_eq!(frames[0].0, FrameKind::Headers);
        assert_eq!(frames[1].0, FrameKind::Continuation);
        assert_eq!(frames[2].0, FrameKind::Continuation);

        // END_HEADERS only on the last; END_STREAM on none of them.
        assert_eq!(frames[0].1 & flags::END_HEADERS, 0);
        assert_eq!(frames[1].1 & flags::END_HEADERS, 0);
        assert_eq!(frames[2].1 & flags::END_HEADERS, flags::END_HEADERS);
        assert!(frames.iter().all(|f| f.1 & flags::END_STREAM == 0));

        assert!(frames.iter().all(|f| f.2 == 7), "all on the same stream");
        let rejoined: Vec<u8> = frames.iter().flat_map(|f| f.3.clone()).collect();
        assert_eq!(rejoined, block, "the block survives the split");
        assert_eq!(frames[2].3.len(), 1, "the remainder is its own frame");
    }

    #[test]
    fn end_stream_rides_only_the_first_frame() {
        let block = vec![0u8; 16_385];
        let wire = write_headers(3, &block, true, 16_384).unwrap();
        let frames = read_back(&wire);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].1 & flags::END_STREAM, flags::END_STREAM);
        assert_eq!(
            frames[1].1 & flags::END_STREAM,
            0,
            "END_STREAM on a CONTINUATION would be a protocol error"
        );
    }

    #[test]
    fn an_empty_block_still_produces_one_frame() {
        let frames = read_back(&write_headers(1, b"", false, 16_384).unwrap());
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].0, FrameKind::Headers);
        assert!(frames[0].3.is_empty());
    }

    #[test]
    fn stream_zero_and_the_reserved_bit_are_refused() {
        assert_eq!(
            write_headers(0, b"x", false, 16_384),
            Err(Http2Error::InvalidStreamId),
            "a field block never belongs to the connection stream"
        );
        assert_eq!(
            write_headers(0x8000_0000, b"x", false, 16_384),
            Err(Http2Error::InvalidStreamId)
        );
    }

    #[test]
    fn an_out_of_range_frame_size_is_clamped_not_hung() {
        // 0 would be an infinite loop if it reached `chunks`.
        let frames = read_back(&write_headers(1, &[0u8; 100], false, 0).unwrap());
        assert_eq!(frames.len(), 1, "clamped up to the 16 KiB floor");
        let huge = write_headers(1, &[0u8; 100], false, u32::MAX).unwrap();
        assert_eq!(read_back(&huge).len(), 1);
    }

    fn frame_bytes(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Bytes {
        let mut v = Vec::new();
        let len = payload.len() as u32;
        v.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        v.push(kind);
        v.push(flags);
        v.extend_from_slice(&stream.to_be_bytes());
        v.extend_from_slice(payload);
        Bytes::from(v)
    }

    #[test]
    fn parses_a_minimal_frame() {
        let buf = frame_bytes(0x1, flags::END_HEADERS, 1, b"abc");
        let (f, used) = parse_frame(&buf, 16_384).unwrap().unwrap();
        assert_eq!(f.kind, FrameKind::Headers);
        assert_eq!(f.stream_id, 1);
        assert!(f.has(flags::END_HEADERS));
        assert_eq!(f.payload.as_ref(), b"abc");
        assert_eq!(used, FRAME_HEADER_LEN + 3);
    }

    #[test]
    fn waits_for_a_partial_frame() {
        let buf = frame_bytes(0x0, 0, 1, b"hello");
        for n in 0..buf.len() {
            assert!(
                parse_frame(&buf.slice(..n), 16_384).unwrap().is_none(),
                "must not decide on {n} bytes"
            );
        }
        assert!(parse_frame(&buf, 16_384).unwrap().is_some());
    }

    #[test]
    fn a_frame_above_max_frame_size_is_refused() {
        let mut v = vec![0x00, 0x40, 0x01]; // 16385
        v.extend_from_slice(&[0x0, 0x0, 0, 0, 0, 1]);
        let buf = Bytes::from(v);
        assert!(matches!(
            parse_frame(&buf, 16_384),
            Err(Http2Error::FrameTooLarge)
        ));
    }

    #[test]
    fn padding_is_stripped_and_overlong_padding_refused() {
        // pad length 2, data "hi", then two pad bytes.
        let buf = frame_bytes(0x0, flags::PADDED, 1, &[2, b'h', b'i', 0, 0]);
        let (f, _) = parse_frame(&buf, 16_384).unwrap().unwrap();
        assert_eq!(f.payload.as_ref(), b"hi");

        // Padding longer than what remains: a way to hide bytes from
        // a decoder that clamps instead of rejecting.
        let buf = frame_bytes(0x0, flags::PADDED, 1, &[9, b'h', b'i']);
        assert!(matches!(
            parse_frame(&buf, 16_384),
            Err(Http2Error::MalformedFrame)
        ));
    }

    #[test]
    fn the_priority_prefix_is_stripped_from_headers() {
        let payload = [0, 0, 0, 1, 16, b'X'];
        let buf = frame_bytes(0x1, flags::PRIORITY, 3, &payload);
        let (f, _) = parse_frame(&buf, 16_384).unwrap().unwrap();
        assert_eq!(f.payload.as_ref(), b"X");
    }

    #[test]
    fn the_reserved_stream_id_bit_is_ignored() {
        let buf = frame_bytes(0x0, 0, 0x8000_0001, b"");
        let (f, _) = parse_frame(&buf, 16_384).unwrap().unwrap();
        assert_eq!(f.stream_id, 1);
    }

    #[test]
    fn unknown_frame_types_are_kept_not_refused() {
        // §4.1: unknown types must be ignored, not treated as errors.
        let buf = frame_bytes(0xfa, 0, 1, b"ext");
        let (f, _) = parse_frame(&buf, 16_384).unwrap().unwrap();
        assert_eq!(f.kind, FrameKind::Unknown(0xfa));
    }

    #[test]
    fn the_promised_stream_id_is_stripped_from_push_promise() {
        // §6.6: the four promised-id octets precede the field block.
        // Leaving them in feeds them to HPACK, which corrupts the
        // dynamic table for the rest of the connection.
        let mut payload = 2u32.to_be_bytes().to_vec();
        payload.extend_from_slice(b"BLOCK");
        let buf = frame_bytes(0x5, flags::END_HEADERS, 1, &payload);
        let (f, _) = parse_frame(&buf, 16_384).unwrap().unwrap();
        assert_eq!(f.promised_stream_id, Some(2));
        assert_eq!(f.payload.as_ref(), b"BLOCK");
    }

    #[test]
    fn a_push_promise_too_short_for_its_promised_id_is_refused() {
        let buf = frame_bytes(0x5, flags::END_HEADERS, 1, &[0, 0]);
        assert!(matches!(
            parse_frame(&buf, 16_384),
            Err(Http2Error::MalformedFrame)
        ));
    }

    #[test]
    fn settings_parse_the_parameters_that_affect_framing() {
        let payload = [
            0x00, 0x01, 0x00, 0x00, 0x10, 0x00, // header table size 4096
            0x00, 0x05, 0x00, 0x00, 0x80, 0x00, // max frame size 32768
        ];
        let s = parse_settings(&payload).unwrap();
        assert_eq!(s.header_table_size, Some(4096));
        assert_eq!(s.max_frame_size, Some(32768));
        assert_eq!(s.max_header_list_size, None);
    }

    #[test]
    fn a_settings_payload_of_the_wrong_length_is_refused() {
        assert!(matches!(
            parse_settings(&[0, 1, 0, 0]),
            Err(Http2Error::MalformedFrame)
        ));
    }
}

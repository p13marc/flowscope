//! Why the HTTP/2 parser gave up on a connection.

/// A condition that makes further parsing of an HTTP/2 connection
/// meaningless.
///
/// HPACK is stateful across the whole connection, so most of these
/// are fatal in a way an HTTP/1 framing error is not: once the
/// dynamic table is out of step with the peer's encoder, every later
/// field block decodes to plausible-looking nonsense. Stopping is the
/// only safe response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum Http2Error {
    /// The connection did not start with the client preface.
    BadPreface,
    /// A frame declared a length above `SETTINGS_MAX_FRAME_SIZE`.
    FrameTooLarge,
    /// A frame's fixed fields were malformed for its type.
    MalformedFrame,
    /// A `HEADERS` block was interrupted by a frame other than
    /// `CONTINUATION` on the same stream (RFC 9113 §6.10).
    InterleavedContinuation,
    /// A `CONTINUATION` arrived with no `HEADERS` block open.
    UnexpectedContinuation,
    /// A field block exceeded the header-list cap.
    HeaderListTooLong,
    /// More concurrent streams than the parser will track.
    TooManyStreams,
    /// Frame or field-block bytes buffered past the cap.
    BufferOverflow,

    // ── HPACK (RFC 7541) ──────────────────────────────────────────
    /// A header index referred to nothing.
    HpackInvalidIndex,
    /// A field block ended mid-field.
    HpackTruncated,
    /// A variable-length integer's continuation would overflow.
    HpackIntegerOverflow,
    /// A dynamic-table size update exceeded the hard cap.
    HpackTableSizeExceeded,
    /// Invalid Huffman coding: EOS in the data, or bad padding.
    HuffmanInvalid,

    // ── Encoding (this side's own output) ─────────────────────────
    /// A field handed to the encoder could not legally be sent:
    /// an uppercase or non-token name, a misplaced pseudo-header,
    /// a control character in a value, or a connection-specific
    /// field HTTP/2 forbids (RFC 9113 §8.2).
    InvalidHeaderField,
    /// A field block was framed for stream 0, or for a stream id with
    /// the reserved high bit set (RFC 9113 §5.1.1).
    InvalidStreamId,
}

impl Http2Error {
    /// Stable, lowercase slug — safe as a metric label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BadPreface => "bad-preface",
            Self::FrameTooLarge => "frame-too-large",
            Self::MalformedFrame => "malformed-frame",
            Self::InterleavedContinuation => "interleaved-continuation",
            Self::UnexpectedContinuation => "unexpected-continuation",
            Self::HeaderListTooLong => "header-list-too-long",
            Self::TooManyStreams => "too-many-streams",
            Self::BufferOverflow => "buffer-overflow",
            Self::HpackInvalidIndex => "hpack-invalid-index",
            Self::HpackTruncated => "hpack-truncated",
            Self::HpackIntegerOverflow => "hpack-integer-overflow",
            Self::HpackTableSizeExceeded => "hpack-table-size-exceeded",
            Self::HuffmanInvalid => "huffman-invalid",
            Self::InvalidHeaderField => "invalid-header-field",
            Self::InvalidStreamId => "invalid-stream-id",
        }
    }
}

impl std::fmt::Display for Http2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for Http2Error {}

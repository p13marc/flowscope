//! Typed reasons a streaming HTTP parser gives up on a connection.

/// Why [`HttpProxyParser`](super::HttpProxyParser) stopped parsing.
///
/// An inline proxy must not keep forwarding bytes once framing is in
/// doubt — that is how request smuggling gets through. Each variant
/// names one specific failure so the caller can decide what to do
/// with it (a client-side framing violation warrants `400`, a
/// server-side one `502`), rather than parsing a message string.
///
/// [`as_str`](Self::as_str) gives a stable slug, which is what
/// [`SessionParser::poison_reason`](crate::SessionParser::poison_reason)
/// reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum HttpPoison {
    /// The start line + header block exceeded its cap before it
    /// finished.
    HeadOverflow,
    /// A chunk-size line exceeded its cap before its CRLF arrived.
    ChunkLineOverflow,
    /// The trailer section exceeded its cap before its blank line.
    TrailerOverflow,
    /// More requests are outstanding than the pipeline cap allows.
    PipelineOverflow,
    /// A chunk-size line was not valid hexadecimal.
    InvalidChunkSize,
    /// A chunk's data was not followed by CRLF.
    MalformedChunkTerminator,
    /// The start line or a header field could not be parsed.
    MalformedHead,

    // ── RFC 9112 §6.3 framing ambiguity (request smuggling) ───────
    /// Both `Content-Length` and `Transfer-Encoding` were present.
    /// Two recipients may disagree about which wins, which is the
    /// CL.TE / TE.CL desync primitive.
    ContentLengthWithTransferEncoding,
    /// Two `Content-Length` values that do not agree.
    ConflictingContentLength,
    /// A `Content-Length` that is not a plain decimal number (a
    /// leading `+`, a hex form, or trailing junk).
    InvalidContentLength,
    /// `Transfer-Encoding` was present but `chunked` was not the
    /// final coding, so the body length is undefined (§6.3 rule 3).
    NonFinalChunked,
    /// A transfer coding the parser does not implement.
    UnknownTransferCoding,
    /// `Transfer-Encoding` appeared more than once — the classic
    /// TE.TE obfuscation, where one hop reads the header the other
    /// ignores.
    DuplicateTransferEncoding,
    /// An obs-fold (a header value continued on a folded line).
    /// Deprecated by RFC 9112 §5.2 and a known desync vector.
    ObsFold,
    /// A bare CR inside the header block (RFC 9112 §2.2).
    BareCr,
    /// More than one `Host` header: recipients may route on
    /// different ones.
    DuplicateHost,
    /// A request authority that is not ASCII. Case-folding non-ASCII
    /// is a routing-desync primitive (U+212A KELVIN lowercases to
    /// `k`), so it is refused rather than normalized.
    NonAsciiAuthority,
    /// A response arrived with no request outstanding.
    UnexpectedResponse,
}

impl HttpPoison {
    /// Stable, lowercase slug — safe to use as a metric label or to
    /// match on in a consumer.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HeadOverflow => "head-overflow",
            Self::ChunkLineOverflow => "chunk-line-overflow",
            Self::TrailerOverflow => "trailer-overflow",
            Self::PipelineOverflow => "pipeline-overflow",
            Self::InvalidChunkSize => "invalid-chunk-size",
            Self::MalformedChunkTerminator => "malformed-chunk-terminator",
            Self::MalformedHead => "malformed-head",
            Self::ContentLengthWithTransferEncoding => "content-length-with-transfer-encoding",
            Self::ConflictingContentLength => "conflicting-content-length",
            Self::InvalidContentLength => "invalid-content-length",
            Self::NonFinalChunked => "non-final-chunked",
            Self::UnknownTransferCoding => "unknown-transfer-coding",
            Self::DuplicateTransferEncoding => "duplicate-transfer-encoding",
            Self::ObsFold => "obs-fold",
            Self::BareCr => "bare-cr",
            Self::DuplicateHost => "duplicate-host",
            Self::NonAsciiAuthority => "non-ascii-authority",
            Self::UnexpectedResponse => "unexpected-response",
        }
    }

    /// Whether the offending message came from the client.
    ///
    /// A gateway answers a client-side framing violation with `400`
    /// and a server-side one with `502`; this classifies which is
    /// which for the cases where the direction is implied by the
    /// violation itself. `None` means either side could produce it,
    /// so use the direction the bytes arrived on.
    pub const fn implies_client_fault(self) -> Option<bool> {
        match self {
            Self::DuplicateHost | Self::NonAsciiAuthority => Some(true),
            Self::UnexpectedResponse => Some(false),
            _ => None,
        }
    }
}

impl std::fmt::Display for HttpPoison {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

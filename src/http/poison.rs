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
        }
    }
}

impl std::fmt::Display for HttpPoison {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

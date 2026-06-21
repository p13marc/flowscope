//! QUIC Initial decoder + ClientHello extraction pipeline.

use quic_parser::{decrypt_initial, parse_crypto_frames, parse_initial, reassemble_crypto_stream};
use tls_parser::{TlsClientHelloContents, TlsExtension, TlsMessage, TlsMessageHandshake};

use super::types::{QuicInitial, QuicVersion};

pub const PARSER_KIND_STR: &str = "quic";

pub fn parser_kind() -> &'static str {
    PARSER_KIND_STR
}

/// Failure mode for [`parse`]. Each variant maps to one
/// operationally-distinct step of the QUIC Initial pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// Datagram isn't a QUIC long-header Initial. Most common
    /// cause: NAT-keepalive or unrelated UDP/443 traffic.
    NotInitial,
    /// AEAD decryption of the Initial payload failed — either
    /// the QUIC version isn't one with a known Initial salt,
    /// or the wire is malformed past the long header.
    AeadDecryptFailed,
    /// CRYPTO frame parse failed after a successful decrypt.
    CryptoFrameDecode,
    /// Reserved for future API additions. Currently unused —
    /// flowscope returns a QuicInitial even when the CRYPTO
    /// stream is empty, since the long-header metadata (DCID /
    /// SCID / version / token presence) is operationally
    /// useful on its own.
    #[doc(hidden)]
    _NoClientHello,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotInitial => f.write_str("not a QUIC long-header Initial"),
            Self::AeadDecryptFailed => f.write_str("Initial AEAD decrypt failed"),
            Self::CryptoFrameDecode => f.write_str("CRYPTO frame decode failed"),
            Self::_NoClientHello => f.write_str("no TLS ClientHello in CRYPTO stream"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Decode one QUIC Initial datagram. Returns the parsed
/// [`QuicInitial`] on success, or a [`ParseError`] indicating
/// which stage of the pipeline failed.
pub fn parse(datagram: &[u8]) -> Result<QuicInitial, ParseError> {
    let header = parse_initial(datagram).map_err(|_| ParseError::NotInitial)?;
    let decrypted = decrypt_initial(&header).map_err(|_| ParseError::AeadDecryptFailed)?;
    let frames = parse_crypto_frames(&decrypted).map_err(|_| ParseError::CryptoFrameDecode)?;
    let crypto_stream = reassemble_crypto_stream(&frames);

    let (sni, alpn) = extract_tls_metadata(&crypto_stream).unwrap_or((None, Vec::new()));
    Ok(QuicInitial {
        version: QuicVersion::from_raw(header.version),
        dcid: header.dcid.to_vec(),
        scid: header.scid.to_vec(),
        token_present: !header.token.is_empty(),
        sni,
        alpn,
    })
}

/// Walk the CRYPTO-stream bytes as a TLS handshake message
/// and pull SNI + ALPN from the ClientHello extensions.
fn extract_tls_metadata(crypto_stream: &[u8]) -> Option<(Option<String>, Vec<String>)> {
    let (_, msgs) = tls_parser::parse_tls_message_handshake(crypto_stream).ok()?;
    let ch = match msgs {
        TlsMessage::Handshake(TlsMessageHandshake::ClientHello(ch)) => ch,
        _ => return None,
    };
    let (sni, alpn) = extract_from_client_hello(&ch);
    Some((sni, alpn))
}

fn extract_from_client_hello(ch: &TlsClientHelloContents<'_>) -> (Option<String>, Vec<String>) {
    let mut sni = None;
    let mut alpn = Vec::new();
    if let Some(ext_bytes) = ch.ext {
        let mut rest = ext_bytes;
        while let Ok((next, ext)) = tls_parser::parse_tls_extension(rest) {
            match ext {
                TlsExtension::SNI(entries) => {
                    if let Some((_kind, name)) = entries.first()
                        && let Ok(s) = std::str::from_utf8(name)
                    {
                        sni = Some(s.to_string());
                    }
                }
                TlsExtension::ALPN(protos) => {
                    for proto in protos {
                        if let Ok(s) = std::str::from_utf8(proto) {
                            alpn.push(s.to_string());
                        }
                    }
                }
                _ => {}
            }
            if next.len() >= rest.len() {
                break;
            }
            rest = next;
        }
    }
    (sni, alpn)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_returns_not_initial() {
        assert_eq!(parse(&[]).unwrap_err(), ParseError::NotInitial);
    }

    #[test]
    fn non_long_header_returns_not_initial() {
        // First byte's MSB unset → short header → not Initial.
        let bytes = [0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(parse(&bytes).unwrap_err(), ParseError::NotInitial);
    }

    #[test]
    fn parse_error_implements_error() {
        // Compile-time check.
        fn _is_error<E: std::error::Error>() {}
        _is_error::<ParseError>();
    }

    #[test]
    fn parser_kind_is_quic() {
        assert_eq!(parser_kind(), "quic");
    }
}

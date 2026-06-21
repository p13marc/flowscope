//! QUIC Initial decoder + ClientHello extraction pipeline.

use quic_parser::{decrypt_initial, parse_crypto_frames, parse_initial, reassemble_crypto_stream};
use tls_parser::{TlsClientHelloContents, TlsExtension, TlsMessage, TlsMessageHandshake};

use super::types::QuicInitial;

pub const PARSER_KIND_STR: &str = "quic";

pub fn parser_kind() -> &'static str {
    PARSER_KIND_STR
}

/// Decode one QUIC Initial datagram. Returns `None` when the
/// datagram isn't a parseable QUIC long-header Initial, when
/// the AEAD decrypt fails, or when no TLS ClientHello can be
/// reassembled from the CRYPTO frames.
pub fn parse(datagram: &[u8]) -> Option<QuicInitial> {
    let header = parse_initial(datagram).ok()?;
    let decrypted = decrypt_initial(&header).ok()?;
    let frames = parse_crypto_frames(&decrypted).ok()?;
    let crypto_stream = reassemble_crypto_stream(&frames);

    let mut out = QuicInitial {
        version: header.version,
        dcid: header.dcid.to_vec(),
        scid: header.scid.to_vec(),
        token_present: !header.token.is_empty(),
        sni: None,
        alpn: Vec::new(),
    };

    if let Some((sni, alpn)) = extract_tls_metadata(&crypto_stream) {
        out.sni = sni;
        out.alpn = alpn;
    }

    Some(out)
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
    fn empty_returns_none() {
        assert!(parse(&[]).is_none());
    }

    #[test]
    fn non_long_header_returns_none() {
        // First byte's MSB unset → short header → not Initial.
        let bytes = [0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(parse(&bytes).is_none());
    }

    #[test]
    fn parser_kind_is_quic() {
        assert_eq!(parser_kind(), "quic");
    }
}

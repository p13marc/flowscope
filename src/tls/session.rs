//! [`TlsParser`] — `SessionParser` impl that produces TLS handshake
//! events as a typed message stream.
//!
//! Equivalent to [`crate::tls::TlsFactory`] but in the
//! `SessionParser` shape: pair with `netring::FlowStream::session_stream(...)`
//! to get an async iterator of TLS events instead of a callback
//! handler.

use bytes::Bytes;

use super::{
    parser::{self, DirState, ParseOutput},
    types::{TlsAlert, TlsClientHello, TlsConfig, TlsServerHello},
};
use crate::{SessionParser, Timestamp};

/// Unified message type emitted by [`TlsParser`].
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "type", content = "data", rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum TlsMessage {
    /// Client → server handshake `ClientHello`.
    ClientHello(Box<TlsClientHello>),
    /// Server → client handshake `ServerHello`.
    ServerHello(Box<TlsServerHello>),
    /// Either-direction TLS alert.
    Alert(TlsAlert),
    /// JA3 fingerprint computed from a [`Self::ClientHello`]. Only
    /// emitted when [`TlsConfig::ja3`] is true (and the
    /// `tls-fingerprints` feature is on; was `ja3` pre-0.12).
    #[cfg(feature = "tls-fingerprints")]
    Ja3 {
        /// MD5 hex digest of the canonical string.
        hash: String,
        /// Canonical string (raw fingerprint, dash-joined fields).
        canonical: String,
    },
    /// JA4 fingerprint computed from a [`Self::ClientHello`]. Only
    /// emitted when [`TlsConfig::ja4`] is true (and the
    /// `tls-fingerprints` feature is on; was `ja4` pre-0.12).
    #[cfg(feature = "tls-fingerprints")]
    Ja4 {
        /// Underscore-joined fingerprint (e.g.
        /// `t13d1516h2_8daaf6152771_b186095e22b6`).
        fingerprint: String,
    },
    /// JA4S server fingerprint computed from a [`Self::ServerHello`].
    /// Emitted alongside the ServerHello when [`TlsConfig::ja4`] is true
    /// (and the opt-in `ja4plus` feature is on). New in 0.15.0; moved behind
    /// `ja4plus` in 0.16.0 (FoxIO License 1.1 — see NOTICE).
    #[cfg(feature = "ja4plus")]
    Ja4s {
        /// Underscore-joined fingerprint (e.g.
        /// `t130200_1301_a56c5b993250`).
        fingerprint: String,
    },
    /// TLS 1.2 `Certificate` handshake record. `chain` is the
    /// list of X.509 DER blobs the server (or client, in mutual
    /// TLS) presented, in wire order — leaf first per RFC
    /// 5246 §7.4.2. New in 0.18.0 (issue #24 prereq).
    ///
    /// TLS 1.3 carries the cert chain inside encrypted
    /// `EncryptedExtensions` records; this variant only fires
    /// on TLS 1.2 / 1.1 / 1.0 cleartext cert chains.
    Certificate { chain: Vec<Bytes> },
}

/// Per-flow TLS handshake parser. Holds independent state for the
/// initiator (client) and responder (server) directions.
///
/// Implements `Default + Clone`, so it can be passed directly as a
/// `SessionParserFactory` — every new flow gets a fresh clone.
#[derive(Debug, Clone)]
pub struct TlsParser {
    config: TlsConfig,
    init_buf: Vec<u8>,
    init_state: DirState,
    resp_buf: Vec<u8>,
    resp_state: DirState,
}

impl Default for TlsParser {
    fn default() -> Self {
        Self::with_config(TlsConfig::default())
    }
}

impl TlsParser {
    /// Construct with explicit config.
    pub fn with_config(config: TlsConfig) -> Self {
        Self {
            config,
            init_buf: Vec::with_capacity(4096),
            init_state: DirState::Reading,
            resp_buf: Vec::with_capacity(4096),
            resp_state: DirState::Reading,
        }
    }

    fn drain(
        state: &mut DirState,
        buf: &mut Vec<u8>,
        is_initiator: bool,
        cfg: &TlsConfig,
        out: &mut Vec<TlsMessage>,
    ) {
        let mut parsed = Vec::new();
        loop {
            match parser::step(state, buf, is_initiator, cfg, &mut parsed) {
                Ok(true) => {}
                Ok(false) => break,
                Err(_) => {
                    buf.clear();
                    break;
                }
            }
        }
        for ev in parsed {
            Self::dispatch(ev, cfg, out);
        }
    }

    fn dispatch(parsed: ParseOutput, cfg: &TlsConfig, out: &mut Vec<TlsMessage>) {
        match parsed {
            ParseOutput::ClientHello(ch) => {
                #[cfg(feature = "tls-fingerprints")]
                if cfg.ja3 {
                    let (canonical, hash) = super::fingerprint::ja3(&ch);
                    out.push(TlsMessage::Ja3 { hash, canonical });
                }
                #[cfg(feature = "tls-fingerprints")]
                if cfg.ja4 {
                    let fingerprint = super::ja4::ja4(&ch);
                    out.push(TlsMessage::Ja4 { fingerprint });
                }
                #[cfg(not(feature = "tls-fingerprints"))]
                {
                    let _ = cfg; // silence unused-warning when both off
                }
                out.push(TlsMessage::ClientHello(ch));
            }
            ParseOutput::ServerHello(sh) => {
                // JA4S is FoxIO-licensed (opt-in `ja4plus`); the BSD JA4/JA3
                // client fingerprints stay under `tls-fingerprints`.
                #[cfg(feature = "ja4plus")]
                if cfg.ja4 {
                    let fingerprint = super::ja4s::ja4s(&sh);
                    out.push(TlsMessage::Ja4s { fingerprint });
                }
                out.push(TlsMessage::ServerHello(sh));
            }
            ParseOutput::Alert(a) => out.push(TlsMessage::Alert(a)),
            ParseOutput::Certificate { chain } => {
                out.push(TlsMessage::Certificate { chain });
            }
        }
    }
}

impl SessionParser for TlsParser {
    type Message = TlsMessage;

    fn feed_initiator(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<TlsMessage>) {
        if bytes.is_empty() || matches!(self.init_state, DirState::Encrypted | DirState::Desynced) {
            return;
        }
        self.init_buf.extend_from_slice(bytes);
        Self::drain(
            &mut self.init_state,
            &mut self.init_buf,
            true,
            &self.config,
            out,
        );
    }

    fn feed_responder(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<TlsMessage>) {
        if bytes.is_empty() || matches!(self.resp_state, DirState::Encrypted | DirState::Desynced) {
            return;
        }
        self.resp_buf.extend_from_slice(bytes);
        Self::drain(
            &mut self.resp_state,
            &mut self.resp_buf,
            false,
            &self.config,
            out,
        );
    }

    fn rst_initiator(&mut self) {
        self.init_buf.clear();
        self.init_state = DirState::Reading;
    }

    fn rst_responder(&mut self) {
        self.resp_buf.clear();
        self.resp_state = DirState::Reading;
    }

    fn parser_kind(&self) -> &'static str {
        crate::tls::PARSER_KIND
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_client_hello_record() -> Vec<u8> {
        // Synthetic TLS 1.2 ClientHello record. Reuses the fixture
        // shape from tests/tls_parser.rs.
        let mut ch_body = Vec::new();
        ch_body.extend_from_slice(&[0x03, 0x03]); // legacy version 0x0303 (TLS 1.2)
        ch_body.extend_from_slice(&[0u8; 32]); // random
        ch_body.push(0); // session_id length
        // cipher suites: [TLS_AES_128_GCM_SHA256]
        ch_body.extend_from_slice(&[0, 2, 0x13, 0x01]);
        // compression methods: [null]
        ch_body.extend_from_slice(&[1, 0]);
        // extensions length 0
        ch_body.extend_from_slice(&[0, 0]);

        // Handshake header: type=1 (CH), length(3 bytes) + body
        let mut handshake = Vec::new();
        handshake.push(0x01);
        let len = ch_body.len();
        handshake.push(((len >> 16) & 0xff) as u8);
        handshake.push(((len >> 8) & 0xff) as u8);
        handshake.push((len & 0xff) as u8);
        handshake.extend_from_slice(&ch_body);

        // TLS record header: type=22 (handshake), version=0x0301, length
        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    /// Synthetic TLS 1.3 ServerHello record: legacy version 1.2, one
    /// cipher (0x1301), no compression, a single `supported_versions`
    /// extension (type 43) selecting TLS 1.3.
    fn build_server_hello_record() -> Vec<u8> {
        let mut sh_body = Vec::new();
        sh_body.extend_from_slice(&[0x03, 0x03]); // legacy version TLS 1.2
        sh_body.extend_from_slice(&[0u8; 32]); // random
        sh_body.push(0); // session_id length
        sh_body.extend_from_slice(&[0x13, 0x01]); // chosen cipher suite
        sh_body.push(0); // compression = null
        // Extensions: supported_versions (43) selecting 0x0304 (TLS 1.3).
        let ext = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
        sh_body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        sh_body.extend_from_slice(&ext);

        // Handshake header: type=2 (ServerHello), 3-byte length + body.
        let mut handshake = Vec::new();
        handshake.push(0x02);
        let len = sh_body.len();
        handshake.push(((len >> 16) & 0xff) as u8);
        handshake.push(((len >> 8) & 0xff) as u8);
        handshake.push((len & 0xff) as u8);
        handshake.extend_from_slice(&sh_body);

        // TLS record header: type=22 (handshake), version 0x0303.
        let mut record = Vec::new();
        record.push(0x16);
        record.extend_from_slice(&[0x03, 0x03]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    #[cfg(feature = "tls-fingerprints")]
    #[test]
    fn emits_extension_types_for_server_hello() {
        // The ServerHello carries the parsed extension list (43 =
        // supported_versions). This is generic observed data, NOT the
        // FoxIO-licensed JA4S algorithm, so it stays under `tls-fingerprints`.
        let mut p = TlsParser::with_config(TlsConfig {
            ja4: true,
            ..TlsConfig::default()
        });
        let messages = feed_resp(&mut p, &build_server_hello_record());
        let sh = messages.iter().find_map(|m| match m {
            TlsMessage::ServerHello(sh) => Some(sh),
            _ => None,
        });
        let sh = sh.expect("expected a ServerHello message");
        assert!(
            sh.extension_types.contains(&43),
            "extension_types = {:?}",
            sh.extension_types
        );
    }

    #[cfg(feature = "ja4plus")]
    #[test]
    fn emits_ja4s_for_server_hello() {
        // JA4S (FoxIO License 1.1, opt-in `ja4plus`) rides alongside the
        // ServerHello when `ja4` config is on.
        let mut p = TlsParser::with_config(TlsConfig {
            ja4: true,
            ..TlsConfig::default()
        });
        let messages = feed_resp(&mut p, &build_server_hello_record());
        let ja4s = messages.iter().find_map(|m| match m {
            TlsMessage::Ja4s { fingerprint } => Some(fingerprint),
            _ => None,
        });
        let fp = ja4s.expect("expected a Ja4s message");
        // t = TCP, 13 = negotiated TLS 1.3, 01 = one extension, 00 = no alpn.
        assert!(fp.starts_with("t130100_1301_"), "ja4s = {fp}");
    }

    fn feed_init(p: &mut TlsParser, bytes: &[u8]) -> Vec<TlsMessage> {
        let mut out = Vec::new();
        p.feed_initiator(bytes, Timestamp::default(), &mut out);
        out
    }
    fn feed_resp(p: &mut TlsParser, bytes: &[u8]) -> Vec<TlsMessage> {
        let mut out = Vec::new();
        p.feed_responder(bytes, Timestamp::default(), &mut out);
        out
    }

    #[test]
    fn parses_client_hello() {
        let mut p = TlsParser::default();
        let bytes = build_client_hello_record();
        let messages = feed_init(&mut p, &bytes);
        assert!(
            messages
                .iter()
                .any(|m| matches!(m, TlsMessage::ClientHello(_))),
            "expected at least one ClientHello, got {messages:?}"
        );
    }

    #[test]
    fn split_segments_concatenate() {
        let mut p = TlsParser::default();
        let bytes = build_client_hello_record();
        let mut all_msgs = Vec::new();
        for chunk in bytes.chunks(1) {
            all_msgs.extend(feed_init(&mut p, chunk));
        }
        assert!(
            all_msgs
                .iter()
                .any(|m| matches!(m, TlsMessage::ClientHello(_))),
            "expected ClientHello after byte-at-a-time feed, got {all_msgs:?}"
        );
    }

    #[test]
    fn rst_clears_state() {
        let mut p = TlsParser::default();
        feed_init(&mut p, &[0x16, 0x03, 0x01, 0x00]);
        p.rst_initiator();
        assert!(p.init_buf.is_empty());
        assert_eq!(p.init_state, DirState::Reading);
    }

    #[test]
    fn empty_feed_returns_empty() {
        let mut p = TlsParser::default();
        assert!(feed_init(&mut p, &[]).is_empty());
        assert!(feed_resp(&mut p, &[]).is_empty());
    }
}

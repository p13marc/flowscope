//! [`TlsParser`] — `SessionParser` impl that produces TLS handshake
//! events as a typed message stream.
//!
//! Equivalent to [`crate::tls::TlsFactory`] but in the
//! `SessionParser` shape: pair with `netring::FlowStream::session_stream(...)`
//! to get an async iterator of TLS events instead of a callback
//! handler.

use crate::{SessionParser, Timestamp};

use super::parser::{self, DirState, ParseOutput};
use super::types::{TlsAlert, TlsClientHello, TlsConfig, TlsServerHello};

/// Unified message type emitted by [`TlsParser`].
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "type", content = "data", rename_all = "snake_case")
)]
pub enum TlsMessage {
    /// Client → server handshake `ClientHello`.
    ClientHello(Box<TlsClientHello>),
    /// Server → client handshake `ServerHello`.
    ServerHello(Box<TlsServerHello>),
    /// Either-direction TLS alert.
    Alert(TlsAlert),
    /// JA3 fingerprint computed from a [`Self::ClientHello`]. Only
    /// emitted when [`TlsConfig::ja3`] is true (and the `ja3` feature
    /// is on).
    #[cfg(feature = "ja3")]
    Ja3 {
        /// MD5 hex digest of the canonical string.
        hash: String,
        /// Canonical string (raw fingerprint, dash-joined fields).
        canonical: String,
    },
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
        loop {
            match parser::step(state, buf, is_initiator, cfg) {
                Ok(Some(parsed)) => Self::dispatch(parsed, cfg, out),
                Ok(None) => break,
                Err(_) => {
                    buf.clear();
                    break;
                }
            }
        }
    }

    fn dispatch(parsed: ParseOutput, cfg: &TlsConfig, out: &mut Vec<TlsMessage>) {
        match parsed {
            ParseOutput::ClientHello(ch) => {
                #[cfg(feature = "ja3")]
                if cfg.ja3 {
                    let (canonical, hash) = super::fingerprint::ja3(&ch);
                    out.push(TlsMessage::Ja3 { hash, canonical });
                }
                #[cfg(not(feature = "ja3"))]
                {
                    let _ = cfg; // silence unused-warning when ja3 is off
                }
                out.push(TlsMessage::ClientHello(ch));
            }
            ParseOutput::ServerHello(sh) => out.push(TlsMessage::ServerHello(sh)),
            ParseOutput::Alert(a) => out.push(TlsMessage::Alert(a)),
        }
    }
}

impl SessionParser for TlsParser {
    type Message = TlsMessage;

    fn feed_initiator(&mut self, bytes: &[u8], _ts: Timestamp) -> Vec<TlsMessage> {
        if bytes.is_empty() || matches!(self.init_state, DirState::Encrypted | DirState::Desynced) {
            return Vec::new();
        }
        self.init_buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        Self::drain(
            &mut self.init_state,
            &mut self.init_buf,
            true,
            &self.config,
            &mut out,
        );
        out
    }

    fn feed_responder(&mut self, bytes: &[u8], _ts: Timestamp) -> Vec<TlsMessage> {
        if bytes.is_empty() || matches!(self.resp_state, DirState::Encrypted | DirState::Desynced) {
            return Vec::new();
        }
        self.resp_buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        Self::drain(
            &mut self.resp_state,
            &mut self.resp_buf,
            false,
            &self.config,
            &mut out,
        );
        out
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
    use bytes::Bytes;

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

    #[test]
    fn parses_client_hello() {
        let mut p = TlsParser::default();
        let bytes = build_client_hello_record();
        let messages = p.feed_initiator(&bytes, Timestamp::default());
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
        // Feed one byte at a time.
        let mut all_msgs = Vec::new();
        for chunk in bytes.chunks(1) {
            all_msgs.extend(p.feed_initiator(chunk, Timestamp::default()));
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
        // Feed a partial record; nothing should emit.
        p.feed_initiator(&[0x16, 0x03, 0x01, 0x00], Timestamp::default()); // partial record header
        p.rst_initiator();
        assert!(p.init_buf.is_empty());
        assert_eq!(p.init_state, DirState::Reading);
    }

    #[test]
    fn empty_feed_returns_empty() {
        let mut p = TlsParser::default();
        assert!(p.feed_initiator(&[], Timestamp::default()).is_empty());
        assert!(p.feed_responder(&[], Timestamp::default()).is_empty());
    }

    // Touch private types so cargo doesn't flag them.
    #[allow(dead_code)]
    fn _bytes_used() -> Bytes {
        Bytes::new()
    }
}

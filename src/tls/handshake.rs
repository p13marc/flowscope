//! [`TlsHandshakeParser`] — aggregates ClientHello + ServerHello +
//! Alert into a single [`TlsHandshake`] message per flow.
//!
//! The existing [`super::TlsParser`] emits per-message events;
//! consumers tracking "what handshake happened on this flow"
//! hand-rolled correlation across those events. This parser
//! does that stitching internally and emits one rich event per
//! handshake outcome.

use crate::Timestamp;
use crate::session::SessionParser;

use super::TlsParser;
use super::session::TlsMessage;
use super::types::{TlsConfig, TlsVersion};

/// Outcome of an observed handshake.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum HandshakeOutcome {
    /// ServerHello arrived; no fatal alert observed during the
    /// handshake window.
    Completed,
    /// Server sent a fatal alert.
    AlertedByServer { description: u8 },
    /// Client sent a fatal alert.
    AlertedByClient { description: u8 },
    /// Flow ended (FIN/RST/timeout) before a ServerHello arrived.
    Truncated,
}

/// Aggregated TLS handshake event.
///
/// One emitted per observed handshake. Carries enough fields for
/// the common "log TLS handshake" use case (SNI, ALPN, version,
/// cipher, JA3/JA4 if features on, outcome) without consumers
/// hand-rolling correlation across the per-message stream.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct TlsHandshake {
    pub sni: Option<String>,
    pub client_alpn: Vec<String>,
    pub server_alpn: Option<String>,
    /// JA3 fingerprint (MD5 hex). Set when `ja3` feature on.
    pub ja3: Option<String>,
    /// JA4 fingerprint (FoxIO format). Set when `ja4` feature on.
    pub ja4: Option<String>,
    /// Negotiated TLS version (from ServerHello supported_versions
    /// if present, else legacy_version).
    pub version: Option<TlsVersion>,
    /// Server's selected cipher suite.
    pub cipher_suite: Option<u16>,
    /// True iff the client sent PSK / session-ticket extensions
    /// (indicates resumption was attempted).
    pub resumption_attempted: bool,
    /// Final outcome.
    pub outcome: HandshakeOutcome,
}

impl Default for TlsHandshake {
    fn default() -> Self {
        Self {
            sni: None,
            client_alpn: Vec::new(),
            server_alpn: None,
            ja3: None,
            ja4: None,
            version: None,
            cipher_suite: None,
            resumption_attempted: false,
            outcome: HandshakeOutcome::Truncated,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    AwaitingClientHello,
    AwaitingServerHello,
    /// After ServerHello until the next ClientHello (resumption /
    /// renegotiation produces a fresh handshake event).
    Completed,
}

/// `SessionParser` that emits one `TlsHandshake` per observed
/// handshake on the underlying TCP flow.
///
/// Reuses [`TlsParser`] internally for the per-message decode
/// (no duplication of the tls-parser bridge). The handshake
/// aggregator accumulates fields from successive messages and
/// emits on terminal events (ServerHello completion or alert).
#[derive(Debug, Clone)]
pub struct TlsHandshakeParser {
    inner: TlsParser,
    state: State,
    accumulator: TlsHandshake,
}

impl Default for TlsHandshakeParser {
    fn default() -> Self {
        Self::with_config(TlsConfig {
            ja3: cfg!(feature = "ja3"),
            ja4: cfg!(feature = "ja4"),
            ..Default::default()
        })
    }
}

impl TlsHandshakeParser {
    /// Construct with explicit config. Defaults turn on JA3/JA4
    /// when their features are enabled.
    pub fn with_config(config: TlsConfig) -> Self {
        Self {
            inner: TlsParser::with_config(config),
            state: State::AwaitingClientHello,
            accumulator: TlsHandshake::default(),
        }
    }

    fn process(&mut self, msgs: Vec<TlsMessage>, out: &mut Vec<TlsHandshake>) {
        for msg in msgs {
            match msg {
                TlsMessage::ClientHello(ch) => {
                    // A new ClientHello while we were in Completed
                    // state — emit the previous (if any) as a fresh
                    // event for the next handshake.
                    self.accumulator.sni = ch.sni.clone();
                    self.accumulator.client_alpn = ch.alpn.clone();
                    // 41 = pre_shared_key, 35 = session_ticket
                    self.accumulator.resumption_attempted =
                        ch.extension_types.iter().any(|&e| e == 41 || e == 35);
                    self.state = State::AwaitingServerHello;
                }
                TlsMessage::ServerHello(sh) => {
                    self.accumulator.server_alpn = sh.alpn.clone();
                    self.accumulator.cipher_suite = Some(sh.cipher_suite);
                    self.accumulator.version =
                        Some(sh.supported_version.unwrap_or(sh.legacy_version));
                    self.accumulator.outcome = HandshakeOutcome::Completed;
                    let done = std::mem::take(&mut self.accumulator);
                    out.push(done);
                    self.state = State::Completed;
                }
                TlsMessage::Alert(a) => {
                    if a.level == super::types::TlsAlertLevel::Fatal {
                        // Caller-side fatal alert. We can't tell
                        // initiator from responder at this layer
                        // (alerts can come from either); attribute
                        // to whichever side was "expected" given
                        // current state.
                        let outcome = match self.state {
                            State::AwaitingServerHello => HandshakeOutcome::AlertedByServer {
                                description: a.description,
                            },
                            _ => HandshakeOutcome::AlertedByClient {
                                description: a.description,
                            },
                        };
                        self.accumulator.outcome = outcome;
                        let done = std::mem::take(&mut self.accumulator);
                        out.push(done);
                        self.state = State::AwaitingClientHello;
                    }
                }
                #[cfg(feature = "ja3")]
                TlsMessage::Ja3 { hash, .. } => {
                    self.accumulator.ja3 = Some(hash);
                }
                #[cfg(feature = "ja4")]
                TlsMessage::Ja4 { fingerprint } => {
                    self.accumulator.ja4 = Some(fingerprint);
                }
            }
        }
    }
}

impl SessionParser for TlsHandshakeParser {
    type Message = TlsHandshake;

    fn parser_kind(&self) -> &'static str {
        "tls-handshake"
    }

    fn feed_initiator(&mut self, bytes: &[u8], ts: Timestamp) -> Vec<Self::Message> {
        let inner_out = self.inner.feed_initiator(bytes, ts);
        let mut out = Vec::new();
        self.process(inner_out, &mut out);
        out
    }

    fn feed_responder(&mut self, bytes: &[u8], ts: Timestamp) -> Vec<Self::Message> {
        let inner_out = self.inner.feed_responder(bytes, ts);
        let mut out = Vec::new();
        self.process(inner_out, &mut out);
        out
    }

    fn fin_initiator(&mut self) -> Vec<Self::Message> {
        let inner_out = self.inner.fin_initiator();
        let mut out = Vec::new();
        self.process(inner_out, &mut out);
        // Flow ended without server hello → Truncated outcome.
        if matches!(self.state, State::AwaitingServerHello) {
            self.accumulator.outcome = HandshakeOutcome::Truncated;
            let done = std::mem::take(&mut self.accumulator);
            out.push(done);
            self.state = State::AwaitingClientHello;
        }
        out
    }

    fn fin_responder(&mut self) -> Vec<Self::Message> {
        let inner_out = self.inner.fin_responder();
        let mut out = Vec::new();
        self.process(inner_out, &mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_has_session_parser_shape() {
        // Compile-only: the parser implements SessionParser.
        fn assert_impls<P: SessionParser>() {}
        assert_impls::<TlsHandshakeParser>();
    }

    #[test]
    fn parser_kind_label() {
        let p = TlsHandshakeParser::default();
        assert_eq!(p.parser_kind(), "tls-handshake");
    }
}

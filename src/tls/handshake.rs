//! [`TlsHandshakeParser`] — aggregates ClientHello + ServerHello +
//! Alert into a single [`TlsHandshake`] message per flow.
//!
//! The existing [`super::TlsParser`] emits per-message events;
//! consumers tracking "what handshake happened on this flow"
//! hand-rolled correlation across those events. This parser
//! does that stitching internally and emits one rich event per
//! handshake outcome.

use bytes::Bytes;

use super::{
    TlsParser,
    session::TlsMessage,
    types::{TlsConfig, TlsVersion},
};
use crate::{Timestamp, session::SessionParser};

/// Stable identifier for the handshake aggregator — the
/// [`ParserKind::TlsHandshake`](crate::ParserKind::TlsHandshake)
/// slug, so consumers don't have to write the magic string.
pub const PARSER_KIND: &str = "tls-handshake";

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
    /// JA4S server fingerprint (FoxIO format), from the ServerHello.
    /// Set when the `ja4` config + opt-in `ja4plus` feature are on.
    /// New in 0.15.0; moved behind `ja4plus` in 0.16.0 (FoxIO License 1.1 —
    /// see NOTICE).
    #[cfg(feature = "ja4plus")]
    pub ja4s: Option<String>,
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

    // ── ECH — plan 144, 0.12.0 ───────────────────────────
    /// Aggregated ECH outcome derived from the client's
    /// `ech_present` flag plus the server's
    /// `ech_retry_configs` plaintext-fallback signal.
    pub ech_outcome: EchOutcome,
    /// HPKE `config_id` from the client's outer ECHClientHello,
    /// when ECH was offered.
    pub ech_config_id: Option<u8>,
    /// `true` if the client offered a post-quantum hybrid
    /// key-exchange group (X25519MLKEM768 family). Mirrors
    /// [`TlsClientHello::pq_key_share`](super::TlsClientHello::pq_key_share);
    /// the dominant reason a modern ClientHello spans multiple
    /// segments. Issue #135 (0.22.0).
    pub pq_key_share: bool,
    /// Server's certificate chain from a TLS 1.2 `Certificate`
    /// handshake record (leaf first per RFC 5246 §7.4.2). Each
    /// entry is an X.509 DER blob. Empty for TLS 1.3
    /// (cert chain is encrypted) and for sessions where no cert
    /// record was observed before the parser stopped. New in
    /// 0.18.0 (issue #24 prereq).
    pub certificate_chain: Vec<Bytes>,
    /// JA4X server-certificate fingerprint of the **leaf**
    /// (first) cert in [`Self::certificate_chain`]. Behind
    /// the FoxIO-licensed `ja4plus` feature. `None` when no
    /// cert chain was observed (TLS 1.3 / truncated /
    /// `ja4plus` off) or the DER failed to parse.
    /// Issue #24 (0.18.0).
    #[cfg(feature = "ja4plus")]
    pub ja4x: Option<String>,
}

/// Aggregate ECH outcome on a [`TlsHandshake`]. Plan 144, 0.12.0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum EchOutcome {
    /// Client did not offer ECH.
    NotOffered,
    /// Client offered ECH and the server did not signal
    /// rejection in observable plaintext. Most ECH-accepted
    /// handshakes land here (EncryptedExtensions carries
    /// retry_configs encrypted; we can't see them).
    Accepted,
    /// Client offered ECH; server's plaintext EE carries
    /// retry_configs — explicit rejection on early handshake
    /// errors.
    Rejected,
    /// Client offered ECH; outcome indeterminate (handshake
    /// did not reach ServerHello / EncryptedExtensions).
    Unknown,
}

impl TlsHandshake {
    /// Classify the ECH (Encrypted ClientHello) state from the
    /// handshake-level evidence — the client's ECH offer and the
    /// server's plaintext-observable rejection signal.
    ///
    /// Refines [`crate::tls::TlsClientHello::ech_state`] with
    /// the server side:
    ///
    /// - `ech_outcome == NotOffered` → [`super::EchState::NotPresent`]
    /// - `ech_outcome == Rejected` → [`super::EchState::Rejected`]
    /// - else: classify by outer SNI via
    ///   [`super::ech::classify_client_hello`] (Accepted /
    ///   Unknown without `retry_configs` can't be distinguished
    ///   from GREASE without further evidence).
    ///
    /// Issue #8 (0.18).
    pub fn ech_state(&self) -> super::EchState {
        match self.ech_outcome {
            EchOutcome::NotOffered => super::EchState::NotPresent,
            EchOutcome::Rejected => super::EchState::Rejected,
            EchOutcome::Accepted | EchOutcome::Unknown => {
                super::ech::classify_client_hello(true, self.sni.as_deref())
            }
        }
    }

    /// The ALPN protocol to route on: the server's selection if the
    /// handshake got that far, otherwise the client's first offer.
    ///
    /// The server's choice is the negotiated outcome; the client's
    /// list is only a wish. A terminating proxy uses this to decide
    /// whether to speak HTTP/1 or HTTP/2 on the connection.
    ///
    /// ```
    /// use flowscope::tls::TlsHandshake;
    ///
    /// let mut hs = TlsHandshake::default();
    /// hs.client_alpn = vec!["h2".into(), "http/1.1".into()];
    /// assert_eq!(hs.routing_alpn(), Some("h2"));
    ///
    /// // Once the server picks, that wins over the offer order.
    /// hs.server_alpn = Some("http/1.1".into());
    /// assert_eq!(hs.routing_alpn(), Some("http/1.1"));
    /// ```
    pub fn routing_alpn(&self) -> Option<&str> {
        self.server_alpn
            .as_deref()
            .or_else(|| self.client_alpn.first().map(String::as_str))
    }

    /// The name to route on, and whether it can be trusted as the
    /// client's real target.
    ///
    /// Returns `(name, is_real_target)`. With ECH in play the SNI on
    /// the wire is the outer cover domain, so `is_real_target` is
    /// `false` and the caller should expect to fall further down the
    /// ladder in `docs/tls-routing.md`. `None` means no SNI at all —
    /// route by JA4, first-byte class, or pass through.
    ///
    /// This never *fails* on ECH: degrading is the designed
    /// behaviour, and refusing connections that offer ECH would
    /// refuse a growing share of ordinary traffic.
    ///
    /// ```
    /// use flowscope::tls::{EchOutcome, TlsHandshake};
    ///
    /// let mut hs = TlsHandshake::default();
    /// hs.sni = Some("api.example.com".into());
    /// assert_eq!(hs.routing_sni(), Some(("api.example.com", true)));
    ///
    /// // With ECH offered, the same field is only a cover name.
    /// hs.ech_outcome = EchOutcome::Accepted;
    /// assert_eq!(hs.routing_sni(), Some(("api.example.com", false)));
    /// ```
    pub fn routing_sni(&self) -> Option<(&str, bool)> {
        let name = self.sni.as_deref()?;
        let is_real_target = matches!(self.ech_outcome, EchOutcome::NotOffered);
        Some((name, is_real_target))
    }
}

impl Default for TlsHandshake {
    fn default() -> Self {
        Self {
            sni: None,
            client_alpn: Vec::new(),
            server_alpn: None,
            ja3: None,
            ja4: None,
            #[cfg(feature = "ja4plus")]
            ja4s: None,
            version: None,
            cipher_suite: None,
            resumption_attempted: false,
            outcome: HandshakeOutcome::Truncated,
            ech_outcome: EchOutcome::NotOffered,
            ech_config_id: None,
            pq_key_share: false,
            certificate_chain: Vec::new(),
            #[cfg(feature = "ja4plus")]
            ja4x: None,
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
            ja3: cfg!(feature = "tls-fingerprints"),
            ja4: cfg!(feature = "tls-fingerprints"),
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
                    self.accumulator.pq_key_share = ch.pq_key_share;
                    // 41 = pre_shared_key, 35 = session_ticket
                    self.accumulator.resumption_attempted =
                        ch.extension_types.iter().any(|&e| e == 41 || e == 35);
                    // Plan 144: capture ECH offer state from the
                    // outer ClientHello.
                    if ch.ech_present {
                        self.accumulator.ech_outcome = EchOutcome::Unknown;
                        self.accumulator.ech_config_id = ch.ech_config_id;
                    }
                    self.state = State::AwaitingServerHello;
                }
                TlsMessage::ServerHello(sh) => {
                    self.accumulator.server_alpn = sh.alpn.clone();
                    self.accumulator.cipher_suite = Some(sh.cipher_suite);
                    self.accumulator.version =
                        Some(sh.supported_version.unwrap_or(sh.legacy_version));
                    self.accumulator.outcome = HandshakeOutcome::Completed;
                    // Plan 144: derive ECH outcome from the
                    // server's plaintext-observable signal.
                    if matches!(self.accumulator.ech_outcome, EchOutcome::Unknown) {
                        self.accumulator.ech_outcome = if sh.ech_retry_configs {
                            EchOutcome::Rejected
                        } else {
                            EchOutcome::Accepted
                        };
                    }
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
                #[cfg(feature = "tls-fingerprints")]
                TlsMessage::Ja3 { hash, .. } => {
                    self.accumulator.ja3 = Some(hash);
                }
                #[cfg(feature = "tls-fingerprints")]
                TlsMessage::Ja4 { fingerprint } => {
                    self.accumulator.ja4 = Some(fingerprint);
                }
                // Ja4s is emitted right before its ServerHello, so it
                // lands in the accumulator before the ServerHello arm
                // takes it. FoxIO-licensed → opt-in `ja4plus`.
                #[cfg(feature = "ja4plus")]
                TlsMessage::Ja4s { fingerprint } => {
                    self.accumulator.ja4s = Some(fingerprint);
                }
                // TLS 1.2 cert chain — accumulate; the ServerHello
                // arm will take it via std::mem::take.
                TlsMessage::Certificate { chain } => {
                    // JA4X over the leaf cert (FoxIO ja4plus).
                    #[cfg(feature = "ja4plus")]
                    if let Some(leaf) = chain.first() {
                        self.accumulator.ja4x = super::ja4x::ja4x_for_der(leaf);
                    }
                    self.accumulator.certificate_chain = chain;
                }
            }
        }
    }
}

impl SessionParser for TlsHandshakeParser {
    type Message = TlsHandshake;

    fn parser_kind(&self) -> crate::ParserKind {
        crate::ParserKind::TlsHandshake
    }

    fn feed_initiator(&mut self, bytes: &[u8], ts: Timestamp, out: &mut Vec<Self::Message>) {
        let mut inner_out = Vec::new();
        self.inner.feed_initiator(bytes, ts, &mut inner_out);
        self.process(inner_out, out);
    }

    fn feed_responder(&mut self, bytes: &[u8], ts: Timestamp, out: &mut Vec<Self::Message>) {
        let mut inner_out = Vec::new();
        self.inner.feed_responder(bytes, ts, &mut inner_out);
        self.process(inner_out, out);
    }

    fn fin_initiator(&mut self, out: &mut Vec<Self::Message>) {
        let mut inner_out = Vec::new();
        self.inner.fin_initiator(&mut inner_out);
        self.process(inner_out, out);
        if matches!(self.state, State::AwaitingServerHello) {
            self.accumulator.outcome = HandshakeOutcome::Truncated;
            let done = std::mem::take(&mut self.accumulator);
            out.push(done);
            self.state = State::AwaitingClientHello;
        }
    }

    fn fin_responder(&mut self, out: &mut Vec<Self::Message>) {
        let mut inner_out = Vec::new();
        self.inner.fin_responder(&mut inner_out);
        self.process(inner_out, out);
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
        assert_eq!(p.parser_kind().as_str(), "tls-handshake");
    }

    #[cfg(feature = "ja4plus")]
    #[test]
    fn aggregator_captures_ja4s_onto_the_handshake() {
        use super::super::{TlsMessage, types::TlsServerHello};

        let mut p = TlsHandshakeParser::default();
        let mut out = Vec::new();
        // Ja4s is emitted right before its ServerHello (the session
        // parser's ordering), so it lands in the accumulator that the
        // ServerHello arm then takes.
        let sh = TlsServerHello {
            cipher_suite: 0x1301,
            ..Default::default()
        };
        p.process(
            vec![
                TlsMessage::Ja4s {
                    fingerprint: "t130100_1301_deadbeefcafe".to_string(),
                },
                TlsMessage::ServerHello(Box::new(sh)),
            ],
            &mut out,
        );
        assert_eq!(out.len(), 1, "expected one completed handshake");
        assert_eq!(out[0].ja4s.as_deref(), Some("t130100_1301_deadbeefcafe"));
    }
}

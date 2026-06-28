//! [`FtpParser`] — `SessionParser` over the FTP control channel.

use bytes::BytesMut;

use super::parser::{extract_line, split_command, split_reply};
use super::types::{FtpCommand, FtpMessage, TransferKind};
use crate::Timestamp;
use crate::session::SessionParser;

/// Stable identifier for the parser.
pub const PARSER_KIND: &str = "ftp";

/// IANA-assigned FTP control-channel port.
pub const FTP_PORT: u16 = 21;

/// `SessionParser` that emits one [`FtpMessage`] per parsed
/// FTP command / reply line plus aggregated
/// [`FtpMessage::Credentials`] / [`FtpMessage::Transfer`] /
/// [`FtpMessage::TlsUpgrade`] convenience events.
#[derive(Debug, Clone, Default)]
pub struct FtpParser {
    init: SideState,
    resp: SideState,
    /// Pending `USER` username waiting for a `PASS`. Cleared
    /// once the pair is emitted as `Credentials`.
    pending_user: Option<String>,
    /// `true` after `AUTH TLS` / `AUTH SSL` command has been
    /// observed; waits for a `234` reply before emitting
    /// `TlsUpgrade`.
    auth_tls_requested: bool,
    /// `true` after we've emitted `TlsUpgrade` — subsequent
    /// bytes are TLS-encrypted and we stop draining.
    encrypted: bool,
    /// `true` once we've emitted the server banner.
    banner_seen: bool,
}

#[derive(Debug, Clone, Default)]
struct SideState {
    buffer: BytesMut,
}

impl FtpParser {
    pub fn new() -> Self {
        Self::default()
    }

    fn drain_initiator(&mut self, out: &mut Vec<FtpMessage>) {
        while let Some(line) = extract_line(&mut self.init.buffer) {
            let Some((verb_raw, args)) = split_command(&line) else {
                continue;
            };
            let verb = FtpCommand::from_verb(verb_raw);
            let args_str = args.to_string();

            // Credential aggregation.
            if matches!(verb, FtpCommand::User) && !args_str.is_empty() {
                self.pending_user = Some(args_str.clone());
            } else if matches!(verb, FtpCommand::Pass)
                && let Some(user) = self.pending_user.take()
            {
                out.push(FtpMessage::Credentials {
                    user,
                    pass: args_str.clone(),
                });
            }

            // AUTH TLS request (waits for 234 reply).
            if matches!(verb, FtpCommand::Auth) {
                let upper = args_str.to_ascii_uppercase();
                if upper == "TLS" || upper == "SSL" || upper == "TLS-C" {
                    self.auth_tls_requested = true;
                }
            }

            // Transfer convenience event.
            if let Some(kind) = TransferKind::from_command(&verb) {
                out.push(FtpMessage::Transfer {
                    kind,
                    filename: args_str.clone(),
                });
            }

            out.push(FtpMessage::Command {
                verb,
                args: args_str,
            });
        }
    }

    fn drain_responder(&mut self, out: &mut Vec<FtpMessage>) {
        while let Some(line) = extract_line(&mut self.resp.buffer) {
            let Some((code, text, is_final)) = split_reply(&line) else {
                continue;
            };
            // We only surface final-line replies — intermediate
            // multi-line entries are noise for the consumer
            // surface but still detected via the `is_final`
            // flag.
            if !is_final {
                continue;
            }
            let text_owned = text.to_string();
            if !self.banner_seen && code == 220 {
                self.banner_seen = true;
                out.push(FtpMessage::Banner {
                    banner: text_owned.clone(),
                });
            }
            if self.auth_tls_requested && code == 234 {
                self.auth_tls_requested = false;
                out.push(FtpMessage::TlsUpgrade);
                self.encrypted = true;
                // Drain remaining buffered bytes into the void;
                // future feeds will short-circuit too.
                self.init.buffer.clear();
                self.resp.buffer.clear();
                out.push(FtpMessage::Reply {
                    code,
                    text: text_owned,
                });
                return;
            }
            out.push(FtpMessage::Reply {
                code,
                text: text_owned,
            });
        }
    }
}

impl SessionParser for FtpParser {
    type Message = FtpMessage;

    fn parser_kind(&self) -> crate::ParserKind {
        crate::ParserKind::Ftp
    }

    fn feed_initiator(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<Self::Message>) {
        if self.encrypted {
            return;
        }
        self.init.buffer.extend_from_slice(bytes);
        self.drain_initiator(out);
    }

    fn feed_responder(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<Self::Message>) {
        if self.encrypted {
            return;
        }
        self.resp.buffer.extend_from_slice(bytes);
        self.drain_responder(out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts() -> Timestamp {
        Timestamp::default()
    }

    #[test]
    fn parser_kind_label() {
        assert_eq!(FtpParser::new().parser_kind().as_str(), "ftp");
    }

    #[test]
    fn port_constant_matches_iana() {
        assert_eq!(FTP_PORT, 21);
    }

    #[test]
    fn banner_emitted_first() {
        let mut p = FtpParser::new();
        let mut out = Vec::new();
        p.feed_responder(b"220 vsFTPd 3.0.3\r\n", ts(), &mut out);
        assert!(matches!(out[0], FtpMessage::Banner { ref banner } if banner == "vsFTPd 3.0.3"));
    }

    #[test]
    fn user_pass_emitted_as_credentials() {
        let mut p = FtpParser::new();
        let mut out = Vec::new();
        p.feed_initiator(b"USER alice\r\nPASS secret123\r\n", ts(), &mut out);
        let creds = out
            .iter()
            .find_map(|m| match m {
                FtpMessage::Credentials { user, pass } => Some((user.clone(), pass.clone())),
                _ => None,
            })
            .expect("creds emitted");
        assert_eq!(creds.0, "alice");
        assert_eq!(creds.1, "secret123");
    }

    #[test]
    fn user_without_pass_no_credentials() {
        let mut p = FtpParser::new();
        let mut out = Vec::new();
        p.feed_initiator(b"USER alice\r\n", ts(), &mut out);
        assert!(
            !out.iter()
                .any(|m| matches!(m, FtpMessage::Credentials { .. }))
        );
    }

    #[test]
    fn auth_tls_followed_by_234_emits_upgrade_and_stops() {
        let mut p = FtpParser::new();
        let mut out = Vec::new();
        p.feed_initiator(b"AUTH TLS\r\n", ts(), &mut out);
        p.feed_responder(b"234 AUTH TLS OK\r\n", ts(), &mut out);
        assert!(out.iter().any(|m| matches!(m, FtpMessage::TlsUpgrade)));
        // Subsequent feeds are dropped.
        let before = out.len();
        p.feed_initiator(b"\x16\x03\x01\x00", ts(), &mut out);
        p.feed_responder(b"\x16\x03\x01\x00", ts(), &mut out);
        assert_eq!(out.len(), before, "no events after TLS upgrade");
    }

    #[test]
    fn retr_emits_transfer_event() {
        let mut p = FtpParser::new();
        let mut out = Vec::new();
        p.feed_initiator(b"RETR /etc/passwd\r\n", ts(), &mut out);
        let xfer = out
            .iter()
            .find_map(|m| match m {
                FtpMessage::Transfer { kind, filename } => Some((*kind, filename.clone())),
                _ => None,
            })
            .expect("transfer emitted");
        assert_eq!(xfer.0, TransferKind::Download);
        assert_eq!(xfer.1, "/etc/passwd");
    }

    #[test]
    fn stor_emits_upload_transfer() {
        let mut p = FtpParser::new();
        let mut out = Vec::new();
        p.feed_initiator(b"STOR upload.zip\r\n", ts(), &mut out);
        assert!(out.iter().any(|m| matches!(
            m,
            FtpMessage::Transfer {
                kind: TransferKind::Upload,
                ..
            }
        )));
    }

    #[test]
    fn intermediate_multiline_reply_dropped() {
        let mut p = FtpParser::new();
        let mut out = Vec::new();
        p.feed_responder(b"220-part 1\r\n220-part 2\r\n220 done\r\n", ts(), &mut out);
        let replies: Vec<_> = out
            .iter()
            .filter(|m| matches!(m, FtpMessage::Reply { .. }))
            .collect();
        assert_eq!(replies.len(), 1, "only the final-line is surfaced");
    }

    #[test]
    fn case_insensitive_verb_matching() {
        let mut p = FtpParser::new();
        let mut out = Vec::new();
        p.feed_initiator(b"user bob\r\n", ts(), &mut out);
        p.feed_initiator(b"pass hunter2\r\n", ts(), &mut out);
        assert!(
            out.iter()
                .any(|m| matches!(m, FtpMessage::Credentials { .. }))
        );
    }

    #[test]
    fn unknown_command_emits_other() {
        let mut p = FtpParser::new();
        let mut out = Vec::new();
        p.feed_initiator(b"SITE CHMOD 644 file\r\n", ts(), &mut out);
        let cmd = out
            .iter()
            .find_map(|m| match m {
                FtpMessage::Command { verb, args } => Some((verb.clone(), args.clone())),
                _ => None,
            })
            .expect("command");
        assert!(matches!(cmd.0, FtpCommand::Other(ref v) if v == "SITE"));
        assert_eq!(cmd.1, "CHMOD 644 file");
    }

    #[test]
    fn buffer_survives_split_feed() {
        let mut p = FtpParser::new();
        let mut out = Vec::new();
        p.feed_initiator(b"USER al", ts(), &mut out);
        p.feed_initiator(b"ice\r\n", ts(), &mut out);
        let cmd = out
            .iter()
            .find_map(|m| match m {
                FtpMessage::Command { verb, args } => Some((verb.clone(), args.clone())),
                _ => None,
            })
            .expect("command");
        assert!(matches!(cmd.0, FtpCommand::User));
        assert_eq!(cmd.1, "alice");
    }
}

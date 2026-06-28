//! [`SmtpParser`] — `SessionParser` over the SMTP control channel.

use bytes::BytesMut;

use super::parser::{
    decode_auth_login_token, decode_auth_plain, extract_envelope_address, extract_line,
    split_command, split_reply,
};
use super::types::{SmtpCommand, SmtpMessage};
use crate::Timestamp;
use crate::session::SessionParser;

pub const PARSER_KIND: &str = "smtp";
pub const SMTP_PORT: u16 = 25;
pub const SMTP_SUBMISSION_PORT: u16 = 587;

/// `SessionParser` for cleartext SMTP per RFC 5321 / 4954.
#[derive(Debug, Clone, Default)]
pub struct SmtpParser {
    init: BytesMut,
    resp: BytesMut,
    banner_seen: bool,
    encrypted: bool,
    /// Pending command pending its reply. `MAIL FROM` /
    /// `RCPT TO` / `STARTTLS` / `DATA` / `AUTH` use this
    /// channel.
    pending_cmd: Option<PendingCmd>,
    /// In-progress AUTH LOGIN — `Some(None)` after server
    /// prompts for username, `Some(Some(user))` after client
    /// sent username and server prompted for password.
    auth_login_state: Option<Option<String>>,
    /// In-progress AUTH PLAIN — `true` after server prompts
    /// for the single base64 blob (`AUTH PLAIN` without
    /// initial response).
    auth_plain_inline: bool,
    /// `true` after `DATA` was accepted (`354`) — body bytes
    /// accumulate until `\r\n.\r\n`.
    in_data: bool,
    data_bytes: u64,
}

#[derive(Debug, Clone)]
enum PendingCmd {
    StartTls,
    Data,
    AuthPlain(Option<String>), // inline IR if provided
    AuthLogin,
}

impl SmtpParser {
    pub fn new() -> Self {
        Self::default()
    }

    fn drain_initiator(&mut self, out: &mut Vec<SmtpMessage>) {
        loop {
            // In DATA mode: bytes are the message body; look
            // for the `\r\n.\r\n` terminator.
            if self.in_data {
                if let Some(idx) = find_data_end(&self.init) {
                    let body_len = idx as u64;
                    self.data_bytes = self.data_bytes.saturating_add(body_len);
                    out.push(SmtpMessage::DataEnd {
                        bytes: self.data_bytes,
                    });
                    super::parser::advance_by(&mut self.init, idx + 5); // include "\r\n.\r\n"
                    self.in_data = false;
                    self.data_bytes = 0;
                    continue;
                } else {
                    // Consume all but the last 4 bytes (need
                    // them to detect a span-crossing
                    // terminator).
                    let keep = 4.min(self.init.len());
                    let consume = self.init.len() - keep;
                    self.data_bytes = self.data_bytes.saturating_add(consume as u64);
                    super::parser::advance_by(&mut self.init, consume);
                    return;
                }
            }
            let Some(line) = extract_line(&mut self.init) else {
                return;
            };
            // AUTH LOGIN: client sends base64-encoded user
            // then base64-encoded password as standalone
            // lines (no verb prefix).
            if let Some(state) = self.auth_login_state.clone() {
                let token = String::from_utf8_lossy(&line).to_string();
                match state {
                    None => {
                        // First token = username.
                        let user = decode_auth_login_token(&token).unwrap_or_default();
                        self.auth_login_state = Some(Some(user));
                    }
                    Some(user) => {
                        let pass = decode_auth_login_token(&token).unwrap_or_default();
                        out.push(SmtpMessage::Credentials {
                            mechanism: "LOGIN".into(),
                            user,
                            pass,
                        });
                        self.auth_login_state = None;
                    }
                }
                continue;
            }
            // AUTH PLAIN inline-prompted: a single standalone
            // base64 line carrying the whole \0user\0pass blob.
            if self.auth_plain_inline {
                let token = String::from_utf8_lossy(&line).to_string();
                if let Some((user, pass)) = decode_auth_plain(&token) {
                    out.push(SmtpMessage::Credentials {
                        mechanism: "PLAIN".into(),
                        user,
                        pass,
                    });
                }
                self.auth_plain_inline = false;
                continue;
            }
            let Some((verb_raw, args)) = split_command(&line) else {
                continue;
            };
            let verb = SmtpCommand::from_verb(verb_raw);
            let args_str = args.to_string();

            // Cmd-specific aggregation.
            match &verb {
                SmtpCommand::Helo | SmtpCommand::Ehlo => {
                    out.push(SmtpMessage::Helo {
                        domain: args_str.split_whitespace().next().unwrap_or("").to_string(),
                        esmtp: matches!(verb, SmtpCommand::Ehlo),
                    });
                }
                SmtpCommand::MailFrom => {
                    if let Some(addr) = extract_envelope_address(&args_str) {
                        out.push(SmtpMessage::MailFrom { address: addr });
                    }
                }
                SmtpCommand::RcptTo => {
                    if let Some(addr) = extract_envelope_address(&args_str) {
                        out.push(SmtpMessage::RcptTo { address: addr });
                    }
                }
                SmtpCommand::StartTls => {
                    self.pending_cmd = Some(PendingCmd::StartTls);
                }
                SmtpCommand::Data => {
                    self.pending_cmd = Some(PendingCmd::Data);
                }
                SmtpCommand::Auth => {
                    let mut parts = args_str.split_whitespace();
                    let mech = parts.next().unwrap_or("").to_ascii_uppercase();
                    let initial = parts.next().map(|s| s.to_string());
                    if mech == "PLAIN" {
                        if let Some(ir) = initial {
                            // AUTH PLAIN with inline initial response.
                            if let Some((user, pass)) = decode_auth_plain(&ir) {
                                out.push(SmtpMessage::Credentials {
                                    mechanism: "PLAIN".into(),
                                    user,
                                    pass,
                                });
                            }
                        } else {
                            // Server will prompt with 334;
                            // client's next line is the blob.
                            self.pending_cmd = Some(PendingCmd::AuthPlain(None));
                        }
                    } else if mech == "LOGIN" {
                        self.pending_cmd = Some(PendingCmd::AuthLogin);
                    }
                }
                _ => {}
            }
            out.push(SmtpMessage::Command {
                verb,
                args: args_str,
            });
        }
    }

    fn drain_responder(&mut self, out: &mut Vec<SmtpMessage>) {
        while let Some(line) = extract_line(&mut self.resp) {
            let Some((code, text, is_final)) = split_reply(&line) else {
                continue;
            };
            // For multi-line, the intermediate `XYZ-` lines
            // are reply lines too but we only surface the
            // final one. (Tests assert this.)
            if !is_final {
                continue;
            }
            let text_owned = text.to_string();
            if !self.banner_seen && code == 220 {
                self.banner_seen = true;
                out.push(SmtpMessage::Banner {
                    banner: text_owned.clone(),
                });
            }
            // React to pending commands by reply class.
            let pending = self.pending_cmd.take();
            match pending {
                Some(PendingCmd::StartTls) if code == 220 => {
                    out.push(SmtpMessage::Reply {
                        code,
                        text: text_owned,
                    });
                    out.push(SmtpMessage::TlsUpgrade);
                    self.encrypted = true;
                    self.init.clear();
                    self.resp.clear();
                    return;
                }
                Some(PendingCmd::Data) if code == 354 => {
                    self.in_data = true;
                    self.data_bytes = 0;
                    out.push(SmtpMessage::DataBegin);
                }
                Some(PendingCmd::AuthPlain(None)) if code == 334 => {
                    self.auth_plain_inline = true;
                }
                Some(PendingCmd::AuthLogin) if code == 334 => {
                    self.auth_login_state = Some(None);
                }
                Some(other) => {
                    // Other-than-expected reply; reset.
                    let _ = other;
                }
                None => {}
            }
            out.push(SmtpMessage::Reply {
                code,
                text: text_owned,
            });
        }
    }
}

/// Locate the `\r\n.\r\n` terminator. Returns the index of
/// the `\r` (the first byte). The "leading" `\r\n` is
/// optionally part of a previous-line terminator we already
/// consumed, but in practice the marker is always preceded
/// by content. We search for `\r\n.\r\n` and report idx of
/// the first `\r`.
fn find_data_end(buf: &BytesMut) -> Option<usize> {
    let needle = b"\r\n.\r\n";
    buf.windows(needle.len()).position(|w| w == needle)
}

impl SessionParser for SmtpParser {
    type Message = SmtpMessage;

    fn parser_kind(&self) -> crate::ParserKind {
        crate::ParserKind::Smtp
    }

    fn feed_initiator(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<Self::Message>) {
        if self.encrypted {
            return;
        }
        self.init.extend_from_slice(bytes);
        self.drain_initiator(out);
    }

    fn feed_responder(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<Self::Message>) {
        if self.encrypted {
            return;
        }
        self.resp.extend_from_slice(bytes);
        self.drain_responder(out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    fn ts() -> Timestamp {
        Timestamp::default()
    }

    #[test]
    fn parser_kind_and_ports() {
        assert_eq!(SmtpParser::new().parser_kind().as_str(), "smtp");
        assert_eq!(SMTP_PORT, 25);
        assert_eq!(SMTP_SUBMISSION_PORT, 587);
    }

    #[test]
    fn banner_emitted() {
        let mut p = SmtpParser::new();
        let mut out = Vec::new();
        p.feed_responder(b"220 mail.example.com ESMTP Postfix\r\n", ts(), &mut out);
        assert!(out.iter().any(|m| matches!(m, SmtpMessage::Banner { .. })));
    }

    #[test]
    fn helo_emitted_with_domain() {
        let mut p = SmtpParser::new();
        let mut out = Vec::new();
        p.feed_initiator(b"EHLO sender.example.org\r\n", ts(), &mut out);
        let helo = out
            .iter()
            .find_map(|m| match m {
                SmtpMessage::Helo { domain, esmtp } => Some((domain.clone(), *esmtp)),
                _ => None,
            })
            .expect("helo");
        assert_eq!(helo.0, "sender.example.org");
        assert!(helo.1, "EHLO → esmtp = true");
    }

    #[test]
    fn mail_from_extracted() {
        let mut p = SmtpParser::new();
        let mut out = Vec::new();
        p.feed_initiator(b"MAIL FROM:<sender@example.org>\r\n", ts(), &mut out);
        assert!(out.iter().any(|m| matches!(
            m,
            SmtpMessage::MailFrom { address } if address == "sender@example.org"
        )));
    }

    #[test]
    fn rcpt_to_extracted_with_size_param() {
        let mut p = SmtpParser::new();
        let mut out = Vec::new();
        p.feed_initiator(
            b"RCPT TO:<recipient@example.com> SIZE=2048\r\n",
            ts(),
            &mut out,
        );
        assert!(out.iter().any(|m| matches!(
            m,
            SmtpMessage::RcptTo { address } if address == "recipient@example.com"
        )));
    }

    #[test]
    fn auth_plain_inline_decodes_credentials() {
        let mut p = SmtpParser::new();
        let mut out = Vec::new();
        let blob = base64::engine::general_purpose::STANDARD.encode("\0alice\0secret");
        let cmd = format!("AUTH PLAIN {blob}\r\n");
        p.feed_initiator(cmd.as_bytes(), ts(), &mut out);
        let creds = out
            .iter()
            .find_map(|m| match m {
                SmtpMessage::Credentials {
                    user,
                    pass,
                    mechanism,
                } => Some((user.clone(), pass.clone(), mechanism.clone())),
                _ => None,
            })
            .expect("creds");
        assert_eq!(creds.0, "alice");
        assert_eq!(creds.1, "secret");
        assert_eq!(creds.2, "PLAIN");
    }

    #[test]
    fn auth_login_two_prompt_sequence() {
        let mut p = SmtpParser::new();
        let mut out = Vec::new();
        p.feed_initiator(b"AUTH LOGIN\r\n", ts(), &mut out);
        p.feed_responder(b"334 VXNlcm5hbWU6\r\n", ts(), &mut out);
        let user_b64 = base64::engine::general_purpose::STANDARD.encode("bob");
        p.feed_initiator(format!("{user_b64}\r\n").as_bytes(), ts(), &mut out);
        p.feed_responder(b"334 UGFzc3dvcmQ6\r\n", ts(), &mut out);
        let pass_b64 = base64::engine::general_purpose::STANDARD.encode("hunter2");
        p.feed_initiator(format!("{pass_b64}\r\n").as_bytes(), ts(), &mut out);
        let creds = out
            .iter()
            .find_map(|m| match m {
                SmtpMessage::Credentials {
                    user,
                    pass,
                    mechanism,
                } => Some((user.clone(), pass.clone(), mechanism.clone())),
                _ => None,
            })
            .expect("creds");
        assert_eq!(creds.0, "bob");
        assert_eq!(creds.1, "hunter2");
        assert_eq!(creds.2, "LOGIN");
    }

    #[test]
    fn starttls_then_220_emits_upgrade() {
        let mut p = SmtpParser::new();
        let mut out = Vec::new();
        p.feed_responder(b"220 Ready\r\n", ts(), &mut out);
        p.feed_initiator(b"STARTTLS\r\n", ts(), &mut out);
        p.feed_responder(b"220 Go ahead\r\n", ts(), &mut out);
        assert!(out.iter().any(|m| matches!(m, SmtpMessage::TlsUpgrade)));
        let before = out.len();
        p.feed_initiator(b"\x16\x03\x01\x00", ts(), &mut out);
        assert_eq!(out.len(), before, "post-upgrade bytes dropped");
    }

    #[test]
    fn data_354_starts_body_mode_then_terminator_ends() {
        let mut p = SmtpParser::new();
        let mut out = Vec::new();
        p.feed_initiator(b"DATA\r\n", ts(), &mut out);
        p.feed_responder(b"354 End data with <CRLF>.<CRLF>\r\n", ts(), &mut out);
        assert!(out.iter().any(|m| matches!(m, SmtpMessage::DataBegin)));
        // Send a short message body.
        p.feed_initiator(b"Subject: hi\r\n\r\nhello world\r\n.\r\n", ts(), &mut out);
        let end = out
            .iter()
            .find_map(|m| match m {
                SmtpMessage::DataEnd { bytes } => Some(*bytes),
                _ => None,
            })
            .expect("data end");
        assert!(end > 0);
    }

    #[test]
    fn multiline_reply_intermediates_dropped() {
        let mut p = SmtpParser::new();
        let mut out = Vec::new();
        p.feed_responder(
            b"250-mail.example.com\r\n250-PIPELINING\r\n250 SIZE 35882577\r\n",
            ts(),
            &mut out,
        );
        let replies: Vec<_> = out
            .iter()
            .filter(|m| matches!(m, SmtpMessage::Reply { .. }))
            .collect();
        assert_eq!(replies.len(), 1, "only the final-line is surfaced");
    }
}

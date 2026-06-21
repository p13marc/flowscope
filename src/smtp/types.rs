//! Public types for the SMTP parser.

/// One parsed SMTP control-channel message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "event", rename_all = "snake_case"))]
#[non_exhaustive]
pub enum SmtpMessage {
    /// Command from the client.
    Command { verb: SmtpCommand, args: String },
    /// Reply from the server (final-line only for multi-line).
    Reply { code: u16, text: String },
    /// Server banner — first `220` reply on the responder.
    Banner { banner: String },
    /// EHLO / HELO domain advertised by the client.
    Helo { domain: String, esmtp: bool },
    /// `MAIL FROM:<addr>`. `address` is the envelope-from
    /// with `<>` stripped; empty for the null-sender `<>`.
    MailFrom { address: String },
    /// `RCPT TO:<addr>`. `address` is the envelope-recipient
    /// with `<>` stripped.
    RcptTo { address: String },
    /// AUTH credentials. `mechanism` is `"PLAIN"` or
    /// `"LOGIN"`. `user` / `pass` are base64-decoded; either
    /// may be empty on a malformed exchange.
    Credentials {
        mechanism: String,
        user: String,
        pass: String,
    },
    /// `STARTTLS` was accepted (`220` reply). After this
    /// event the parser stops draining — pair with
    /// `flowscope::tls` for the encrypted handshake.
    TlsUpgrade,
    /// Client sent `DATA` and got `354 Start mail input`.
    /// Following bytes are message body terminated by
    /// `\r\n.\r\n`.
    DataBegin,
    /// Message body finished (`\r\n.\r\n` observed). `bytes`
    /// is the body length including headers but excluding the
    /// terminator dot line.
    DataEnd { bytes: u64 },
}

/// Enumerated SMTP commands of operational interest.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum SmtpCommand {
    Helo,
    Ehlo,
    MailFrom,
    RcptTo,
    Data,
    Rset,
    Vrfy,
    Expn,
    Help,
    Noop,
    Quit,
    StartTls,
    Auth,
    Bdat,
    Other(String),
}

impl SmtpCommand {
    pub fn from_verb(raw: &str) -> Self {
        let upper = raw.to_ascii_uppercase();
        match upper.as_str() {
            "HELO" => Self::Helo,
            "EHLO" => Self::Ehlo,
            "MAIL" => Self::MailFrom,
            "RCPT" => Self::RcptTo,
            "DATA" => Self::Data,
            "RSET" => Self::Rset,
            "VRFY" => Self::Vrfy,
            "EXPN" => Self::Expn,
            "HELP" => Self::Help,
            "NOOP" => Self::Noop,
            "QUIT" => Self::Quit,
            "STARTTLS" => Self::StartTls,
            "AUTH" => Self::Auth,
            "BDAT" => Self::Bdat,
            _ => Self::Other(upper),
        }
    }
}

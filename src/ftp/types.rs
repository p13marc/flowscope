//! Public types for the FTP parser.

/// One parsed FTP control-channel message. Emitted in
/// arrival order across both directions.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "event", rename_all = "snake_case"))]
#[non_exhaustive]
pub enum FtpMessage {
    /// A command from the client (initiator). `args` is the
    /// raw argument string — empty when the command takes
    /// no argument (e.g. `PASV`, `QUIT`).
    Command { verb: FtpCommand, args: String },
    /// A reply from the server (responder). `code` is the
    /// 3-digit numeric code; `text` is the trailing text.
    /// Multi-line replies are coalesced to their final-line
    /// text only per RFC 959 §4.2.
    Reply { code: u16, text: String },
    /// Server banner — first `220` reply on a fresh session.
    /// Convenience emission alongside the corresponding
    /// [`Self::Reply`]; commonly carries vendor + version
    /// strings (`220 (vsFTPd 3.0.3)`).
    Banner { banner: String },
    /// A `USER name` / `PASS secret` pair, surfaced as one
    /// event after both have been observed on the initiator
    /// side. Cleartext credential capture (T1078, T1110).
    Credentials { user: String, pass: String },
    /// `AUTH TLS` / `AUTH SSL` was accepted (`234` reply).
    /// After this event the parser stops draining bytes —
    /// pair with `flowscope::tls` for the encrypted
    /// handshake.
    TlsUpgrade,
    /// A data-transfer command. Surfaced as its own event
    /// (in addition to the underlying [`Self::Command`]) so
    /// downstream rules can react without parsing arg
    /// strings.
    Transfer {
        kind: TransferKind,
        filename: String,
    },
}

/// Enumerated FTP commands of operational interest. Every
/// other command is mapped to [`Self::Other`] with the raw
/// verb string preserved (uppercased).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum FtpCommand {
    User,
    Pass,
    Acct,
    Auth,
    Cwd,
    Cdup,
    Pwd,
    List,
    Nlst,
    Retr,
    Stor,
    Appe,
    Stou,
    Mkd,
    Rmd,
    Dele,
    Rnfr,
    Rnto,
    Pasv,
    Port,
    Epsv,
    Eprt,
    Type,
    Mode,
    Stru,
    Quit,
    Noop,
    Syst,
    Stat,
    Help,
    Feat,
    Opts,
    Other(String),
}

impl FtpCommand {
    /// Map a wire verb (case-insensitive) to the enum.
    pub fn from_verb(raw: &str) -> Self {
        let upper = raw.to_ascii_uppercase();
        match upper.as_str() {
            "USER" => Self::User,
            "PASS" => Self::Pass,
            "ACCT" => Self::Acct,
            "AUTH" => Self::Auth,
            "CWD" => Self::Cwd,
            "CDUP" => Self::Cdup,
            "PWD" => Self::Pwd,
            "LIST" => Self::List,
            "NLST" => Self::Nlst,
            "RETR" => Self::Retr,
            "STOR" => Self::Stor,
            "APPE" => Self::Appe,
            "STOU" => Self::Stou,
            "MKD" => Self::Mkd,
            "RMD" => Self::Rmd,
            "DELE" => Self::Dele,
            "RNFR" => Self::Rnfr,
            "RNTO" => Self::Rnto,
            "PASV" => Self::Pasv,
            "PORT" => Self::Port,
            "EPSV" => Self::Epsv,
            "EPRT" => Self::Eprt,
            "TYPE" => Self::Type,
            "MODE" => Self::Mode,
            "STRU" => Self::Stru,
            "QUIT" => Self::Quit,
            "NOOP" => Self::Noop,
            "SYST" => Self::Syst,
            "STAT" => Self::Stat,
            "HELP" => Self::Help,
            "FEAT" => Self::Feat,
            "OPTS" => Self::Opts,
            _ => Self::Other(upper),
        }
    }

    /// Returns `true` for the file-transfer commands —
    /// `RETR` / `STOR` / `APPE` / `STOU`.
    pub fn is_transfer(&self) -> bool {
        matches!(self, Self::Retr | Self::Stor | Self::Appe | Self::Stou)
    }
}

/// Classification of an FTP reply code's first digit.
/// Helps downstream tooling react to outcome without
/// parsing every code individually.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum FtpReplyClass {
    /// 1xx — positive preliminary (action being initiated).
    PositivePreliminary,
    /// 2xx — positive completion (action completed).
    PositiveCompletion,
    /// 3xx — positive intermediate (more info expected).
    PositiveIntermediate,
    /// 4xx — transient negative completion (try again).
    TransientNegative,
    /// 5xx — permanent negative completion (do not retry).
    PermanentNegative,
    /// Anything outside 1xx-5xx (malformed).
    Other,
}

impl FtpReplyClass {
    pub fn classify(code: u16) -> Self {
        match code / 100 {
            1 => Self::PositivePreliminary,
            2 => Self::PositiveCompletion,
            3 => Self::PositiveIntermediate,
            4 => Self::TransientNegative,
            5 => Self::PermanentNegative,
            _ => Self::Other,
        }
    }
}

/// Direction / kind of a file-transfer command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum TransferKind {
    /// `RETR` — download from server.
    Download,
    /// `STOR` — upload to server (overwriting).
    Upload,
    /// `APPE` — append upload to server.
    Append,
    /// `STOU` — unique-name upload.
    UploadUnique,
}

impl TransferKind {
    pub(crate) fn from_command(cmd: &FtpCommand) -> Option<Self> {
        Some(match cmd {
            FtpCommand::Retr => Self::Download,
            FtpCommand::Stor => Self::Upload,
            FtpCommand::Appe => Self::Append,
            FtpCommand::Stou => Self::UploadUnique,
            _ => return None,
        })
    }
}

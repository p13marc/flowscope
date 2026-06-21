//! Public SMB message types.

/// SMB wire-level dialect family detected from the
/// 4-byte protocol marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum SmbDialect {
    /// `\xFF SMB` — SMB1 / CIFS (legacy, downgrade-suspect).
    V1,
    /// `\xFE SMB` — SMB2 / SMB3 cleartext.
    V2,
    /// `\xFD SMB` — SMB3 encrypted transform header. The
    /// inner SMB2 message is AES-CCM or AES-GCM ciphertext;
    /// passive observers can't decode it.
    EncryptedTransform,
    /// `\xFC SMB` — SMB3 compression transform header.
    CompressedTransform,
}

impl SmbDialect {
    /// Lowercase slug for metric labels.
    pub fn as_str(&self) -> &'static str {
        match self {
            SmbDialect::V1 => "smb1",
            SmbDialect::V2 => "smb2",
            SmbDialect::EncryptedTransform => "smb3_encrypted",
            SmbDialect::CompressedTransform => "smb3_compressed",
        }
    }

    /// `true` for encrypted / compressed transform headers
    /// where we can't see the inner SMB2 message.
    pub fn is_opaque(&self) -> bool {
        matches!(
            self,
            SmbDialect::EncryptedTransform | SmbDialect::CompressedTransform
        )
    }
}

/// SMB2 command number — the high-byte / low-byte
/// 16-bit field at offset 12 of an SMB2 header.
///
/// Numbers track MS-SMB2 §2.2.1.2. SMB1 commands are
/// fundamentally different (single-byte enum); we
/// don't enumerate them — they surface as
/// [`Self::OtherSmb1`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum SmbCommand {
    Negotiate,
    SessionSetup,
    Logoff,
    TreeConnect,
    TreeDisconnect,
    Create,
    Close,
    Flush,
    Read,
    Write,
    Lock,
    Ioctl,
    Cancel,
    Echo,
    QueryDirectory,
    ChangeNotify,
    QueryInfo,
    SetInfo,
    OplockBreak,
    Other(u16),
    OtherSmb1(u8),
    NotApplicable,
}

impl SmbCommand {
    pub fn as_str(&self) -> &'static str {
        match self {
            SmbCommand::Negotiate => "negotiate",
            SmbCommand::SessionSetup => "session_setup",
            SmbCommand::Logoff => "logoff",
            SmbCommand::TreeConnect => "tree_connect",
            SmbCommand::TreeDisconnect => "tree_disconnect",
            SmbCommand::Create => "create",
            SmbCommand::Close => "close",
            SmbCommand::Flush => "flush",
            SmbCommand::Read => "read",
            SmbCommand::Write => "write",
            SmbCommand::Lock => "lock",
            SmbCommand::Ioctl => "ioctl",
            SmbCommand::Cancel => "cancel",
            SmbCommand::Echo => "echo",
            SmbCommand::QueryDirectory => "query_directory",
            SmbCommand::ChangeNotify => "change_notify",
            SmbCommand::QueryInfo => "query_info",
            SmbCommand::SetInfo => "set_info",
            SmbCommand::OplockBreak => "oplock_break",
            SmbCommand::Other(_) => "other",
            SmbCommand::OtherSmb1(_) => "smb1",
            SmbCommand::NotApplicable => "n/a",
        }
    }

    pub(crate) fn from_smb2(code: u16) -> Self {
        match code {
            0x0000 => SmbCommand::Negotiate,
            0x0001 => SmbCommand::SessionSetup,
            0x0002 => SmbCommand::Logoff,
            0x0003 => SmbCommand::TreeConnect,
            0x0004 => SmbCommand::TreeDisconnect,
            0x0005 => SmbCommand::Create,
            0x0006 => SmbCommand::Close,
            0x0007 => SmbCommand::Flush,
            0x0008 => SmbCommand::Read,
            0x0009 => SmbCommand::Write,
            0x000A => SmbCommand::Lock,
            0x000B => SmbCommand::Ioctl,
            0x000C => SmbCommand::Cancel,
            0x000D => SmbCommand::Echo,
            0x000E => SmbCommand::QueryDirectory,
            0x000F => SmbCommand::ChangeNotify,
            0x0010 => SmbCommand::QueryInfo,
            0x0011 => SmbCommand::SetInfo,
            0x0012 => SmbCommand::OplockBreak,
            other => SmbCommand::Other(other),
        }
    }
}

/// One decoded SMB message (the first message in a
/// NetBIOS Session Service PDU; chained / compound
/// follow-ons are not surfaced in M1).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct SmbMessage {
    pub dialect: SmbDialect,
    /// SMB2 command, or [`SmbCommand::OtherSmb1`] for SMB1
    /// messages, or [`SmbCommand::NotApplicable`] for
    /// encrypted / compressed transform headers (where we
    /// can't see the inner command).
    pub command: SmbCommand,
    /// SMB2 message ID. `None` for SMB1 / encrypted
    /// transform headers (no equivalent field).
    pub message_id: Option<u64>,
    /// SMB2 tree ID (the open file-share handle).
    pub tree_id: Option<u32>,
    /// SMB2 session ID.
    pub session_id: Option<u64>,
    /// `true` when the message is an encrypted-transform
    /// header (SMB3 AES-CCM/GCM). Payload is opaque.
    pub encrypted: bool,
    /// For SMB2 TREE_CONNECT request, the share path
    /// (e.g. `\\server\C$`). UTF-16LE on the wire,
    /// surfaced as UTF-8.
    pub tree_connect_path: Option<String>,
    /// `true` when `tree_connect_path` matches one of the
    /// classic admin shares (`C$`, `ADMIN$`, `IPC$`,
    /// `NETLOGON`, `SYSVOL`) — the lateral-movement
    /// signal.
    pub tree_connect_is_admin_share: bool,
}

impl SmbMessage {
    pub(crate) fn new(dialect: SmbDialect, command: SmbCommand) -> Self {
        Self {
            dialect,
            command,
            message_id: None,
            tree_id: None,
            session_id: None,
            encrypted: matches!(dialect, SmbDialect::EncryptedTransform),
            tree_connect_path: None,
            tree_connect_is_admin_share: false,
        }
    }
}

//! Public SMB message types.

use std::fmt;

/// 16-byte DCE-RPC interface UUID, the value advertised
/// in a BIND PDU's abstract-syntax field. Wraps the raw
/// bytes with a canonical hyphenated-hex [`std::fmt::Display`]
/// form and a [`Self::well_known_name`] reverse lookup
/// for the famous lateral-movement / cred-dump / DCSync
/// interfaces.
///
/// **Why a newtype:** `Vec<String>` of UUIDs invites
/// stringly-typed comparison + duplicate `format!`
/// allocations. The newtype carries the bytes (16) and
/// formats once when displayed.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DceRpcInterfaceUuid(pub [u8; 16]);

impl DceRpcInterfaceUuid {
    /// Construct from raw bytes as they appear in the
    /// abstract-syntax field of an MS-RPCE bind request.
    /// Per MS-DTYP the first three fields are
    /// little-endian, the last two big-endian; this
    /// struct preserves the raw byte order — formatting
    /// reorders for display.
    #[inline]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// Raw 16 bytes (MS-DTYP wire order).
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Reverse lookup against the curated table of
    /// well-known lateral-movement / cred-dump UUIDs.
    /// Returns the IDL interface name (e.g. `"svcctl"`,
    /// `"lsarpc"`, `"drsuapi"`) or `None` for unknown
    /// interfaces.
    ///
    /// Source: Microsoft MS-* spec interface UUIDs.
    pub fn well_known_name(&self) -> Option<&'static str> {
        match self.canonical_string().as_str() {
            "367abb81-9844-35f1-ad32-98f038001003" => Some("svcctl"), // MS-SCMR
            "338cd001-2244-31f1-aaaa-900038001003" => Some("winreg"), // MS-RRP
            "12345778-1234-abcd-ef00-0123456789ab" => Some("lsarpc"), // MS-LSAD/LSAT
            "12345778-1234-abcd-ef00-0123456789ac" => Some("samr"),   // MS-SAMR
            "12345678-1234-abcd-ef00-01234567cffb" => Some("netlogon"), // MS-NRPC
            "12345678-1234-abcd-ef00-0123456789ab" => Some("spoolss"), // MS-RPRN
            "1ff70682-0a51-30e8-076d-740be8cee98b" => Some("atsvc"),  // MS-TSCH
            "82273fdc-e32a-18c3-3f78-827929dc23ea" => Some("eventlog"), // MS-EVEN
            "6bffd098-a112-3610-9833-46c3f87e345a" => Some("wkssvc"), // MS-WKST
            "4b324fc8-1670-01d3-1278-5a47bf6ee188" => Some("srvsvc"), // MS-SRVS
            "e3514235-4b06-11d1-ab04-00c04fc2dcd2" => Some("drsuapi"), // MS-DRSR (DCSync)
            _ => None,
        }
    }

    /// Canonical hyphenated-hex form per MS-DTYP — first
    /// three fields little-endian, last two big-endian.
    /// Same format Wireshark / Zeek emit.
    pub fn canonical_string(&self) -> String {
        let b = &self.0;
        format!(
            "{:02x}{:02x}{:02x}{:02x}-\
             {:02x}{:02x}-\
             {:02x}{:02x}-\
             {:02x}{:02x}-\
             {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[3],
            b[2],
            b[1],
            b[0],
            b[5],
            b[4],
            b[7],
            b[6],
            b[8],
            b[9],
            b[10],
            b[11],
            b[12],
            b[13],
            b[14],
            b[15],
        )
    }
}

impl fmt::Display for DceRpcInterfaceUuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.canonical_string())
    }
}

impl fmt::Debug for DceRpcInterfaceUuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DceRpcInterfaceUuid({})", self.canonical_string())
    }
}

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
    /// For SMB2 CREATE requests, the requested file or
    /// pipe path (UTF-16LE on the wire, decoded to UTF-8).
    /// For named-pipe opens this is the pipe name
    /// (`svcctl`, `lsarpc`, `samr`, `spoolss`, ...).
    /// **M2 (issue #12).**
    pub create_path: Option<String>,
    /// `true` when `create_path` matches a well-known
    /// named-pipe endpoint historically abused for
    /// lateral movement / credential dumping
    /// (`svcctl` → service creation, `lsarpc` / `samr`
    /// → cred-dump, `spoolss` → PrintNightmare, etc.).
    /// **M2 (issue #12).**
    pub create_is_admin_named_pipe: bool,
    /// For SMB2 READ requests, the requested byte
    /// length. Large reads concentrated on a single file
    /// suggest data exfiltration. **M2 (issue #12).**
    pub read_length: Option<u32>,
    /// For SMB2 READ requests, the file offset.
    /// **M2 (issue #12).**
    pub read_offset: Option<u64>,
    /// For SMB2 WRITE requests, the byte length.
    /// **M2 (issue #12).**
    pub write_length: Option<u32>,
    /// For SMB2 WRITE requests, the file offset.
    /// **M2 (issue #12).**
    pub write_offset: Option<u64>,

    /// For SMB2 SESSION_SETUP requests that carry an
    /// NTLMSSP authentication blob (NTLM Type 3
    /// AUTHENTICATE), the decoded identity tuple.
    /// `None` for Kerberos / Negotiate auth.
    /// **M3 (issue #12).**
    pub ntlm_auth: Option<NtlmAuth>,

    /// For SMB2 WRITE requests whose payload is a
    /// DCE-RPC PDU, the parsed bind information when the
    /// PDU type is BIND (0x0B). One entry per offered
    /// abstract-syntax UUID. Use
    /// [`DceRpcInterfaceUuid::well_known_name`] for the
    /// curated lateral-movement-interface lookup.
    /// **M3 (issue #12).**
    pub dcerpc_bind_uuids: Vec<DceRpcInterfaceUuid>,
}

/// Identity tuple extracted from an NTLM Type 3
/// AUTHENTICATE message. Used for pass-the-hash detection
/// (workstation field anomalies, mismatched-domain auth)
/// and identity-correlation.
///
/// Per MS-NLMP §2.2.1.3. Strings are decoded as UTF-16LE
/// when the NTLMSSP NEGOTIATE_UNICODE flag is set
/// (commonplace) or as Windows-1252 / ASCII when OEM.
/// We default to assuming Unicode; the surface is
/// best-effort and consumers should not rely on
/// byte-perfect domain casing.
///
/// Issue #12 M3.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct NtlmAuth {
    pub domain: Option<String>,
    pub username: Option<String>,
    pub workstation: Option<String>,
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
            create_path: None,
            create_is_admin_named_pipe: false,
            read_length: None,
            read_offset: None,
            write_length: None,
            write_offset: None,
            ntlm_auth: None,
            dcerpc_bind_uuids: Vec::new(),
        }
    }
}

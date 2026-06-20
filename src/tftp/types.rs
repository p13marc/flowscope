//! TFTP message types.

/// One parsed TFTP packet. Field semantics depend on
/// [`TftpMessage::opcode`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct TftpMessage {
    /// The 2-byte opcode at the start of every TFTP packet.
    pub opcode: TftpOpcode,
    /// RRQ / WRQ: requested file name. Always `None` for the
    /// other opcodes.
    pub filename: Option<String>,
    /// RRQ / WRQ: transfer mode (`netascii` / `octet` / `mail`).
    /// Always `None` for the other opcodes.
    pub mode: Option<TftpMode>,
    /// DATA / ACK: block number (1-based).
    pub block: Option<u16>,
    /// DATA: payload byte length. We don't surface the bytes
    /// (too large), just the size — useful for transfer-volume
    /// counting.
    pub data_len: Option<usize>,
    /// ERROR: error code (RFC 1350 §5).
    pub error_code: Option<TftpErrorCode>,
    /// ERROR: human-readable message.
    pub error_message: Option<String>,
}

/// TFTP opcode (RFC 1350 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "kind", content = "value", rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum TftpOpcode {
    /// `1` — Read Request.
    ReadRequest,
    /// `2` — Write Request.
    WriteRequest,
    /// `3` — DATA block.
    Data,
    /// `4` — DATA acknowledgement.
    Ack,
    /// `5` — Error.
    Error,
    /// Any other opcode value.
    Other(u16),
}

impl TftpOpcode {
    /// Stable slug for metric labels.
    pub fn as_str(self) -> &'static str {
        match self {
            TftpOpcode::ReadRequest => "rrq",
            TftpOpcode::WriteRequest => "wrq",
            TftpOpcode::Data => "data",
            TftpOpcode::Ack => "ack",
            TftpOpcode::Error => "error",
            TftpOpcode::Other(_) => "other",
        }
    }

    /// Decode the 2-byte opcode field.
    pub fn from_raw(v: u16) -> Self {
        match v {
            1 => TftpOpcode::ReadRequest,
            2 => TftpOpcode::WriteRequest,
            3 => TftpOpcode::Data,
            4 => TftpOpcode::Ack,
            5 => TftpOpcode::Error,
            other => TftpOpcode::Other(other),
        }
    }

    /// IANA numeric value (`1..=5` for known opcodes).
    pub fn as_u16(self) -> u16 {
        match self {
            TftpOpcode::ReadRequest => 1,
            TftpOpcode::WriteRequest => 2,
            TftpOpcode::Data => 3,
            TftpOpcode::Ack => 4,
            TftpOpcode::Error => 5,
            TftpOpcode::Other(n) => n,
        }
    }
}

/// TFTP transfer mode (RFC 1350 §1 + RFC 2347 options).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "kind", rename_all = "snake_case"))]
#[non_exhaustive]
pub enum TftpMode {
    /// `"netascii"` — text mode.
    NetAscii,
    /// `"octet"` — binary mode (the common case).
    Octet,
    /// `"mail"` — historical, deprecated.
    Mail,
    /// Anything else (RFC 2347 option-extension modes etc.).
    Other,
}

impl TftpMode {
    /// Parse the mode string case-insensitively per RFC 1350 §1.
    pub fn parse_str(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "netascii" => TftpMode::NetAscii,
            "octet" => TftpMode::Octet,
            "mail" => TftpMode::Mail,
            _ => TftpMode::Other,
        }
    }
}

/// TFTP error code (RFC 1350 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "kind", content = "value", rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum TftpErrorCode {
    /// `0` — not defined; see error string.
    NotDefined,
    /// `1` — File not found.
    FileNotFound,
    /// `2` — Access violation. Common on `RRQ`-prevention.
    AccessViolation,
    /// `3` — Disk full or allocation exceeded.
    DiskFull,
    /// `4` — Illegal TFTP operation.
    IllegalOperation,
    /// `5` — Unknown transfer ID.
    UnknownTransferId,
    /// `6` — File already exists. Common on `WRQ`-collision.
    FileAlreadyExists,
    /// `7` — No such user.
    NoSuchUser,
    /// Anything else.
    Other(u16),
}

impl TftpErrorCode {
    /// Decode the 2-byte field.
    pub fn from_raw(v: u16) -> Self {
        match v {
            0 => TftpErrorCode::NotDefined,
            1 => TftpErrorCode::FileNotFound,
            2 => TftpErrorCode::AccessViolation,
            3 => TftpErrorCode::DiskFull,
            4 => TftpErrorCode::IllegalOperation,
            5 => TftpErrorCode::UnknownTransferId,
            6 => TftpErrorCode::FileAlreadyExists,
            7 => TftpErrorCode::NoSuchUser,
            other => TftpErrorCode::Other(other),
        }
    }

    /// IANA numeric value.
    pub fn as_u16(self) -> u16 {
        match self {
            TftpErrorCode::NotDefined => 0,
            TftpErrorCode::FileNotFound => 1,
            TftpErrorCode::AccessViolation => 2,
            TftpErrorCode::DiskFull => 3,
            TftpErrorCode::IllegalOperation => 4,
            TftpErrorCode::UnknownTransferId => 5,
            TftpErrorCode::FileAlreadyExists => 6,
            TftpErrorCode::NoSuchUser => 7,
            TftpErrorCode::Other(n) => n,
        }
    }
}

impl TftpMessage {
    /// `true` when this is a read or write request for a
    /// **device-config-shaped filename** — heuristic match for
    /// the strings Cisco / Juniper / Arista boxes use:
    /// `running-config`, `startup-config`, `confg`, `.cfg`
    /// suffix, `.conf` suffix. Operationally a useful
    /// config-theft IOC.
    pub fn is_device_config_transfer(&self) -> bool {
        let Some(name) = self.filename.as_deref() else {
            return false;
        };
        if !matches!(
            self.opcode,
            TftpOpcode::ReadRequest | TftpOpcode::WriteRequest
        ) {
            return false;
        }
        let lower = name.to_ascii_lowercase();
        lower.contains("running-config")
            || lower.contains("startup-config")
            || lower == "confg"
            || lower.ends_with(".cfg")
            || lower.ends_with(".conf")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_round_trip() {
        for n in 1..=5u16 {
            assert_eq!(TftpOpcode::from_raw(n).as_u16(), n);
        }
        assert_eq!(TftpOpcode::from_raw(99), TftpOpcode::Other(99));
        assert_eq!(TftpOpcode::Other(99).as_u16(), 99);
    }

    #[test]
    fn opcode_slugs_locked() {
        assert_eq!(TftpOpcode::ReadRequest.as_str(), "rrq");
        assert_eq!(TftpOpcode::WriteRequest.as_str(), "wrq");
        assert_eq!(TftpOpcode::Data.as_str(), "data");
        assert_eq!(TftpOpcode::Ack.as_str(), "ack");
        assert_eq!(TftpOpcode::Error.as_str(), "error");
    }

    #[test]
    fn mode_case_insensitive() {
        assert_eq!(TftpMode::parse_str("octet"), TftpMode::Octet);
        assert_eq!(TftpMode::parse_str("OCTET"), TftpMode::Octet);
        assert_eq!(TftpMode::parse_str("NetAscii"), TftpMode::NetAscii);
        assert_eq!(TftpMode::parse_str("mail"), TftpMode::Mail);
        assert_eq!(TftpMode::parse_str("anything-else"), TftpMode::Other);
    }

    #[test]
    fn error_code_round_trip() {
        for n in 0..=7u16 {
            assert_eq!(TftpErrorCode::from_raw(n).as_u16(), n);
        }
        assert_eq!(TftpErrorCode::from_raw(50), TftpErrorCode::Other(50));
    }

    fn req(op: TftpOpcode, file: &str) -> TftpMessage {
        TftpMessage {
            opcode: op,
            filename: Some(file.into()),
            mode: Some(TftpMode::Octet),
            block: None,
            data_len: None,
            error_code: None,
            error_message: None,
        }
    }

    #[test]
    fn device_config_transfer_detector_fires_on_cisco_shapes() {
        assert!(req(TftpOpcode::ReadRequest, "running-config").is_device_config_transfer());
        assert!(req(TftpOpcode::WriteRequest, "startup-config").is_device_config_transfer());
        assert!(req(TftpOpcode::ReadRequest, "router1.cfg").is_device_config_transfer());
        assert!(req(TftpOpcode::WriteRequest, "site.conf").is_device_config_transfer());
        assert!(req(TftpOpcode::ReadRequest, "confg").is_device_config_transfer());
    }

    #[test]
    fn device_config_transfer_detector_misses_non_config_files() {
        assert!(!req(TftpOpcode::ReadRequest, "pxelinux.0").is_device_config_transfer());
        assert!(!req(TftpOpcode::ReadRequest, "vmlinuz").is_device_config_transfer());
        assert!(!req(TftpOpcode::ReadRequest, "firmware.bin").is_device_config_transfer());
    }

    #[test]
    fn device_config_transfer_only_for_rrq_or_wrq() {
        let mut m = req(TftpOpcode::ReadRequest, "running-config");
        m.opcode = TftpOpcode::Data;
        assert!(!m.is_device_config_transfer());
        m.opcode = TftpOpcode::Ack;
        assert!(!m.is_device_config_transfer());
    }
}

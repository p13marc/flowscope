//! Public types for the DNP3 parser.

use bitflags::bitflags;

/// One parsed DNP3 data-link frame.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct DnpMessage {
    /// Source address (1-65519 standard range; 0xFFFF
    /// broadcast).
    pub src_addr: u16,
    /// Destination address.
    pub dst_addr: u16,
    /// Link function (the low 4 bits of the control byte).
    pub link_function: DnpLinkFunctionKind,
    /// DIR bit lift — direction of travel relative to the
    /// outstation.
    pub link_dir: DnpLinkDirection,
    /// PRM bit lift — primary-station vs secondary-station
    /// message.
    pub link_prm: DnpLinkRole,
    /// Application-layer payload, when the first user-data
    /// block contains a parsable application frame.
    pub application: Option<DnpApplication>,
    /// Whether the data-link **header CRC** (bytes 8..10,
    /// covering the 8-byte link header) validated against the
    /// DNP3 CRC-16 (poly 0x3D65). A `false` here means the frame
    /// is corrupt or not really DNP3 — don't trust the addresses
    /// / function blindly. Issue #80.
    ///
    /// Only the fixed-size header CRC is checked; per-block
    /// user-data CRCs are intentionally not verified (the
    /// length-driven block walk is the Suricata-CVE-prone part
    /// and stays out of scope).
    pub header_crc_valid: bool,
}

/// IEEE 1815-2012 §9.1.2.1 DIR bit. The bit is `1` when sent
/// from a master toward an outstation; `0` in the reverse
/// direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum DnpLinkDirection {
    ToOutstation,
    ToMaster,
}

impl DnpLinkDirection {
    pub fn from_bit(bit: bool) -> Self {
        if bit {
            Self::ToOutstation
        } else {
            Self::ToMaster
        }
    }
    pub fn as_bit(&self) -> bool {
        matches!(self, Self::ToOutstation)
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ToOutstation => "to_outstation",
            Self::ToMaster => "to_master",
        }
    }
}

impl std::fmt::Display for DnpLinkDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// IEEE 1815-2012 §9.1.2.1 PRM bit. The bit is `1` for
/// primary-station messages (the initiating side); `0` for
/// secondary-station (responder) messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum DnpLinkRole {
    Primary,
    Secondary,
}

impl DnpLinkRole {
    pub fn from_bit(bit: bool) -> Self {
        if bit { Self::Primary } else { Self::Secondary }
    }
    pub fn as_bit(&self) -> bool {
        matches!(self, Self::Primary)
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Secondary => "secondary",
        }
    }
}

impl std::fmt::Display for DnpLinkRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// IEEE 1815-2012 §9.1.2.1 data-link function vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum DnpLinkFunctionKind {
    /// Primary, function 0 — Reset of Remote Link.
    ResetLinkStates,
    /// Primary, function 3 — User Data (the common case).
    UserData,
    /// Primary, function 4 — Unconfirmed User Data.
    UnconfirmedUserData,
    /// Primary, function 9 — Request Link Status.
    RequestLinkStatus,
    /// Secondary, function 0 — ACK of primary message.
    Ack,
    /// Secondary, function 1 — NACK of primary message.
    Nack,
    /// Secondary, function 11 — Status of Link.
    LinkStatus,
    /// Secondary, function 15 — Not Supported.
    NotSupported,
    Other(u8),
}

impl DnpLinkFunctionKind {
    pub(crate) fn from_raw(control: u8) -> Self {
        let prm = (control & 0x40) != 0;
        let fc = control & 0x0F;
        match (prm, fc) {
            (true, 0) => Self::ResetLinkStates,
            (true, 3) => Self::UserData,
            (true, 4) => Self::UnconfirmedUserData,
            (true, 9) => Self::RequestLinkStatus,
            (false, 0) => Self::Ack,
            (false, 1) => Self::Nack,
            (false, 11) => Self::LinkStatus,
            (false, 15) => Self::NotSupported,
            (_, n) => Self::Other(n),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ResetLinkStates => "reset_link_states",
            Self::UserData => "user_data",
            Self::UnconfirmedUserData => "unconfirmed_user_data",
            Self::RequestLinkStatus => "request_link_status",
            Self::Ack => "ack",
            Self::Nack => "nack",
            Self::LinkStatus => "link_status",
            Self::NotSupported => "not_supported",
            Self::Other(_) => "other",
        }
    }
}

/// Application-layer payload from the first link
/// user-data block.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct DnpApplication {
    /// Application sequence number (low 4 bits of AC).
    pub sequence: u8,
    /// FIR bit — first fragment.
    pub fir: bool,
    /// FIN bit — final fragment.
    pub fin: bool,
    /// CON bit — confirm requested.
    pub con: bool,
    /// UNS bit — unsolicited.
    pub uns: bool,
    /// Decoded function code (the common ones; `Other`
    /// preserves the raw byte).
    pub function: DnpAppFunctionKind,
    /// Raw function code byte (preserved for debug /
    /// metrics).
    pub raw_function_code: u8,
    /// Internal Indications — only populated on response
    /// frames (function codes 129/130/131).
    pub iin: Option<DnpInternalIndications>,
}

/// Application-layer function codes per IEEE 1815-2012 §10.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum DnpAppFunctionKind {
    Confirm,
    Read,
    Write,
    Select,
    Operate,
    DirectOperate,
    DirectOperateNoAck,
    ImmediateFreeze,
    ImmediateFreezeNoAck,
    FreezeClear,
    FreezeClearNoAck,
    FreezeAtTime,
    FreezeAtTimeNoAck,
    ColdRestart,
    WarmRestart,
    InitializeData,
    InitializeApplication,
    StartApplication,
    StopApplication,
    SaveConfiguration,
    EnableUnsolicited,
    DisableUnsolicited,
    AssignClass,
    DelayMeasure,
    RecordCurrentTime,
    OpenFile,
    CloseFile,
    DeleteFile,
    GetFileInfo,
    AuthenticateFile,
    AbortFile,
    ActivateConfig,
    AuthenticateRequest,
    AuthenticateError,
    Response,
    UnsolicitedResponse,
    AuthenticateResponse,
    Other(u8),
}

impl DnpAppFunctionKind {
    pub(crate) fn from_raw(code: u8) -> Self {
        match code {
            0 => Self::Confirm,
            1 => Self::Read,
            2 => Self::Write,
            3 => Self::Select,
            4 => Self::Operate,
            5 => Self::DirectOperate,
            6 => Self::DirectOperateNoAck,
            7 => Self::ImmediateFreeze,
            8 => Self::ImmediateFreezeNoAck,
            9 => Self::FreezeClear,
            10 => Self::FreezeClearNoAck,
            11 => Self::FreezeAtTime,
            12 => Self::FreezeAtTimeNoAck,
            13 => Self::ColdRestart,
            14 => Self::WarmRestart,
            15 => Self::InitializeData,
            16 => Self::InitializeApplication,
            17 => Self::StartApplication,
            18 => Self::StopApplication,
            19 => Self::SaveConfiguration,
            20 => Self::EnableUnsolicited,
            21 => Self::DisableUnsolicited,
            22 => Self::AssignClass,
            23 => Self::DelayMeasure,
            24 => Self::RecordCurrentTime,
            25 => Self::OpenFile,
            26 => Self::CloseFile,
            27 => Self::DeleteFile,
            28 => Self::GetFileInfo,
            29 => Self::AuthenticateFile,
            30 => Self::AbortFile,
            31 => Self::ActivateConfig,
            32 => Self::AuthenticateRequest,
            33 => Self::AuthenticateError,
            129 => Self::Response,
            130 => Self::UnsolicitedResponse,
            131 => Self::AuthenticateResponse,
            n => Self::Other(n),
        }
    }

    /// `true` for response function codes (129/130/131) —
    /// the ones that carry Internal Indications.
    pub fn is_response(&self) -> bool {
        matches!(
            self,
            Self::Response | Self::UnsolicitedResponse | Self::AuthenticateResponse
        )
    }
}

bitflags! {
    /// IEEE 1815-2012 §4.4.4 Internal Indications bitmap.
    /// Two octets, surfaced on the wire as `IIN1 | IIN2`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct DnpInternalIndications: u16 {
        // IIN1
        const BROADCAST              = 1 << 0;
        const CLASS_1_EVENTS         = 1 << 1;
        const CLASS_2_EVENTS         = 1 << 2;
        const CLASS_3_EVENTS         = 1 << 3;
        const TIME_SYNC_REQUIRED     = 1 << 4;
        const LOCAL_CONTROL          = 1 << 5;
        const DEVICE_TROUBLE         = 1 << 6;
        const DEVICE_RESTART         = 1 << 7;
        // IIN2
        const NO_FUNCTION_CODE       = 1 << 8;
        const OBJECT_UNKNOWN         = 1 << 9;
        const PARAMETER_ERROR        = 1 << 10;
        const EVENT_BUFFER_OVERFLOW  = 1 << 11;
        const ALREADY_EXECUTING      = 1 << 12;
        const CONFIG_CORRUPT         = 1 << 13;
        // Bits 14 + 15 reserved per the spec.
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for DnpInternalIndications {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        s.serialize_u16(self.bits())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for DnpInternalIndications {
    fn deserialize<D>(d: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bits = <u16 as serde::Deserialize>::deserialize(d)?;
        Ok(DnpInternalIndications::from_bits_truncate(bits))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_direction_round_trip() {
        for bit in [true, false] {
            assert_eq!(DnpLinkDirection::from_bit(bit).as_bit(), bit);
        }
        assert_eq!(
            DnpLinkDirection::from_bit(true),
            DnpLinkDirection::ToOutstation
        );
        assert_eq!(
            DnpLinkDirection::from_bit(false),
            DnpLinkDirection::ToMaster
        );
    }

    #[test]
    fn link_role_round_trip() {
        for bit in [true, false] {
            assert_eq!(DnpLinkRole::from_bit(bit).as_bit(), bit);
        }
        assert_eq!(DnpLinkRole::from_bit(true), DnpLinkRole::Primary);
        assert_eq!(DnpLinkRole::from_bit(false), DnpLinkRole::Secondary);
    }

    #[test]
    fn slugs_are_stable() {
        assert_eq!(DnpLinkDirection::ToOutstation.as_str(), "to_outstation");
        assert_eq!(DnpLinkRole::Secondary.as_str(), "secondary");
    }
}

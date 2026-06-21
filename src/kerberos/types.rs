//! Public Kerberos message types.

use std::fmt;

/// Kerberos encryption type (`etype` value), per
/// RFC 3961 + RFC 4757. The four named variants are the
/// ones operators alert on; everything else falls into
/// [`Self::Other`] preserving the raw IANA value.
///
/// **Why a typed enum:** the security-relevant question
/// "is this Kerberoasting-prone?" reduces to
/// `etype.is_rc4()` instead of `etype == 23`. The
/// downgrade-to-weak-crypto pattern (MITRE T1558.003)
/// becomes self-documenting at the call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum KerberosEtype {
    /// `des-cbc-crc` — DES, RFC 3961.
    DesCbcCrc,
    /// `des-cbc-md4` — DES, RFC 3961.
    DesCbcMd4,
    /// `des-cbc-md5` — DES, RFC 3961.
    DesCbcMd5,
    /// `des3-cbc-sha1-kd` — 3DES, RFC 3961.
    Des3CbcSha1Kd,
    /// `aes128-cts-hmac-sha1-96` — AES-128, RFC 3962.
    Aes128CtsHmacSha1,
    /// `aes256-cts-hmac-sha1-96` — AES-256, RFC 3962.
    Aes256CtsHmacSha1,
    /// `aes128-cts-hmac-sha256-128` — AES-128, RFC 8009.
    Aes128CtsHmacSha256,
    /// `aes256-cts-hmac-sha384-192` — AES-256, RFC 8009.
    Aes256CtsHmacSha384,
    /// `rc4-hmac` — RC4, RFC 4757. **Weak**. TGS-REQ
    /// listing this is the classic Kerberoasting
    /// downgrade signal (MITRE T1558.003).
    Rc4Hmac,
    /// `rc4-hmac-exp` — export-grade RC4. **Weak**.
    Rc4HmacExp,
    /// Any other / future etype. The raw IANA number
    /// stays in the variant for forensic preservation.
    Other(i32),
}

impl KerberosEtype {
    /// Construct from the on-wire i32.
    #[inline]
    pub fn from_raw(value: i32) -> Self {
        match value {
            1 => Self::DesCbcCrc,
            2 => Self::DesCbcMd4,
            3 => Self::DesCbcMd5,
            16 => Self::Des3CbcSha1Kd,
            17 => Self::Aes128CtsHmacSha1,
            18 => Self::Aes256CtsHmacSha1,
            19 => Self::Aes128CtsHmacSha256,
            20 => Self::Aes256CtsHmacSha384,
            23 => Self::Rc4Hmac,
            24 => Self::Rc4HmacExp,
            other => Self::Other(other),
        }
    }

    /// IANA `etype` number (on-wire form).
    #[inline]
    pub fn as_raw(&self) -> i32 {
        match self {
            Self::DesCbcCrc => 1,
            Self::DesCbcMd4 => 2,
            Self::DesCbcMd5 => 3,
            Self::Des3CbcSha1Kd => 16,
            Self::Aes128CtsHmacSha1 => 17,
            Self::Aes256CtsHmacSha1 => 18,
            Self::Aes128CtsHmacSha256 => 19,
            Self::Aes256CtsHmacSha384 => 20,
            Self::Rc4Hmac => 23,
            Self::Rc4HmacExp => 24,
            Self::Other(v) => *v,
        }
    }

    /// `true` for AES-family etypes (modern, RFC 3962 +
    /// RFC 8009).
    #[inline]
    pub fn is_aes(&self) -> bool {
        matches!(
            self,
            Self::Aes128CtsHmacSha1
                | Self::Aes256CtsHmacSha1
                | Self::Aes128CtsHmacSha256
                | Self::Aes256CtsHmacSha384
        )
    }

    /// `true` for RC4-family etypes — the Kerberoasting
    /// target.
    #[inline]
    pub fn is_rc4(&self) -> bool {
        matches!(self, Self::Rc4Hmac | Self::Rc4HmacExp)
    }

    /// `true` for DES / 3DES — long-deprecated.
    #[inline]
    pub fn is_des(&self) -> bool {
        matches!(
            self,
            Self::DesCbcCrc | Self::DesCbcMd4 | Self::DesCbcMd5 | Self::Des3CbcSha1Kd
        )
    }

    /// `true` for any weak etype (RC4 + DES). The single
    /// predicate operators alert on for downgrade
    /// detection.
    #[inline]
    pub fn is_weak(&self) -> bool {
        self.is_rc4() || self.is_des()
    }
}

impl From<i32> for KerberosEtype {
    #[inline]
    fn from(value: i32) -> Self {
        Self::from_raw(value)
    }
}

impl From<KerberosEtype> for i32 {
    #[inline]
    fn from(value: KerberosEtype) -> Self {
        value.as_raw()
    }
}

impl fmt::Display for KerberosEtype {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::DesCbcCrc => "des-cbc-crc",
            Self::DesCbcMd4 => "des-cbc-md4",
            Self::DesCbcMd5 => "des-cbc-md5",
            Self::Des3CbcSha1Kd => "des3-cbc-sha1-kd",
            Self::Aes128CtsHmacSha1 => "aes128-cts-hmac-sha1-96",
            Self::Aes256CtsHmacSha1 => "aes256-cts-hmac-sha1-96",
            Self::Aes128CtsHmacSha256 => "aes128-cts-hmac-sha256-128",
            Self::Aes256CtsHmacSha384 => "aes256-cts-hmac-sha384-192",
            Self::Rc4Hmac => "rc4-hmac",
            Self::Rc4HmacExp => "rc4-hmac-exp",
            Self::Other(v) => return write!(f, "etype-{v}"),
        };
        f.write_str(s)
    }
}

/// Classification of a Kerberos message by its
/// APPLICATION-tagged outer type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum KerberosMessageKind {
    AsReq,
    AsRep,
    TgsReq,
    TgsRep,
    ApReq,
    ApRep,
    KrbError,
    Unknown(u8),
}

impl KerberosMessageKind {
    /// Stable lowercase slug for metric labels / log fields.
    pub fn as_str(&self) -> &'static str {
        match self {
            KerberosMessageKind::AsReq => "as_req",
            KerberosMessageKind::AsRep => "as_rep",
            KerberosMessageKind::TgsReq => "tgs_req",
            KerberosMessageKind::TgsRep => "tgs_rep",
            KerberosMessageKind::ApReq => "ap_req",
            KerberosMessageKind::ApRep => "ap_rep",
            KerberosMessageKind::KrbError => "krb_error",
            KerberosMessageKind::Unknown(_) => "unknown",
        }
    }
}

/// One decoded Kerberos message. Intentionally narrow —
/// metadata only, no decrypted ticket payload.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct KerberosMessage {
    pub kind: KerberosMessageKind,
    pub pvno: u32,
    pub realm: String,
    pub cname: Option<String>,
    pub sname: Option<String>,
    /// List of [`KerberosEtype`]s the client requested.
    /// Empty for replies / errors. The
    /// [`Self::kerberoast_suspect`] boolean is set when
    /// this list contains an [`KerberosEtype::is_rc4`]
    /// entry on a TGS-REQ.
    pub etypes: Vec<KerberosEtype>,
    /// PA-DATA type numbers observed in the message.
    pub padata_types: Vec<i32>,
    /// `true` when the message is a TGS-REQ that lists
    /// RC4-HMAC (etype 23) — the classic Kerberoasting
    /// downgrade signal.
    pub kerberoast_suspect: bool,
    /// KRB-ERROR error code (e.g. KDC_ERR_PREAUTH_REQUIRED
    /// = 25). `None` for non-error messages.
    pub error_code: Option<i32>,
}

impl KerberosMessage {
    /// Construct an all-empty message of the given kind.
    pub(crate) fn new(kind: KerberosMessageKind, pvno: u32, realm: String) -> Self {
        Self {
            kind,
            pvno,
            realm,
            cname: None,
            sname: None,
            etypes: Vec::new(),
            padata_types: Vec::new(),
            kerberoast_suspect: false,
            error_code: None,
        }
    }
}

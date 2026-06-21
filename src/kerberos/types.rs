//! Public Kerberos message types.

/// Classification of a Kerberos message by its
/// APPLICATION-tagged outer type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    /// List of `EncryptionType` numbers requested. Empty for
    /// replies / errors. RC4-HMAC = 23 (Kerberoast); AES =
    /// 17 / 18; DES = 1 / 3.
    pub etypes: Vec<i32>,
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

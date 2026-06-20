//! SSH message types emitted by [`super::SshParser`].

/// A decoded protocol event from the SSH handshake.
///
/// Issue #7 (0.18).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum SshMessage {
    /// Version banner — `"SSH-2.0-..."` line per RFC 4253 §4.2.
    /// One per side per connection; the payload is the full
    /// banner line minus the `\r\n` terminator (e.g.
    /// `"SSH-2.0-OpenSSH_9.6"`).
    Banner { banner: String },
    /// Decoded `SSH_MSG_KEXINIT` (msg byte 20) with the
    /// algorithm name-lists and the side-appropriate HASSH
    /// fingerprint.
    KexInit(Box<SshKexInit>),
    /// `SSH_MSG_NEWKEYS` (msg byte 21) — both sides exchange
    /// it to switch to encrypted records. The parser stops
    /// emitting events after seeing the corresponding side's
    /// NEWKEYS; everything past it is encrypted.
    Encrypted,
}

/// Decoded `SSH_MSG_KEXINIT` payload — algorithm-negotiation
/// name-lists from one side of the handshake.
///
/// The HASSH fingerprint (Salesforce spec) is computed from
/// the side-appropriate subset of these lists:
///
/// - Client (`HASSH`): `kex;c2s_enc;c2s_mac;c2s_compression`
/// - Server (`HASSHServer`): `kex;s2c_enc;s2c_mac;s2c_compression`
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct SshKexInit {
    /// `true` for the client's KEXINIT, `false` for the server's.
    pub from_client: bool,
    /// `kex_algorithms` name-list.
    pub kex_algorithms: Vec<String>,
    /// `server_host_key_algorithms` name-list.
    pub server_host_key_algorithms: Vec<String>,
    /// `encryption_algorithms_client_to_server`.
    pub encryption_c2s: Vec<String>,
    /// `encryption_algorithms_server_to_client`.
    pub encryption_s2c: Vec<String>,
    /// `mac_algorithms_client_to_server`.
    pub mac_c2s: Vec<String>,
    /// `mac_algorithms_server_to_client`.
    pub mac_s2c: Vec<String>,
    /// `compression_algorithms_client_to_server`.
    pub compression_c2s: Vec<String>,
    /// `compression_algorithms_server_to_client`.
    pub compression_s2c: Vec<String>,
    /// `languages_client_to_server`. Typically empty.
    pub languages_c2s: Vec<String>,
    /// `languages_server_to_client`. Typically empty.
    pub languages_s2c: Vec<String>,
    /// `first_kex_packet_follows` flag — a guess-driven
    /// optimisation; not part of HASSH.
    pub first_kex_packet_follows: bool,
    /// HASSH-style fingerprint. For `from_client = true` this
    /// is the standard HASSH (client). For `from_client =
    /// false` it's HASSHServer. Both are lowercase-hex MD5
    /// over the side-appropriate join
    /// `kex;enc;mac;compression`.
    pub hassh: String,
}

use bytes::Bytes;

/// Parsed TLS ClientHello — what the client offered to the server.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct TlsClientHello {
    /// Record-layer protocol version (the version on the outer
    /// record, often `Tls1_0` for TLS 1.3 ClientHellos for
    /// middlebox-compat reasons).
    pub record_version: TlsVersion,
    /// `legacy_version` field on the ClientHello message itself.
    pub legacy_version: TlsVersion,
    /// 32-byte client random (Unix timestamp prefix on TLS 1.0–1.2;
    /// fully random on TLS 1.3).
    pub random: [u8; 32],
    /// Session ID. TLS 1.3 fakes this for compat; in TLS 1.2 a
    /// non-empty value indicates an attempted session resumption.
    pub session_id: Bytes,
    /// Offered cipher suites in order.
    pub cipher_suites: Vec<u16>,
    /// Compression methods offered. Plan 120: was `Vec<u8>` in 0.10.
    pub compression: Bytes,
    /// Server name (SNI) extension value, if present.
    pub sni: Option<String>,
    /// Negotiated ALPN protocols offered by the client.
    pub alpn: Vec<String>,
    /// `supported_versions` extension (TLS 1.3+).
    pub supported_versions: Vec<TlsVersion>,
    /// `supported_groups` (key-exchange named curves).
    pub supported_groups: Vec<u16>,
    /// Extension types in the order they appeared. Useful for
    /// fingerprinting (JA3, JA4).
    pub extension_types: Vec<u16>,

    // ── ECH (Encrypted Client Hello) — plan 144, 0.12.0 ───
    /// `true` if the ClientHello carried the
    /// `encrypted_client_hello` extension (RFC type 0xfe0d,
    /// `draft-ietf-tls-esni`). Outer-form only — inner is
    /// encrypted and not observable passively.
    pub ech_present: bool,
    /// HPKE `config_id` byte from the outer `ECHClientHello`
    /// struct, when ECH is present. Useful for clustering
    /// clients by ECH config rotation.
    pub ech_config_id: Option<u8>,
    /// When `ech_present == true`, the [`Self::sni`] above is
    /// the outer (public cover) domain — **not** the real
    /// target. The inner SNI is encrypted under the ECH
    /// ciphertext and cannot be extracted without the ECH
    /// private key. Default `false`.
    pub sni_is_outer: bool,
}

impl TlsClientHello {
    /// `Server Name Indication` extension value, if present.
    /// Convenience accessor — equivalent to `self.sni.as_deref()`,
    /// shipped (plan 78) for symmetry with the HTTP convenience
    /// accessors and to give trait-object cases a method-shaped
    /// call site.
    pub fn sni(&self) -> Option<&str> {
        self.sni.as_deref()
    }
}

/// Parsed TLS ServerHello.
#[derive(Debug, Clone, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct TlsServerHello {
    pub record_version: TlsVersion,
    pub legacy_version: TlsVersion,
    pub random: [u8; 32],
    pub session_id: Bytes,
    /// The cipher suite the server picked.
    pub cipher_suite: u16,
    pub compression: u8,
    /// Negotiated ALPN protocol, if the extension was present and
    /// the server selected one.
    pub alpn: Option<String>,
    /// `supported_versions` extension — present in TLS 1.3 to
    /// signal the actual negotiated version.
    pub supported_version: Option<TlsVersion>,

    // ── ECH — plan 144, 0.12.0 ───────────────────────────
    /// Best-effort signal that the server returned
    /// `retry_configs` in EncryptedExtensions (ECH rejection).
    /// Encrypted-EE retry-configs are not passively observable
    /// without ECH keys; this field captures only the plaintext
    /// fallback path on early handshake errors. Default
    /// `false`. New in 0.12.0.
    pub ech_retry_configs: bool,
}

/// TLS Alert record (RFC 5246 §7.2).
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TlsAlert {
    pub level: TlsAlertLevel,
    pub description: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "kind", content = "value", rename_all = "snake_case")
)]
pub enum TlsAlertLevel {
    Warning,
    Fatal,
    Other(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "kind", content = "value", rename_all = "snake_case")
)]
pub enum TlsVersion {
    Ssl3_0,
    Tls1_0,
    Tls1_1,
    Tls1_2,
    #[default]
    Tls1_3,
    Other(u16),
}

impl TlsVersion {
    /// Map a raw 16-bit version number from the wire to a `TlsVersion`.
    pub fn from_raw(v: u16) -> Self {
        match v {
            0x0300 => TlsVersion::Ssl3_0,
            0x0301 => TlsVersion::Tls1_0,
            0x0302 => TlsVersion::Tls1_1,
            0x0303 => TlsVersion::Tls1_2,
            0x0304 => TlsVersion::Tls1_3,
            other => TlsVersion::Other(other),
        }
    }

    /// Reverse of [`from_raw`](Self::from_raw).
    pub fn to_raw(self) -> u16 {
        match self {
            TlsVersion::Ssl3_0 => 0x0300,
            TlsVersion::Tls1_0 => 0x0301,
            TlsVersion::Tls1_1 => 0x0302,
            TlsVersion::Tls1_2 => 0x0303,
            TlsVersion::Tls1_3 => 0x0304,
            TlsVersion::Other(v) => v,
        }
    }
}

/// Tunables for the TLS observer.
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// Compute JA3 fingerprints for every ClientHello (requires
    /// `tls-fingerprints` feature; was `ja3` pre-0.12). Default:
    /// `false` even with the feature on.
    pub ja3: bool,
    /// Compute JA4 fingerprints for every ClientHello (requires
    /// `tls-fingerprints` feature; was `ja4` pre-0.12). Default:
    /// `false` even with the feature on.
    pub ja4: bool,
    /// Maximum bytes buffered per direction before the reassembler
    /// gives up and goes Desynced. Defaults to 64 KiB — TLS records
    /// are 16 KiB max each; the handshake usually fits in 1–3 records.
    pub max_buffer: usize,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            ja3: false,
            ja4: false,
            max_buffer: 64 * 1024,
        }
    }
}

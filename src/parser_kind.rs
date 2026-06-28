//! [`ParserKind`] — typed parser identity.
//!
//! Replaces the stringly-typed `parser_kind() -> &'static str`
//! shape. The type landed in 0.18 (issue #21) and became the
//! actual return type of [`crate::SessionParser::parser_kind`] /
//! [`crate::DatagramParser::parser_kind`] — and the field type on
//! [`crate::driver::Event::ParserClosed`] /
//! [`crate::driver::SlotHandle::parser_kind`] — in 0.20 (#109).
//! Routing on the enum at sink / emit / consumer sites is now
//! compile-checked: typos fail to resolve, and `match` arms enforce
//! exhaustiveness against the standard variants.
//!
//! The enum is `#[non_exhaustive]` and includes an
//! `Other(&'static str)` variant so downstream crates can register
//! their own parser kinds without flowscope code changes.

/// Which parser produced a session / datagram message.
///
/// Built-in variants cover every parser shipped under a flowscope
/// feature gate. Downstream crates register their own kinds via
/// [`Self::Other`].
///
/// `#[non_exhaustive]` — future protocol features will add
/// variants; matching on this enum should always include a
/// wildcard arm.
/// Serializes as its [`as_str`](Self::as_str) slug — a plain JSON
/// string (e.g. `"http/1"`), not a tagged object — so the
/// `parser_kind` field in emitted events matches the pre-0.20
/// `&'static str` wire shape. Deserializes a slug back via
/// [`from_slug`](Self::from_slug): built-in slugs round-trip to
/// their variant; an unrecognised slug (including a downstream
/// [`Other`](Self::Other) label) deserializes to
/// [`Unspecified`](Self::Unspecified) — it cannot rebuild the
/// `&'static str` an `Other` needs.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ParserKind {
    /// HTTP/1.x ([`crate::http`]).
    Http1,
    /// TLS ClientHello / ServerHello / Alert / ApplicationData
    /// ([`crate::tls`]).
    Tls,
    /// TLS handshake aggregator
    /// ([`crate::tls::TlsHandshakeParser`]).
    TlsHandshake,
    /// DNS-over-UDP ([`crate::dns::DnsUdpParser`]).
    DnsUdp,
    /// DNS-over-TCP ([`crate::dns::DnsTcpParser`]).
    DnsTcp,
    /// ICMP v4 / v6 ([`crate::icmp::IcmpParser`]).
    Icmp,
    /// SSH banner + KEXINIT + HASSH ([`crate::ssh`]).
    Ssh,
    /// NTP ([`crate::ntp`]).
    Ntp,
    /// SSDP / UPnP ([`crate::ssdp`]).
    Ssdp,
    /// TFTP ([`crate::tftp`]).
    Tftp,
    /// mDNS ([`crate::mdns`]).
    Mdns,
    /// NetBIOS Name Service ([`crate::netbios_ns`]).
    NetbiosNs,
    /// FTP control channel ([`crate::ftp`]).
    Ftp,
    /// SMTP control channel ([`crate::smtp`]).
    Smtp,
    /// WireGuard handshake ([`crate::wireguard`]).
    WireGuard,
    /// Modbus/TCP ([`crate::modbus`]).
    Modbus,
    /// STUN ([`crate::stun`]).
    Stun,
    /// RDP X.224 negotiation ([`crate::rdp`]).
    Rdp,
    /// SNMP v1/v2c ([`crate::snmp`]).
    Snmp,
    /// RADIUS ([`crate::radius`]).
    Radius,
    /// DHCP ([`crate::dhcp`]).
    Dhcp,
    /// QUIC Initial ([`crate::quic`]).
    Quic,
    /// SMB2/3 ([`crate::smb`]).
    Smb,
    /// LDAP ([`crate::ldap`]).
    Ldap,
    /// Kerberos AS/TGS (UDP or TCP) ([`crate::kerberos`]).
    Kerberos,
    /// DNP3 ([`crate::dnp3`]).
    Dnp3,
    /// Downstream-registered parser kind. The `&'static str`
    /// label should be a unique stable slug — typical convention
    /// is `"crate-name/protocol"` (e.g. `"netring/syslog"`).
    Other(&'static str),
    /// Parser didn't identify itself (e.g. a test stub). The
    /// default returned by the [`crate::SessionParser`] /
    /// [`crate::DatagramParser`] traits when not overridden.
    #[default]
    Unspecified,
}

impl ParserKind {
    /// Stable slug — same vocabulary the 0.17-and-earlier
    /// `parser_kind() -> &'static str` returned. Use for metric
    /// labels and JSON `parser_kind` field emission.
    ///
    /// Each built-in variant maps to the slug its parser historically
    /// returned (`Http1` → `"http/1"`, `DnsUdp` → `"dns-udp"`,
    /// `NetbiosNs` → `"netbios-ns"`, …); the full mapping is
    /// regression-pinned by `slug_vocabulary_locked`. [`Self::Other`]
    /// yields its wrapped caller-supplied slug; [`Self::Unspecified`]
    /// yields `""`. [`from_slug`](Self::from_slug) is the inverse.
    pub fn as_str(&self) -> &'static str {
        match self {
            ParserKind::Http1 => "http/1",
            ParserKind::Tls => "tls",
            ParserKind::TlsHandshake => "tls-handshake",
            ParserKind::DnsUdp => "dns-udp",
            ParserKind::DnsTcp => "dns-tcp",
            ParserKind::Icmp => "icmp",
            ParserKind::Ssh => "ssh",
            ParserKind::Ntp => "ntp",
            ParserKind::Ssdp => "ssdp",
            ParserKind::Tftp => "tftp",
            ParserKind::Mdns => "mdns",
            ParserKind::NetbiosNs => "netbios-ns",
            ParserKind::Ftp => "ftp",
            ParserKind::Smtp => "smtp",
            ParserKind::WireGuard => "wireguard",
            ParserKind::Modbus => "modbus",
            ParserKind::Stun => "stun",
            ParserKind::Rdp => "rdp",
            ParserKind::Snmp => "snmp",
            ParserKind::Radius => "radius",
            ParserKind::Dhcp => "dhcp",
            ParserKind::Quic => "quic",
            ParserKind::Smb => "smb",
            ParserKind::Ldap => "ldap",
            ParserKind::Kerberos => "kerberos",
            ParserKind::Dnp3 => "dnp3",
            ParserKind::Other(s) => s,
            ParserKind::Unspecified => "",
        }
    }

    /// Inverse of [`as_str`](Self::as_str) for the built-in slugs.
    ///
    /// A recognised built-in slug maps to its variant; `""` maps to
    /// [`Unspecified`](Self::Unspecified); any other string maps to
    /// [`Unspecified`](Self::Unspecified) too (it can't become an
    /// [`Other`](Self::Other) — that variant needs a `&'static str`,
    /// which a runtime string isn't). Used by the `Deserialize` impl.
    pub fn from_slug(s: &str) -> ParserKind {
        match s {
            "http/1" => ParserKind::Http1,
            "tls" => ParserKind::Tls,
            "tls-handshake" => ParserKind::TlsHandshake,
            "dns-udp" => ParserKind::DnsUdp,
            "dns-tcp" => ParserKind::DnsTcp,
            "icmp" => ParserKind::Icmp,
            "ssh" => ParserKind::Ssh,
            "ntp" => ParserKind::Ntp,
            "ssdp" => ParserKind::Ssdp,
            "tftp" => ParserKind::Tftp,
            "mdns" => ParserKind::Mdns,
            "netbios-ns" => ParserKind::NetbiosNs,
            "ftp" => ParserKind::Ftp,
            "smtp" => ParserKind::Smtp,
            "wireguard" => ParserKind::WireGuard,
            "modbus" => ParserKind::Modbus,
            "stun" => ParserKind::Stun,
            "rdp" => ParserKind::Rdp,
            "snmp" => ParserKind::Snmp,
            "radius" => ParserKind::Radius,
            "dhcp" => ParserKind::Dhcp,
            "quic" => ParserKind::Quic,
            "smb" => ParserKind::Smb,
            "ldap" => ParserKind::Ldap,
            "kerberos" => ParserKind::Kerberos,
            "dnp3" => ParserKind::Dnp3,
            _ => ParserKind::Unspecified,
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for ParserKind {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ParserKind {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let slug = std::borrow::Cow::<'de, str>::deserialize(deserializer)?;
        Ok(ParserKind::from_slug(&slug))
    }
}

impl std::fmt::Display for ParserKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_vocabulary_locked() {
        // Regression-pin the slugs — downstream metric pipelines
        // depend on these.
        assert_eq!(ParserKind::Http1.as_str(), "http/1");
        assert_eq!(ParserKind::Tls.as_str(), "tls");
        assert_eq!(ParserKind::TlsHandshake.as_str(), "tls-handshake");
        assert_eq!(ParserKind::DnsUdp.as_str(), "dns-udp");
        assert_eq!(ParserKind::DnsTcp.as_str(), "dns-tcp");
        assert_eq!(ParserKind::Icmp.as_str(), "icmp");
        assert_eq!(ParserKind::Ssh.as_str(), "ssh");
        assert_eq!(ParserKind::Ntp.as_str(), "ntp");
        assert_eq!(ParserKind::Ssdp.as_str(), "ssdp");
        assert_eq!(ParserKind::Tftp.as_str(), "tftp");
        assert_eq!(ParserKind::Mdns.as_str(), "mdns");
        assert_eq!(ParserKind::NetbiosNs.as_str(), "netbios-ns");
        assert_eq!(ParserKind::Ftp.as_str(), "ftp");
        assert_eq!(ParserKind::Smtp.as_str(), "smtp");
        assert_eq!(ParserKind::WireGuard.as_str(), "wireguard");
        assert_eq!(ParserKind::Modbus.as_str(), "modbus");
        assert_eq!(ParserKind::Stun.as_str(), "stun");
        assert_eq!(ParserKind::Rdp.as_str(), "rdp");
        assert_eq!(ParserKind::Snmp.as_str(), "snmp");
        assert_eq!(ParserKind::Radius.as_str(), "radius");
        assert_eq!(ParserKind::Dhcp.as_str(), "dhcp");
        assert_eq!(ParserKind::Quic.as_str(), "quic");
        assert_eq!(ParserKind::Smb.as_str(), "smb");
        assert_eq!(ParserKind::Ldap.as_str(), "ldap");
        assert_eq!(ParserKind::Kerberos.as_str(), "kerberos");
        assert_eq!(ParserKind::Dnp3.as_str(), "dnp3");
        assert_eq!(ParserKind::Unspecified.as_str(), "");
        assert_eq!(
            ParserKind::Other("netring/syslog").as_str(),
            "netring/syslog"
        );
    }

    #[test]
    fn default_is_unspecified() {
        assert_eq!(ParserKind::default(), ParserKind::Unspecified);
    }

    #[test]
    fn display_uses_slug() {
        assert_eq!(ParserKind::Http1.to_string(), "http/1");
        assert_eq!(ParserKind::Other("custom").to_string(), "custom");
    }

    #[test]
    fn from_slug_round_trips_builtins() {
        for k in [
            ParserKind::Http1,
            ParserKind::Tls,
            ParserKind::TlsHandshake,
            ParserKind::DnsUdp,
            ParserKind::DnsTcp,
            ParserKind::Icmp,
            ParserKind::Ssh,
            ParserKind::Ntp,
            ParserKind::Ssdp,
            ParserKind::Tftp,
            ParserKind::Mdns,
            ParserKind::NetbiosNs,
            ParserKind::Ftp,
            ParserKind::Smtp,
            ParserKind::WireGuard,
            ParserKind::Modbus,
            ParserKind::Stun,
            ParserKind::Rdp,
            ParserKind::Snmp,
            ParserKind::Radius,
            ParserKind::Dhcp,
            ParserKind::Quic,
            ParserKind::Smb,
            ParserKind::Ldap,
            ParserKind::Kerberos,
            ParserKind::Dnp3,
        ] {
            assert_eq!(ParserKind::from_slug(k.as_str()), k);
        }
        assert_eq!(ParserKind::from_slug(""), ParserKind::Unspecified);
        // Unknown / downstream slug can't rebuild `Other` → Unspecified.
        assert_eq!(
            ParserKind::from_slug("netring/syslog"),
            ParserKind::Unspecified
        );
    }

    #[cfg(feature = "serde")]
    #[test]
    fn serde_is_a_plain_slug_string() {
        // Serializes as a bare string, not a tagged object.
        assert_eq!(
            serde_json::to_string(&ParserKind::Http1).unwrap(),
            "\"http/1\""
        );
        assert_eq!(
            serde_json::to_string(&ParserKind::Other("x")).unwrap(),
            "\"x\""
        );
        // Built-in slug round-trips; unknown → Unspecified.
        let back: ParserKind = serde_json::from_str("\"dns-udp\"").unwrap();
        assert_eq!(back, ParserKind::DnsUdp);
        let unknown: ParserKind = serde_json::from_str("\"x\"").unwrap();
        assert_eq!(unknown, ParserKind::Unspecified);
    }
}

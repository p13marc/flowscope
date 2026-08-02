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

/// Declares a `#[non_exhaustive]` **slug enum**: a flat set of
/// built-in variants each paired with its stable string slug in one
/// table, plus the invariant `Other(&'static str)` / `#[default]
/// Unspecified` tail. `as_str` and `from_slug` are both generated
/// from that single table, so the forward and inverse mappings can
/// never drift apart — the class of bug the old hand-written parallel
/// `match` blocks invited (issue #139).
///
/// Adding a parser is now a one-line edit inside the table.
macro_rules! slug_enum {
    (
        $(#[$enum_meta:meta])*
        pub enum $name:ident {
            $( $(#[$vmeta:meta])* $variant:ident => $slug:literal ),+ $(,)?
        }
    ) => {
        $(#[$enum_meta])*
        pub enum $name {
            $( $(#[$vmeta])* $variant, )+
            /// Downstream-registered parser kind. The `&'static str`
            /// label should be a unique stable slug — typical
            /// convention is `"crate-name/protocol"`
            /// (e.g. `"netring/syslog"`).
            Other(&'static str),
            /// Parser didn't identify itself (e.g. a test stub). The
            /// default returned by the [`crate::SessionParser`] /
            /// [`crate::DatagramParser`] traits when not overridden.
            #[default]
            Unspecified,
        }

        impl $name {
            /// Stable slug — same vocabulary the 0.17-and-earlier
            /// `parser_kind() -> &'static str` returned. Use for metric
            /// labels and JSON `parser_kind` field emission.
            ///
            /// Each built-in variant maps to the slug its parser
            /// historically returned (`Http1` → `"http/1"`, `DnsUdp`
            /// → `"dns-udp"`, …); the full mapping is regression-pinned
            /// by `slug_vocabulary_locked`. [`Self::Other`] yields its
            /// wrapped caller-supplied slug; [`Self::Unspecified`]
            /// yields `""`. [`from_slug`](Self::from_slug) is the inverse.
            pub fn as_str(&self) -> &'static str {
                match self {
                    $( $name::$variant => $slug, )+
                    $name::Other(s) => s,
                    $name::Unspecified => "",
                }
            }

            /// Inverse of [`as_str`](Self::as_str) for the built-in
            /// slugs.
            ///
            /// A recognised built-in slug maps to its variant; `""`
            /// maps to [`Unspecified`](Self::Unspecified); any other
            /// string maps to [`Unspecified`](Self::Unspecified) too
            /// (it can't become an [`Other`](Self::Other) — that
            /// variant needs a `&'static str`, which a runtime string
            /// isn't). Used by the `Deserialize` impl.
            pub fn from_slug(s: &str) -> $name {
                match s {
                    $( $slug => $name::$variant, )+
                    _ => $name::Unspecified,
                }
            }
        }
    };
}

slug_enum! {
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
        Http1 => "http/1",
        /// HTTP/2 ([`crate::http2`]).
        Http2 => "http/2",
        /// TLS ClientHello / ServerHello / Alert / ApplicationData
        /// ([`crate::tls`]).
        Tls => "tls",
        /// TLS handshake aggregator
        /// ([`crate::tls::TlsHandshakeParser`]).
        TlsHandshake => "tls-handshake",
        /// DNS-over-UDP ([`crate::dns::DnsUdpParser`]).
        DnsUdp => "dns-udp",
        /// DNS-over-TCP ([`crate::dns::DnsTcpParser`]).
        DnsTcp => "dns-tcp",
        /// ICMP v4 / v6 ([`crate::icmp::IcmpParser`]).
        Icmp => "icmp",
        /// SSH banner + KEXINIT + HASSH ([`crate::ssh`]).
        Ssh => "ssh",
        /// NTP ([`crate::ntp`]).
        Ntp => "ntp",
        /// SSDP / UPnP ([`crate::ssdp`]).
        Ssdp => "ssdp",
        /// TFTP ([`crate::tftp`]).
        Tftp => "tftp",
        /// mDNS ([`crate::mdns`]).
        Mdns => "mdns",
        /// NetBIOS Name Service ([`crate::netbios_ns`]).
        NetbiosNs => "netbios-ns",
        /// FTP control channel ([`crate::ftp`]).
        Ftp => "ftp",
        /// SMTP control channel ([`crate::smtp`]).
        Smtp => "smtp",
        /// WireGuard handshake ([`crate::wireguard`]).
        WireGuard => "wireguard",
        /// Modbus/TCP ([`crate::modbus`]).
        Modbus => "modbus",
        /// STUN ([`crate::stun`]).
        Stun => "stun",
        /// RDP X.224 negotiation ([`crate::rdp`]).
        Rdp => "rdp",
        /// SNMP v1/v2c ([`crate::snmp`]).
        Snmp => "snmp",
        /// RADIUS ([`crate::radius`]).
        Radius => "radius",
        /// DHCP ([`crate::dhcp`]).
        Dhcp => "dhcp",
        /// QUIC Initial ([`crate::quic`]).
        Quic => "quic",
        /// SMB2/3 ([`crate::smb`]).
        Smb => "smb",
        /// LDAP ([`crate::ldap`]).
        Ldap => "ldap",
        /// Kerberos AS/TGS (UDP or TCP) ([`crate::kerberos`]).
        Kerberos => "kerberos",
        /// DNP3 ([`crate::dnp3`]).
        Dnp3 => "dnp3",
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

//! SSDP message types.

/// One parsed SSDP datagram. Field semantics depend on
/// [`SsdpMessage::kind`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct SsdpMessage {
    /// Whether this is an advertisement, search, or response.
    pub kind: SsdpKind,
    /// `HOST` header — multicast address+port (e.g.
    /// `"239.255.255.250:1900"`). RFC 4795: required.
    pub host: Option<String>,
    /// `NT` header (NOTIFY only) — Notification Type — the
    /// device or service type being advertised.
    pub nt: Option<String>,
    /// `NTS` header (NOTIFY only) — Notification Sub-Type:
    /// `"ssdp:alive"`, `"ssdp:byebye"`, `"ssdp:update"`.
    pub nts: Option<String>,
    /// `ST` header (M-SEARCH + response) — Search Target.
    pub st: Option<String>,
    /// `USN` header — Unique Service Name. Combines a
    /// UUID with an optional `::` + URN suffix.
    pub usn: Option<String>,
    /// `LOCATION` header — HTTP URL pointing at the device
    /// description XML.
    pub location: Option<String>,
    /// `SERVER` header — vendor / firmware banner (NOTIFY +
    /// response). Operationally one of the more discriminating
    /// asset-discovery signals.
    pub server: Option<String>,
    /// `CACHE-CONTROL: max-age=<n>` — TTL of the advertisement
    /// in seconds. Decoded only when the header has the exact
    /// `max-age=N` form.
    pub cache_control_max_age: Option<u32>,
    /// `USER-AGENT` header (M-SEARCH only) — the searching
    /// client's identifier.
    pub user_agent: Option<String>,
}

/// SSDP message kind. The three are textually distinct on
/// the request line so the parser disambiguates without
/// additional input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "kind", content = "value", rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum SsdpKind {
    /// `NOTIFY * HTTP/1.1` — device-side advertisement
    /// broadcast on the multicast group.
    Notify,
    /// `M-SEARCH * HTTP/1.1` — client-side query.
    MSearch,
    /// `HTTP/1.1 200 OK` — unicast response to an M-SEARCH.
    Response,
}

impl SsdpKind {
    /// Stable slug for metric labels.
    pub fn as_str(self) -> &'static str {
        match self {
            SsdpKind::Notify => "notify",
            SsdpKind::MSearch => "m_search",
            SsdpKind::Response => "response",
        }
    }
}

impl SsdpMessage {
    /// Convenience: `true` if this is a `NOTIFY` with
    /// `NTS: ssdp:byebye` — device tearing down its
    /// announcement, often a useful "device leaving the
    /// network" signal.
    #[inline]
    pub fn is_byebye(&self) -> bool {
        matches!(self.kind, SsdpKind::Notify)
            && self
                .nts
                .as_deref()
                .map(|s| s.eq_ignore_ascii_case("ssdp:byebye"))
                .unwrap_or(false)
    }

    /// Convenience: `true` if this is a `NOTIFY` with
    /// `NTS: ssdp:alive` — the standard periodic
    /// re-announcement.
    #[inline]
    pub fn is_alive(&self) -> bool {
        matches!(self.kind, SsdpKind::Notify)
            && self
                .nts
                .as_deref()
                .map(|s| s.eq_ignore_ascii_case("ssdp:alive"))
                .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_slugs_locked() {
        assert_eq!(SsdpKind::Notify.as_str(), "notify");
        assert_eq!(SsdpKind::MSearch.as_str(), "m_search");
        assert_eq!(SsdpKind::Response.as_str(), "response");
    }

    #[test]
    fn is_byebye_only_fires_on_notify_byebye() {
        let mut m = SsdpMessage {
            kind: SsdpKind::Notify,
            host: None,
            nt: None,
            nts: Some("ssdp:byebye".into()),
            st: None,
            usn: None,
            location: None,
            server: None,
            cache_control_max_age: None,
            user_agent: None,
        };
        assert!(m.is_byebye());
        assert!(!m.is_alive());

        m.nts = Some("ssdp:alive".into());
        assert!(!m.is_byebye());
        assert!(m.is_alive());

        // Wrong kind, even with the right NTS.
        m.kind = SsdpKind::Response;
        assert!(!m.is_alive());
    }

    #[test]
    fn nts_check_is_case_insensitive() {
        let m = SsdpMessage {
            kind: SsdpKind::Notify,
            host: None,
            nt: None,
            nts: Some("SSDP:ALIVE".into()),
            st: None,
            usn: None,
            location: None,
            server: None,
            cache_control_max_age: None,
            user_agent: None,
        };
        assert!(m.is_alive());
    }
}

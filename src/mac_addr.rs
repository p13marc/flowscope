//! [`MacAddr`] — strongly-typed 48-bit Ethernet MAC address.
//!
//! Replaces raw `[u8; 6]` byte arrays in extractor keys and ARP
//! / NDP message types. Adds:
//!
//! - `Display` formatting as `aa:bb:cc:dd:ee:ff` (lowercase hex,
//!   colon-separated, the IEEE 802 canonical form).
//! - `From<[u8; 6]>` / `Into<[u8; 6]>` for zero-cost wire-format
//!   interop.
//! - Standard predicates: `is_broadcast` (ff:ff:ff:ff:ff:ff),
//!   `is_multicast` (LSB of OUI byte 0), `is_zero` (00:00:00:00:00:00).
//!
//! `#[repr(transparent)]` so it's layout-identical to the inner
//! `[u8; 6]` — passing a `*const MacAddr` to a C ABI that
//! expects `*const u8` is sound, and the struct can be FFI'd
//! without conversion. Same `Send + Sync + Copy + Hash + Eq`
//! shape as the bare array.
//!
//! Issue #1 (0.17).

use std::fmt;
use std::str::FromStr;

/// 48-bit Ethernet hardware address.
///
/// Byte order is **network byte order** (the wire layout): the
/// first byte is the OUI's most-significant byte. Display formats
/// the address as `aa:bb:cc:dd:ee:ff` per IEEE 802.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct MacAddr(pub [u8; 6]);

impl MacAddr {
    /// All-zero address (`00:00:00:00:00:00`).
    pub const ZERO: Self = MacAddr([0; 6]);

    /// Broadcast address (`ff:ff:ff:ff:ff:ff`).
    pub const BROADCAST: Self = MacAddr([0xff; 6]);

    /// Construct from a 6-byte array.
    #[inline]
    pub const fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    /// Borrow the underlying 6 bytes.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8; 6] {
        &self.0
    }

    /// Move the underlying bytes out.
    #[inline]
    pub const fn into_bytes(self) -> [u8; 6] {
        self.0
    }

    /// `true` for the all-zero address.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.0 == [0; 6]
    }

    /// `true` for the broadcast address (`ff:ff:ff:ff:ff:ff`).
    #[inline]
    pub fn is_broadcast(&self) -> bool {
        self.0 == [0xff; 6]
    }

    /// `true` for any multicast address (low bit of byte 0 set).
    /// Includes the broadcast address as a special case.
    #[inline]
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 0x01 != 0
    }

    /// `true` for unicast addresses (low bit of byte 0 clear).
    #[inline]
    pub fn is_unicast(&self) -> bool {
        !self.is_multicast()
    }

    /// `true` for locally-administered addresses (second-lowest
    /// bit of byte 0 set). IEEE-assigned OUIs have this clear.
    #[inline]
    pub fn is_locally_administered(&self) -> bool {
        self.0[0] & 0x02 != 0
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5],
        )
    }
}

impl fmt::Debug for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MacAddr({self})")
    }
}

impl From<[u8; 6]> for MacAddr {
    #[inline]
    fn from(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }
}

impl From<MacAddr> for [u8; 6] {
    #[inline]
    fn from(mac: MacAddr) -> Self {
        mac.0
    }
}

/// Error returned by [`MacAddr::from_str`] for unparseable input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseMacAddrError;

impl fmt::Display for ParseMacAddrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid MAC address (expected six colon- or dash-separated hex bytes)")
    }
}

impl std::error::Error for ParseMacAddrError {}

impl FromStr for MacAddr {
    type Err = ParseMacAddrError;

    /// Parse `aa:bb:cc:dd:ee:ff` or `aa-bb-cc-dd-ee-ff` into a
    /// `MacAddr`. Accepts both upper- and lower-case hex.
    /// Rejects any other shape (12-char strings without
    /// separators, EUI-64, etc.).
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let sep = if s.as_bytes().get(2) == Some(&b':') {
            ':'
        } else if s.as_bytes().get(2) == Some(&b'-') {
            '-'
        } else {
            return Err(ParseMacAddrError);
        };
        let mut bytes = [0u8; 6];
        let mut it = s.split(sep);
        for slot in &mut bytes {
            let chunk = it.next().ok_or(ParseMacAddrError)?;
            if chunk.len() != 2 {
                return Err(ParseMacAddrError);
            }
            *slot = u8::from_str_radix(chunk, 16).map_err(|_| ParseMacAddrError)?;
        }
        if it.next().is_some() {
            return Err(ParseMacAddrError);
        }
        Ok(MacAddr(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_lowercase_colon_separated() {
        let m = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(m.to_string(), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn display_pads_single_digit_bytes() {
        let m = MacAddr([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        assert_eq!(m.to_string(), "01:02:03:04:05:06");
    }

    #[test]
    fn debug_includes_type_name() {
        let m = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(format!("{m:?}"), "MacAddr(aa:bb:cc:dd:ee:ff)");
    }

    #[test]
    fn zero_constant() {
        assert_eq!(MacAddr::ZERO, MacAddr([0; 6]));
        assert!(MacAddr::ZERO.is_zero());
    }

    #[test]
    fn broadcast_constant() {
        assert_eq!(MacAddr::BROADCAST, MacAddr([0xff; 6]));
        assert!(MacAddr::BROADCAST.is_broadcast());
        // Broadcast is also multicast.
        assert!(MacAddr::BROADCAST.is_multicast());
    }

    #[test]
    fn multicast_detection() {
        // LSB of byte 0 set → multicast.
        let m = MacAddr([0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]);
        assert!(m.is_multicast());
        assert!(!m.is_unicast());

        // LSB of byte 0 clear → unicast.
        let m = MacAddr([0x02, 0x00, 0x5e, 0x00, 0x00, 0x01]);
        assert!(!m.is_multicast());
        assert!(m.is_unicast());
    }

    #[test]
    fn locally_administered_bit() {
        // Bit 1 of byte 0 set → locally administered.
        let m = MacAddr([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        assert!(m.is_locally_administered());

        // Bit 1 clear → IEEE-assigned OUI.
        let m = MacAddr([0x00, 0x00, 0x00, 0x00, 0x00, 0x01]);
        assert!(!m.is_locally_administered());
    }

    #[test]
    fn from_into_byte_array() {
        let bytes = [1u8, 2, 3, 4, 5, 6];
        let m: MacAddr = bytes.into();
        let back: [u8; 6] = m.into();
        assert_eq!(back, bytes);
    }

    #[test]
    fn as_bytes_returns_ref() {
        let m = MacAddr([1, 2, 3, 4, 5, 6]);
        assert_eq!(m.as_bytes(), &[1, 2, 3, 4, 5, 6]);
    }

    #[test]
    fn repr_transparent_layout() {
        // #[repr(transparent)] guarantees MacAddr has the same
        // size + alignment as [u8; 6].
        assert_eq!(std::mem::size_of::<MacAddr>(), 6);
        assert_eq!(std::mem::align_of::<MacAddr>(), 1);
    }

    #[test]
    fn hash_and_eq_are_consistent() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(MacAddr([1, 2, 3, 4, 5, 6]));
        assert!(set.contains(&MacAddr([1, 2, 3, 4, 5, 6])));
        assert!(!set.contains(&MacAddr([1, 2, 3, 4, 5, 7])));
    }

    #[test]
    fn ordering_is_lexicographic() {
        let a = MacAddr([0, 0, 0, 0, 0, 1]);
        let b = MacAddr([0, 0, 0, 0, 0, 2]);
        assert!(a < b);
    }

    #[test]
    fn from_str_colon_separated() {
        let m: MacAddr = "aa:bb:cc:dd:ee:ff".parse().unwrap();
        assert_eq!(m, MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
    }

    #[test]
    fn from_str_dash_separated() {
        let m: MacAddr = "aa-bb-cc-dd-ee-ff".parse().unwrap();
        assert_eq!(m, MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
    }

    #[test]
    fn from_str_uppercase_accepted() {
        let m: MacAddr = "AA:BB:CC:DD:EE:FF".parse().unwrap();
        assert_eq!(m, MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
    }

    #[test]
    fn from_str_round_trips_display() {
        let m = MacAddr([1, 2, 3, 4, 5, 6]);
        let s = m.to_string();
        let back: MacAddr = s.parse().unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn from_str_rejects_malformed() {
        assert!("aabbccddeeff".parse::<MacAddr>().is_err()); // no separators
        assert!("aa:bb:cc:dd:ee".parse::<MacAddr>().is_err()); // 5 segments
        assert!("aa:bb:cc:dd:ee:ff:00".parse::<MacAddr>().is_err()); // 7 segments
        assert!("aa:bb:cc:dd:ee:gg".parse::<MacAddr>().is_err()); // non-hex
        assert!("a:bb:cc:dd:ee:ff".parse::<MacAddr>().is_err()); // single-digit
        assert!("".parse::<MacAddr>().is_err()); // empty
    }
}

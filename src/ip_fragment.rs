//! `flowscope::ip_fragment` — IP fragment reassembly (issue #138).
//!
//! Fragmented IP datagrams are an evasion surface: an attack split
//! across fragments bypasses any L4/L7 parser that only sees the
//! first fragment (the classic Ptacek–Newsham insertion/evasion
//! and the teardrop overlap attacks). [`IpFragmentReassembler`]
//! reassembles the original datagram from its fragments, keyed by
//! the RFC 791 reassembly tuple `(src, dst, protocol, id)`, so the
//! reassembled payload can be re-fed to the L4/L7 path.
//!
//! Structurally this mirrors `SegmentBufferReassembler` (the TCP
//! out-of-order hole-filler): a per-datagram offset-ordered
//! buffer, a completion check, a reassembly timeout, and
//! byte/entry caps.
//!
//! # Overlap policy — drop, don't reassemble
//!
//! Overlapping fragments have no legitimate use; they exist to
//! desync a reassembler from the endpoint (different OSes favour
//! first- vs last-writer). Per **RFC 5722** this implementation
//! **drops the entire datagram** on any overlap and counts it
//! ([`overlaps`](IpFragmentReassembler::overlaps)) — a fragmentation-evasion IOC.
//!
//! # IPv4 today; IPv6 follow-up
//!
//! `push_ipv4` (with the `extractors` feature) extracts the
//! reassembly key + offset from an `Ipv4Slice`. The
//! transport-agnostic [`push`](IpFragmentReassembler::push) works
//! for any address family with no feature required; an IPv6
//! convenience awaits Fragment-header (next-header 44) body decode
//! in `layers`.
//!
//! # Example
//!
//! ```
//! use flowscope::ip_fragment::{FragmentKey, IpFragmentReassembler};
//! use flowscope::Timestamp;
//!
//! let mut r = IpFragmentReassembler::new();
//! let key = FragmentKey {
//!     src: "10.0.0.1".parse().unwrap(),
//!     dst: "10.0.0.2".parse().unwrap(),
//!     protocol: 17, // UDP
//!     id: 42,
//! };
//! let now = Timestamp::new(0, 0);
//!
//! // Fragment 1 (offset 0, More-Fragments set) — incomplete.
//! assert!(r.push(key, 0, true, b"AAAAAAAA", now).is_none());
//! // Fragment 2 (offset 8, last) — completes the datagram.
//! let datagram = r.push(key, 8, false, b"BBBB", now).unwrap();
//! assert_eq!(datagram, b"AAAAAAAABBBB");
//! ```

use std::collections::{BTreeMap, HashMap};
use std::net::IpAddr;
use std::time::Duration;

use crate::Timestamp;
#[cfg(feature = "extractors")]
use crate::layers::Ipv4Slice;

/// RFC 791 §3.2 reassembly key: fragments of one datagram share
/// `(source, destination, protocol, identification)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FragmentKey {
    /// Source IP.
    pub src: IpAddr,
    /// Destination IP.
    pub dst: IpAddr,
    /// L4 protocol number (6 = TCP, 17 = UDP, …).
    pub protocol: u8,
    /// IP identification field (16-bit for v4, 32-bit for v6).
    pub id: u32,
}

/// Tuning for [`IpFragmentReassembler`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FragmentConfig {
    /// Max datagrams reassembling concurrently (oldest evicted on
    /// overflow). Default 4096.
    pub max_datagrams: usize,
    /// Max buffered bytes for a single datagram before it's
    /// dropped (a bogus far-offset fragment can't claim 64 KiB).
    /// Default 65 535 (the IPv4 max).
    pub max_datagram_bytes: usize,
    /// Reassembly timeout — a datagram missing fragments longer
    /// than this is dropped (RFC 791 recommends 15 s; Linux uses
    /// 30 s). Default 30 s.
    pub timeout: Duration,
}

impl Default for FragmentConfig {
    fn default() -> Self {
        Self {
            max_datagrams: 4096,
            max_datagram_bytes: 65_535,
            timeout: Duration::from_secs(30),
        }
    }
}

struct Reassembly {
    /// offset (bytes) → fragment payload.
    fragments: BTreeMap<usize, Vec<u8>>,
    /// Total datagram length, known once the last fragment
    /// (More-Fragments = 0) arrives: its offset + length.
    total_len: Option<usize>,
    buffered: usize,
    first_seen: Timestamp,
    /// Poisoned by an overlap — drop on next touch.
    poisoned: bool,
}

/// Reassembles IP datagrams from their fragments. See the
/// [module docs](self) for the overlap policy and bounds.
#[derive(Default)]
pub struct IpFragmentReassembler {
    pending: HashMap<FragmentKey, Reassembly>,
    config: FragmentConfig,
    reassembled: u64,
    timed_out: u64,
    overlaps: u64,
    oversize_dropped: u64,
}

impl IpFragmentReassembler {
    /// New reassembler with default tuning.
    pub fn new() -> Self {
        Self::with_config(FragmentConfig::default())
    }

    /// New reassembler with explicit tuning.
    pub fn with_config(config: FragmentConfig) -> Self {
        Self {
            pending: HashMap::new(),
            config,
            reassembled: 0,
            timed_out: 0,
            overlaps: 0,
            oversize_dropped: 0,
        }
    }

    /// Feed one fragment. `offset` is the fragment's byte offset
    /// within the reassembled datagram (IPv4 carries it in 8-byte
    /// units — multiply by 8). `more_fragments` is the MF flag.
    ///
    /// Returns `Some(datagram)` when this fragment completes the
    /// reassembly, else `None`. A non-fragment (offset 0 + MF
    /// clear) is returned immediately as its own payload.
    pub fn push(
        &mut self,
        key: FragmentKey,
        offset: usize,
        more_fragments: bool,
        payload: &[u8],
        now: Timestamp,
    ) -> Option<Vec<u8>> {
        // Fast path: not actually fragmented.
        if offset == 0 && !more_fragments {
            return Some(payload.to_vec());
        }

        self.evict_expired(now);

        // Bound concurrent datagrams before inserting a new one.
        if !self.pending.contains_key(&key) && self.pending.len() >= self.config.max_datagrams {
            self.drop_oldest();
        }

        let cap = self.config.max_datagram_bytes;
        let entry = self.pending.entry(key).or_insert_with(|| Reassembly {
            fragments: BTreeMap::new(),
            total_len: None,
            buffered: 0,
            first_seen: now,
            poisoned: false,
        });

        if entry.poisoned {
            return None;
        }

        // Overlap check (RFC 5722): does [offset, offset+len)
        // intersect any stored fragment?
        let end = offset.saturating_add(payload.len());
        let overlaps = entry.fragments.iter().any(|(&o, data)| {
            let o_end = o + data.len();
            offset < o_end && o < end
        });
        if overlaps {
            self.overlaps += 1;
            self.pending.remove(&key);
            return None;
        }

        // Oversize guard.
        if entry.buffered + payload.len() > cap || end > cap {
            self.oversize_dropped += 1;
            self.pending.remove(&key);
            return None;
        }

        entry.buffered += payload.len();
        entry.fragments.insert(offset, payload.to_vec());
        if !more_fragments {
            entry.total_len = Some(end);
        }

        // Complete? Contiguous from 0 to total_len.
        if let Some(total) = entry.total_len
            && is_contiguous(&entry.fragments, total)
        {
            let mut out = Vec::with_capacity(total);
            for (_, data) in std::mem::take(&mut entry.fragments) {
                out.extend_from_slice(&data);
            }
            self.pending.remove(&key);
            self.reassembled += 1;
            return Some(out);
        }
        None
    }

    /// Feed an IPv4 packet slice. Extracts the reassembly key +
    /// offset and delegates to [`push`](Self::push). Returns the
    /// reassembled datagram payload when complete.
    #[cfg(feature = "extractors")]
    pub fn push_ipv4(&mut self, ip: &Ipv4Slice<'_>, now: Timestamp) -> Option<Vec<u8>> {
        let key = FragmentKey {
            src: IpAddr::V4(ip.source()),
            dst: IpAddr::V4(ip.destination()),
            protocol: ip.protocol(),
            id: ip.identification() as u32,
        };
        // IPv4 fragment_offset is in 8-byte units.
        let offset = (ip.fragment_offset() as usize) * 8;
        self.push(key, offset, ip.mf(), ip.payload(), now)
    }

    /// Drop datagrams whose first fragment is older than the
    /// timeout. Returns the count dropped.
    pub fn evict_expired(&mut self, now: Timestamp) -> usize {
        let timeout = self.config.timeout;
        let before = self.pending.len();
        self.pending
            .retain(|_, r| now.to_duration().saturating_sub(r.first_seen.to_duration()) <= timeout);
        let dropped = before - self.pending.len();
        self.timed_out += dropped as u64;
        dropped
    }

    fn drop_oldest(&mut self) {
        if let Some(key) = self
            .pending
            .iter()
            .min_by_key(|(_, r)| r.first_seen.to_duration())
            .map(|(k, _)| *k)
        {
            self.pending.remove(&key);
        }
    }

    /// Datagrams currently reassembling.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Total datagrams successfully reassembled.
    pub fn reassembled(&self) -> u64 {
        self.reassembled
    }

    /// Datagrams dropped for a reassembly timeout.
    pub fn timed_out(&self) -> u64 {
        self.timed_out
    }

    /// Datagrams dropped for **overlapping fragments** — a
    /// fragmentation-evasion IOC (RFC 5722).
    pub fn overlaps(&self) -> u64 {
        self.overlaps
    }

    /// Datagrams dropped for exceeding the per-datagram byte cap.
    pub fn oversize_dropped(&self) -> u64 {
        self.oversize_dropped
    }
}

/// Are the buffered fragments contiguous from byte 0 to `total`?
fn is_contiguous(fragments: &BTreeMap<usize, Vec<u8>>, total: usize) -> bool {
    let mut expected = 0usize;
    for (&offset, data) in fragments {
        if offset != expected {
            return false;
        }
        expected += data.len();
    }
    expected == total
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> FragmentKey {
        FragmentKey {
            src: "10.0.0.1".parse().unwrap(),
            dst: "10.0.0.2".parse().unwrap(),
            protocol: 17,
            id: 42,
        }
    }

    fn t(s: u32) -> Timestamp {
        Timestamp::new(s, 0)
    }

    #[test]
    fn reassembles_two_in_order_fragments() {
        let mut r = IpFragmentReassembler::new();
        // Fragment 1: offset 0, 8 bytes, MF=1.
        assert!(r.push(key(), 0, true, b"AAAAAAAA", t(0)).is_none());
        // Fragment 2: offset 8, 5 bytes, MF=0 → completes.
        let out = r.push(key(), 8, false, b"BBBBB", t(0)).unwrap();
        assert_eq!(out, b"AAAAAAAABBBBB");
        assert_eq!(r.reassembled(), 1);
        assert_eq!(r.pending_len(), 0);
    }

    #[test]
    fn reassembles_out_of_order() {
        let mut r = IpFragmentReassembler::new();
        // Last fragment first (offset 8, MF=0).
        assert!(r.push(key(), 8, false, b"BBBBB", t(0)).is_none());
        // Then the first (offset 0, MF=1) → completes.
        let out = r.push(key(), 0, true, b"AAAAAAAA", t(0)).unwrap();
        assert_eq!(out, b"AAAAAAAABBBBB");
    }

    #[test]
    fn non_fragment_returns_immediately() {
        let mut r = IpFragmentReassembler::new();
        let out = r.push(key(), 0, false, b"whole", t(0)).unwrap();
        assert_eq!(out, b"whole");
        assert_eq!(r.pending_len(), 0);
    }

    #[test]
    fn overlapping_fragments_drop_datagram() {
        let mut r = IpFragmentReassembler::new();
        r.push(key(), 0, true, b"AAAAAAAA", t(0));
        // Overlaps [0,8) — teardrop-style.
        assert!(r.push(key(), 4, false, b"XXXXXXXX", t(0)).is_none());
        assert_eq!(r.overlaps(), 1);
        assert_eq!(r.pending_len(), 0, "poisoned datagram dropped");
    }

    #[test]
    fn missing_fragment_never_completes() {
        let mut r = IpFragmentReassembler::new();
        // offset 0 (MF=1) and offset 16 (MF=0) — gap at [8,16).
        assert!(r.push(key(), 0, true, b"AAAAAAAA", t(0)).is_none());
        assert!(r.push(key(), 16, false, b"CCCCC", t(0)).is_none());
        assert_eq!(r.pending_len(), 1);
    }

    #[test]
    fn timeout_evicts_incomplete() {
        let mut r = IpFragmentReassembler::new();
        r.push(key(), 0, true, b"AAAAAAAA", t(0));
        assert_eq!(r.pending_len(), 1);
        let dropped = r.evict_expired(t(31));
        assert_eq!(dropped, 1);
        assert_eq!(r.timed_out(), 1);
    }

    #[cfg(feature = "extractors")]
    fn ipv4_fragment(id: u16, offset_units: u16, mf: bool, payload: &[u8]) -> Vec<u8> {
        let mut h = vec![
            0x45, // v4, IHL 5
            0x00, // DSCP/ECN
            0x00, 0x00, // total length (unused by slice)
        ];
        h.extend_from_slice(&id.to_be_bytes());
        let frag = (offset_units & 0x1FFF) | if mf { 0x2000 } else { 0 };
        h.extend_from_slice(&frag.to_be_bytes());
        h.push(64); // TTL
        h.push(17); // protocol = UDP
        h.extend_from_slice(&[0, 0]); // checksum (unchecked)
        h.extend_from_slice(&[10, 0, 0, 1]); // src
        h.extend_from_slice(&[10, 0, 0, 2]); // dst
        h.extend_from_slice(payload);
        h
    }

    #[cfg(feature = "extractors")]
    #[test]
    fn push_ipv4_extracts_key_and_reassembles() {
        use crate::layers::Ipv4Slice;
        let mut r = IpFragmentReassembler::new();
        // Fragment 1: offset 0 (0 units), MF=1, 8 bytes.
        let f1 = ipv4_fragment(7, 0, true, b"AAAAAAAA");
        assert!(r.push_ipv4(&Ipv4Slice::new(&f1, 20), t(0)).is_none());
        // Fragment 2: offset 8 (1 unit), MF=0 → completes.
        let f2 = ipv4_fragment(7, 1, false, b"BBBB");
        let out = r.push_ipv4(&Ipv4Slice::new(&f2, 20), t(0)).unwrap();
        assert_eq!(out, b"AAAAAAAABBBB");
        assert_eq!(r.reassembled(), 1);
    }

    #[test]
    fn oversize_far_offset_dropped() {
        let cfg = FragmentConfig {
            max_datagram_bytes: 1000,
            ..FragmentConfig::default()
        };
        let mut r = IpFragmentReassembler::with_config(cfg);
        // A fragment claiming offset 2000 exceeds the 1000-byte cap.
        assert!(r.push(key(), 2000, false, b"Z", t(0)).is_none());
        assert_eq!(r.oversize_dropped(), 1);
    }
}

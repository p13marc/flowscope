//! [`QuicUdpParser`] — `DatagramParser` over UDP/443 with
//! cross-datagram ClientHello reassembly (issue #135).

use std::time::Duration;

use quic_parser::reassemble_crypto_stream;

use super::parser::{CryptoFrame, build_from_stream, decode_frames};
use super::types::QuicInitial;
use crate::Timestamp;
use crate::event::FlowSide;
use crate::session::DatagramParser;

/// The IANA-assigned QUIC port. Real-world deployments may
/// also use 80 (h3 over alternate-svc) and arbitrary ports;
/// route additional ports yourself via the typed driver.
pub const QUIC_PORT: u16 = 443;

/// Bounds on [`QuicUdpParser`]'s cross-datagram reassembly state.
///
/// Every field is a defence against a peer that sends Initials
/// which never complete a ClientHello. The defaults are sized for
/// real traffic with headroom: a post-quantum ClientHello is
/// ~1.6 KiB carried in two or three Initials, so an attempt needing
/// 64 KiB or 64 frames is not a handshake.
///
/// Construct with [`Default::default`] and the `with_*` builders —
/// the struct is `#[non_exhaustive]`, so new bounds can be added
/// without a breaking change.
///
/// ```
/// use flowscope::quic::{QuicConfig, QuicUdpParser};
///
/// let parser = QuicUdpParser::with_config(
///     QuicConfig::default()
///         .with_max_pending_connections(256)
///         .with_max_crypto_bytes(16 * 1024),
/// );
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct QuicConfig {
    /// Max concurrent in-flight Initials tracked for reassembly.
    /// At capacity the least-recently-advanced entry is evicted.
    /// Default 1024.
    pub max_pending_connections: usize,
    /// How long an incomplete Initial's frames are retained. The
    /// clock only advances on *progress* — a peer replaying frames
    /// that never extend the contiguous stream cannot hold an entry
    /// open. Default 5 s (a connection attempt is short-lived).
    pub pending_ttl: Duration,
    /// Max CRYPTO bytes accumulated for one connection. Default
    /// 64 KiB, against a ~1.6 KiB post-quantum ClientHello.
    pub max_crypto_bytes: usize,
    /// Max CRYPTO frames accumulated for one connection. Default
    /// 64.
    ///
    /// This is not redundant with [`Self::max_crypto_bytes`]:
    /// reassembly re-sorts the frame list on every datagram, so
    /// 65 536 one-byte frames would stay under a 64 KiB byte cap
    /// while making the work quadratic. The frame cap is what
    /// bounds the CPU.
    pub max_crypto_frames: usize,
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            max_pending_connections: 1024,
            pending_ttl: Duration::from_secs(5),
            max_crypto_bytes: 64 * 1024,
            max_crypto_frames: 64,
        }
    }
}

impl QuicConfig {
    /// Set [`Self::max_pending_connections`].
    #[must_use]
    pub fn with_max_pending_connections(mut self, n: usize) -> Self {
        self.max_pending_connections = n;
        self
    }

    /// Set [`Self::pending_ttl`].
    #[must_use]
    pub fn with_pending_ttl(mut self, ttl: Duration) -> Self {
        self.pending_ttl = ttl;
        self
    }

    /// Set [`Self::max_crypto_bytes`].
    #[must_use]
    pub fn with_max_crypto_bytes(mut self, bytes: usize) -> Self {
        self.max_crypto_bytes = bytes;
        self
    }

    /// Set [`Self::max_crypto_frames`].
    #[must_use]
    pub fn with_max_crypto_frames(mut self, n: usize) -> Self {
        self.max_crypto_frames = n;
        self
    }
}

/// Accumulated CRYPTO frames for one connection's ClientHello,
/// keyed by the client-chosen Destination Connection ID (stable
/// across the client's Initial packets in one attempt).
#[derive(Clone)]
struct Pending {
    frames: Vec<CryptoFrame>,
    /// Sum of `frames[..].data.len()`, kept incrementally so the
    /// byte cap costs nothing to check.
    bytes: usize,
    /// Length of the contiguous reassembled prefix as of the last
    /// datagram. Progress — not arrival — is what refreshes
    /// `last_seen`.
    prefix_len: usize,
    last_seen: Timestamp,
}

/// QUIC Initial parser with cross-datagram CRYPTO reassembly.
///
/// A modern (post-quantum) ClientHello is ~1.4–1.6 KiB and does
/// not fit one QUIC Initial, so clients split it across two
/// Initial packets. This parser accumulates each connection's
/// CRYPTO frames (keyed by DCID) and, once the reassembled stream
/// yields a complete ClientHello, emits a [`QuicInitial`] carrying
/// the SNI / ALPN / full ClientHello. A single-Initial ClientHello
/// (the common non-PQ case) still emits immediately.
///
/// State is bounded by [`QuicConfig`] on every axis a hostile peer
/// controls: how many connections are tracked, how long each is
/// kept, and how many CRYPTO bytes and frames one connection may
/// accumulate. Frames past a cap are discarded and counted in
/// [`pending_dropped`](Self::pending_dropped) rather than silently
/// tolerated.
#[derive(Default, Clone)]
pub struct QuicUdpParser {
    config: QuicConfig,
    pending: Vec<(Vec<u8>, Pending)>,
    pending_dropped: u64,
}

impl QuicUdpParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build with non-default bounds. See [`QuicConfig`].
    pub fn with_config(config: QuicConfig) -> Self {
        Self {
            config,
            pending: Vec::new(),
            pending_dropped: 0,
        }
    }

    /// Connections currently held for reassembly. Bounded by
    /// [`QuicConfig::max_pending_connections`].
    pub fn tracked(&self) -> usize {
        self.pending.len()
    }

    /// CRYPTO frames discarded because a bound was reached —
    /// capacity eviction, the per-connection byte cap, or the frame
    /// cap. A number that climbs under load means either the caps
    /// are too tight for the traffic or somebody is feeding the
    /// parser Initials that never complete.
    pub fn pending_dropped(&self) -> u64 {
        self.pending_dropped
    }

    /// Drop pending Initials older than the TTL relative to `now`.
    fn evict_stale(&mut self, now: Timestamp) {
        let ttl = self.config.pending_ttl;
        let dropped = &mut self.pending_dropped;
        self.pending.retain(|(_, p)| {
            let alive = now.to_duration().saturating_sub(p.last_seen.to_duration()) <= ttl;
            if !alive {
                *dropped += p.frames.len() as u64;
            }
            alive
        });
    }

    /// Merge this datagram's frames into the per-DCID accumulator
    /// and return the reassembled CRYPTO stream so far.
    fn accumulate(&mut self, dcid: Vec<u8>, frames: Vec<CryptoFrame>, ts: Timestamp) -> Vec<u8> {
        let max_bytes = self.config.max_crypto_bytes;
        let max_frames = self.config.max_crypto_frames;

        if let Some((_, p)) = self.pending.iter_mut().find(|(k, _)| *k == dcid) {
            for f in frames {
                if p.frames.len() >= max_frames || p.bytes + f.data.len() > max_bytes {
                    // Refuse rather than truncate: a partial frame
                    // would reassemble into a ClientHello that was
                    // never sent.
                    self.pending_dropped += 1;
                    continue;
                }
                p.bytes += f.data.len();
                p.frames.push(f);
            }
            let stream = reassemble_crypto_stream(&p.frames);
            // Refresh the TTL only when the contiguous prefix grew.
            // Refreshing on arrival would let a peer replaying the
            // same frames hold an entry open forever, which is what
            // the TTL exists to prevent (issue #184).
            if stream.len() > p.prefix_len {
                p.prefix_len = stream.len();
                p.last_seen = ts;
            }
            stream
        } else {
            // New connection. Bound the table before inserting,
            // evicting whichever entry has gone longest without
            // making progress.
            if self.pending.len() >= self.config.max_pending_connections
                && let Some(idx) = self
                    .pending
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, (_, p))| p.last_seen.to_duration())
                    .map(|(i, _)| i)
            {
                self.pending_dropped += self.pending[idx].1.frames.len() as u64;
                self.pending.remove(idx);
            }
            let mut kept: Vec<CryptoFrame> = Vec::new();
            let mut bytes = 0usize;
            for f in frames {
                if kept.len() >= max_frames || bytes + f.data.len() > max_bytes {
                    self.pending_dropped += 1;
                    continue;
                }
                bytes += f.data.len();
                kept.push(f);
            }
            let stream = reassemble_crypto_stream(&kept);
            self.pending.push((
                dcid,
                Pending {
                    frames: kept,
                    bytes,
                    prefix_len: stream.len(),
                    last_seen: ts,
                },
            ));
            stream
        }
    }

    /// Once a ClientHello has been extracted for a DCID, drop its
    /// pending buffer — subsequent Initials on the same DCID
    /// (retransmits) don't need re-accumulation.
    fn forget(&mut self, dcid: &[u8]) {
        self.pending.retain(|(k, _)| k != dcid);
    }
}

impl DatagramParser for QuicUdpParser {
    type Message = QuicInitial;

    fn parser_kind(&self) -> crate::ParserKind {
        crate::ParserKind::Quic
    }

    fn parse(
        &mut self,
        payload: &[u8],
        _side: FlowSide,
        ts: Timestamp,
        out: &mut Vec<Self::Message>,
    ) {
        let Ok((meta, frames)) = decode_frames(payload) else {
            return;
        };
        let dcid = meta.dcid.clone();
        let stream = self.accumulate(dcid.clone(), frames, ts);
        let initial = build_from_stream(meta, &stream);

        // If we now have a full ClientHello, this connection is done
        // reassembling — release its buffer.
        if client_hello_complete(&initial) {
            self.forget(&dcid);
        }
        out.push(initial);
    }

    fn on_tick(&mut self, now: Timestamp, _out: &mut Vec<Self::Message>) {
        self.evict_stale(now);
    }
}

/// Did we extract a usable ClientHello (SNI or ALPN present, or —
/// under `tls` — the full ClientHello)?
fn client_hello_complete(initial: &QuicInitial) -> bool {
    #[cfg(feature = "tls")]
    {
        initial.client_hello.is_some()
    }
    #[cfg(not(feature = "tls"))]
    {
        initial.sni.is_some() || !initial.alpn.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_kind_and_port() {
        let p = QuicUdpParser::new();
        assert_eq!(p.parser_kind().as_str(), "quic");
        assert_eq!(QUIC_PORT, 443);
    }

    #[test]
    fn empty_payload_yields_no_message() {
        let mut p = QuicUdpParser::new();
        let mut out = Vec::new();
        p.parse(&[], FlowSide::Initiator, Timestamp::default(), &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn accumulate_reassembles_crypto_across_datagrams() {
        // The heart of #135: two Initials, each carrying half the
        // ClientHello's CRYPTO stream, reassemble into the whole.
        let mut p = QuicUdpParser::new();
        let dcid = vec![9u8; 8];
        // Datagram 1 — offset 0, incomplete (a gap remains after it).
        let s1 = p.accumulate(
            dcid.clone(),
            vec![CryptoFrame {
                offset: 0,
                data: b"hello ".to_vec(),
            }],
            Timestamp::new(1, 0),
        );
        assert_eq!(s1, b"hello ");
        // Datagram 2 — offset 6, completes the contiguous stream.
        let s2 = p.accumulate(
            dcid.clone(),
            vec![CryptoFrame {
                offset: 6,
                data: b"world".to_vec(),
            }],
            Timestamp::new(2, 0),
        );
        assert_eq!(s2, b"hello world", "frames from both datagrams joined");
        // Same DCID accumulates; a different DCID is independent.
        let other = p.accumulate(
            vec![7u8; 8],
            vec![CryptoFrame {
                offset: 0,
                data: b"xyz".to_vec(),
            }],
            Timestamp::new(3, 0),
        );
        assert_eq!(other, b"xyz");
    }

    #[test]
    fn on_tick_evicts_stale_pending() {
        // Directly exercise the eviction bookkeeping without needing
        // a real decryptable Initial: seed a pending entry, then tick
        // past the TTL.
        let mut p = QuicUdpParser::new();
        p.pending.push((
            vec![1, 2, 3, 4],
            Pending {
                frames: Vec::new(),
                bytes: 0,
                prefix_len: 0,
                last_seen: Timestamp::new(0, 0),
            },
        ));
        assert_eq!(p.pending.len(), 1);
        let mut out = Vec::new();
        p.on_tick(Timestamp::new(10, 0), &mut out);
        assert_eq!(p.pending.len(), 0, "stale pending evicted after TTL");
    }

    fn frame(offset: u64, len: usize) -> CryptoFrame {
        CryptoFrame {
            offset,
            data: vec![0xAB; len],
        }
    }

    /// Issue #184: a peer replaying frames that never extend the
    /// contiguous stream must not keep its entry alive.
    ///
    /// `last_seen` used to be refreshed on arrival, so `evict_stale`
    /// could never reach an actively-fed DCID — the TTL was
    /// unreachable exactly for the traffic it was meant to bound.
    #[test]
    fn replaying_the_same_frames_does_not_refresh_the_ttl() {
        let mut p = QuicUdpParser::new();
        let dcid = vec![1u8; 8];

        p.accumulate(dcid.clone(), vec![frame(0, 16)], Timestamp::new(0, 0));
        assert_eq!(p.tracked(), 1);

        // Keep replaying the identical frame well past the TTL.
        for sec in 1..20 {
            p.accumulate(dcid.clone(), vec![frame(0, 16)], Timestamp::new(sec, 0));
        }
        p.on_tick(Timestamp::new(20, 0), &mut Vec::new());
        assert_eq!(
            p.tracked(),
            0,
            "an entry that never made progress must age out"
        );
    }

    /// Progress, by contrast, does refresh it — a genuinely
    /// multi-datagram ClientHello must not be evicted mid-flight.
    #[test]
    fn progress_refreshes_the_ttl() {
        let mut p = QuicUdpParser::new();
        let dcid = vec![2u8; 8];
        p.accumulate(dcid.clone(), vec![frame(0, 16)], Timestamp::new(0, 0));
        // A frame that extends the contiguous prefix, arriving late.
        p.accumulate(dcid.clone(), vec![frame(16, 16)], Timestamp::new(9, 0));
        p.on_tick(Timestamp::new(11, 0), &mut Vec::new());
        assert_eq!(p.tracked(), 1, "the attempt is still advancing");
    }

    /// Bytes accumulated for one connection are capped.
    #[test]
    fn crypto_bytes_are_capped_per_connection() {
        let mut p = QuicUdpParser::with_config(
            QuicConfig::default()
                .with_max_crypto_bytes(1024)
                .with_max_crypto_frames(1000),
        );
        let dcid = vec![3u8; 8];
        for i in 0..64u64 {
            p.accumulate(
                dcid.clone(),
                vec![frame(i * 100, 100)],
                Timestamp::new(1, 0),
            );
        }
        let held: usize = p.pending[0].1.bytes;
        assert!(held <= 1024, "held {held} bytes, cap is 1024");
        assert!(p.pending_dropped() > 0, "and the refusals are counted");
    }

    /// The frame cap is the one that bounds the quadratic: reassembly
    /// re-sorts the frame list on every datagram, so many tiny frames
    /// are the expensive shape even though they are cheap in bytes.
    #[test]
    fn crypto_frames_are_capped_per_connection() {
        let mut p = QuicUdpParser::with_config(
            QuicConfig::default()
                .with_max_crypto_frames(8)
                .with_max_crypto_bytes(1024 * 1024),
        );
        let dcid = vec![4u8; 8];
        for i in 0..500u64 {
            p.accumulate(dcid.clone(), vec![frame(i, 1)], Timestamp::new(1, 0));
        }
        assert_eq!(p.pending[0].1.frames.len(), 8);
        assert_eq!(p.pending_dropped(), 492);
    }

    /// A flood of distinct DCIDs is bounded by the table cap, and the
    /// entry evicted is the one that has gone longest without
    /// progress.
    #[test]
    fn distinct_connections_are_capped() {
        let mut p =
            QuicUdpParser::with_config(QuicConfig::default().with_max_pending_connections(16));
        for i in 0..1000u32 {
            p.accumulate(
                i.to_be_bytes().to_vec(),
                vec![frame(0, 64)],
                Timestamp::new(1 + i, 0),
            );
        }
        assert_eq!(p.tracked(), 16);
        assert!(p.pending_dropped() > 0);
    }
}

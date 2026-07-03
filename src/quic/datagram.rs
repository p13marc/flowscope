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

/// Max concurrent in-flight Initials tracked for reassembly.
const DEFAULT_MAX_PENDING: usize = 1024;
/// How long an incomplete Initial's frames are retained before
/// eviction (a connection attempt is short-lived).
const DEFAULT_PENDING_TTL: Duration = Duration::from_secs(5);

/// Accumulated CRYPTO frames for one connection's ClientHello,
/// keyed by the client-chosen Destination Connection ID (stable
/// across the client's Initial packets in one attempt).
#[derive(Clone)]
struct Pending {
    frames: Vec<CryptoFrame>,
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
/// State is bounded (`DEFAULT_MAX_PENDING` connections, a 5 s TTL
/// swept on [`on_tick`](DatagramParser::on_tick) and inline on
/// overflow), so a flood of one-packet Initials can't grow memory.
#[derive(Default, Clone)]
pub struct QuicUdpParser {
    pending: Vec<(Vec<u8>, Pending)>,
}

impl QuicUdpParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop pending Initials older than the TTL relative to `now`.
    fn evict_stale(&mut self, now: Timestamp) {
        self.pending.retain(|(_, p)| {
            now.to_duration().saturating_sub(p.last_seen.to_duration()) <= DEFAULT_PENDING_TTL
        });
    }

    /// Merge this datagram's frames into the per-DCID accumulator
    /// and return the reassembled CRYPTO stream so far.
    fn accumulate(&mut self, dcid: Vec<u8>, frames: Vec<CryptoFrame>, ts: Timestamp) -> Vec<u8> {
        if let Some((_, p)) = self.pending.iter_mut().find(|(k, _)| *k == dcid) {
            p.frames.extend(frames);
            p.last_seen = ts;
            reassemble_crypto_stream(&p.frames)
        } else {
            // New connection. Bound the table before inserting.
            if self.pending.len() >= DEFAULT_MAX_PENDING
                && let Some(idx) = self
                    .pending
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, (_, p))| p.last_seen.to_duration())
                    .map(|(i, _)| i)
            {
                self.pending.remove(idx);
            }
            let stream = reassemble_crypto_stream(&frames);
            self.pending.push((
                dcid,
                Pending {
                    frames,
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
                last_seen: Timestamp::new(0, 0),
            },
        ));
        assert_eq!(p.pending.len(), 1);
        let mut out = Vec::new();
        p.on_tick(Timestamp::new(10, 0), &mut out);
        assert_eq!(p.pending.len(), 0, "stale pending evicted after TTL");
    }
}

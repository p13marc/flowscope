// SPDX-License-Identifier: LicenseRef-FoxIO-1.1
//
// JA4SSH is part of the JA4+ suite, (c) FoxIO, LLC, licensed under the FoxIO
// License 1.1 (see LICENSE-FoxIO-1.1 and NOTICE at the crate root) — NOT under
// flowscope's MIT/Apache-2.0 terms. JA4+ methods are patent pending. "JA4+" is
// a trademark of FoxIO, LLC. This file compiles only under the opt-in `ja4plus`
// feature; commercial use requires a FoxIO OEM license.

//! JA4SSH SSH-traffic fingerprint (FoxIO).
//!
//! Where [HASSH](super::compute_hassh) fingerprints the SSH *handshake*
//! (KEXINIT algorithm lists), JA4SSH fingerprints the *encrypted session* — it
//! reveals what kind of traffic is flowing inside an SSH tunnel (interactive
//! shell vs file transfer vs tunneled protocol) without decrypting anything, by
//! summarising packet sizes and ACK patterns over a rolling window.
//!
//! Format (FoxIO): `c{Cm}s{Sm}_c{Cp}s{Sp}_c{Ca}s{Sa}` where, over each window
//! of `packet_count` (default 200) payload-bearing packets:
//! - `Cm` / `Sm` — the **mode** (most common) client/server TCP payload length
//!   (ties broken toward the smaller length),
//! - `Cp` / `Sp` — the number of client/server payload packets,
//! - `Ca` / `Sa` — the number of client/server **pure-ACK** packets (zero
//!   payload, ACK-only flags).
//!
//! Feed every TCP packet of the SSH flow to [`Ja4sshAccumulator::record`]; it
//! returns `Some(fingerprint)` each time a window fills. Call
//! [`Ja4sshAccumulator::finish`] at flow end to flush the final partial window.
//! "Client" = connection initiator (orig); "server" = responder (resp).
//!
//! Reference: FoxIO `zeek/ja4ssh/main.zeek`. The golden vectors below are from
//! FoxIO's own Zeek `ja4ssh.log` test baseline.
//!
//! Issue #77.

use std::collections::HashMap;

/// Default JA4SSH window: emit a fingerprint every 200 payload packets.
pub const DEFAULT_PACKET_COUNT: usize = 200;

/// Pure-ACK TCP flags value (ACK bit only).
const TCP_ACK_ONLY: u8 = 0x10;

/// Rolling JA4SSH accumulator. One per SSH flow.
#[derive(Debug, Clone)]
pub struct Ja4sshAccumulator {
    packet_count: usize,
    client_lens: Vec<u32>,
    server_lens: Vec<u32>,
    client_acks: u32,
    server_acks: u32,
}

impl Default for Ja4sshAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl Ja4sshAccumulator {
    /// New accumulator with the default 200-packet window.
    pub fn new() -> Self {
        Self::with_packet_count(DEFAULT_PACKET_COUNT)
    }

    /// New accumulator emitting a fingerprint every `packet_count`
    /// payload-bearing packets (`packet_count` is clamped to at least 1).
    pub fn with_packet_count(packet_count: usize) -> Self {
        Self {
            packet_count: packet_count.max(1),
            client_lens: Vec::new(),
            server_lens: Vec::new(),
            client_acks: 0,
            server_acks: 0,
        }
    }

    /// Record one TCP packet of the SSH flow.
    ///
    /// - `from_client` — `true` if the packet is initiator→responder.
    /// - `payload_len` — TCP payload length (0 for a bare ACK).
    /// - `tcp_flags` — the TCP flags byte (used to spot pure ACKs).
    ///
    /// Returns `Some(fingerprint)` when this packet completes a window (and
    /// resets the window), else `None`.
    pub fn record(&mut self, from_client: bool, payload_len: u32, tcp_flags: u8) -> Option<String> {
        if payload_len > 0 {
            if from_client {
                self.client_lens.push(payload_len);
            } else {
                self.server_lens.push(payload_len);
            }
        } else if tcp_flags == TCP_ACK_ONLY {
            if from_client {
                self.client_acks += 1;
            } else {
                self.server_acks += 1;
            }
        }

        if self.client_lens.len() + self.server_lens.len() >= self.packet_count {
            Some(self.emit())
        } else {
            None
        }
    }

    /// Flush the current (partial) window at flow end. Returns `None` if no
    /// packets have been recorded since the last emission.
    pub fn finish(&mut self) -> Option<String> {
        if self.client_lens.is_empty()
            && self.server_lens.is_empty()
            && self.client_acks == 0
            && self.server_acks == 0
        {
            return None;
        }
        Some(self.emit())
    }

    /// Format the current window and reset it.
    fn emit(&mut self) -> String {
        let fp = format!(
            "c{}s{}_c{}s{}_c{}s{}",
            mode(&self.client_lens),
            mode(&self.server_lens),
            self.client_lens.len(),
            self.server_lens.len(),
            self.client_acks,
            self.server_acks,
        );
        self.client_lens.clear();
        self.server_lens.clear();
        self.client_acks = 0;
        self.server_acks = 0;
        fp
    }
}

/// Most frequent value; ties broken toward the smaller value; `0` for empty
/// (matching the FoxIO reference's `get_mode`).
fn mode(values: &[u32]) -> u32 {
    if values.is_empty() {
        return 0;
    }
    let mut freqs: HashMap<u32, u32> = HashMap::new();
    for &v in values {
        *freqs.entry(v).or_insert(0) += 1;
    }
    let max = freqs.values().copied().max().unwrap_or(0);
    freqs
        .iter()
        .filter(|&(_, &f)| f == max)
        .map(|(&v, _)| v)
        .min()
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn golden_window_c36s36_c76s124_c74s5() {
        // FoxIO ja4ssh.log baseline line 1: c36s36_c76s124_c74s5.
        // 76 client + 124 server payload packets (len 36) => 200 → emit;
        // 74 client pure-acks + 5 server pure-acks counted in the window.
        let mut acc = Ja4sshAccumulator::new();
        for _ in 0..74 {
            assert_eq!(acc.record(true, 0, TCP_ACK_ONLY), None);
        }
        for _ in 0..5 {
            assert_eq!(acc.record(false, 0, TCP_ACK_ONLY), None);
        }
        for _ in 0..76 {
            assert_eq!(acc.record(true, 36, 0x18), None);
        }
        // 123 server data packets — still under 200 (76+123=199).
        for _ in 0..123 {
            assert_eq!(acc.record(false, 36, 0x18), None);
        }
        // 200th payload packet → emit.
        let fp = acc.record(false, 36, 0x18).expect("window emits at 200");
        assert_eq!(fp, "c36s36_c76s124_c74s5");
        // Window reset.
        assert!(acc.finish().is_none());
    }

    #[test]
    fn mode_ties_break_to_smaller() {
        // freq(10)=2, freq(20)=2 → tie → 10 wins.
        assert_eq!(mode(&[10, 20, 20, 10]), 10);
        assert_eq!(mode(&[]), 0);
        assert_eq!(mode(&[99]), 99);
        // clear winner
        assert_eq!(mode(&[5, 5, 5, 8]), 5);
    }

    #[test]
    fn finish_flushes_partial_window() {
        let mut acc = Ja4sshAccumulator::new();
        acc.record(true, 40, 0x18);
        acc.record(false, 88, 0x18);
        acc.record(true, 0, TCP_ACK_ONLY);
        let fp = acc.finish().expect("partial window flushed");
        assert_eq!(fp, "c40s88_c1s1_c1s0");
        assert!(acc.finish().is_none()); // empty after flush
    }

    #[test]
    fn non_ack_zero_payload_is_ignored() {
        // A zero-payload packet that isn't a pure ACK (e.g. SYN 0x02) is
        // counted neither as payload nor as an ACK.
        let mut acc = Ja4sshAccumulator::new();
        assert_eq!(acc.record(true, 0, 0x02), None);
        assert!(acc.finish().is_none());
    }

    #[test]
    fn custom_window_size() {
        let mut acc = Ja4sshAccumulator::with_packet_count(2);
        assert_eq!(acc.record(true, 100, 0x18), None);
        let fp = acc.record(false, 200, 0x18).expect("emits at 2");
        assert_eq!(fp, "c100s200_c1s1_c0s0");
    }
}

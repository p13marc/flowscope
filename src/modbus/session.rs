//! [`ModbusParser`] — `SessionParser` over TCP/502.

use bytes::BytesMut;

use super::parser::drain_frames;
use super::types::ModbusMessage;
use crate::Timestamp;
use crate::session::SessionParser;

pub const PARSER_KIND: &str = "modbus";

/// IANA-assigned Modbus/TCP port.
pub const MODBUS_PORT: u16 = 502;

/// `SessionParser` for Modbus/TCP. Drains zero or more
/// [`ModbusMessage`]s per feed call. Defensively caps the
/// internal buffer at 64 KiB per direction — a single
/// pathological frame larger than 65 KiB would be the only
/// thing that could occupy more.
#[derive(Debug, Clone, Default)]
pub struct ModbusParser {
    init: BytesMut,
    resp: BytesMut,
    /// Bytes went missing on (initiator, responder): resync on the
    /// next plausible MBAP header.
    resync: [bool; 2],
}

/// Offset of the next plausible MBAP header: protocol id 0, a length
/// of 2..=254 covering unit id + PDU, and a public function code
/// (1..=127, or an exception response 0x81..=0xFF).
fn find_mbap(buf: &[u8]) -> Option<usize> {
    buf.windows(8).position(|w| {
        let len = u16::from_be_bytes([w[4], w[5]]);
        w[2] == 0 && w[3] == 0 && (2..=254).contains(&len) && w[7] != 0 && w[7] != 0x80
    })
}

const MAX_BUFFER: usize = 65_536;

impl ModbusParser {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SessionParser for ModbusParser {
    type Message = ModbusMessage;

    fn parser_kind(&self) -> crate::ParserKind {
        crate::ParserKind::Modbus
    }

    fn feed_initiator(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<Self::Message>) {
        if self.init.len() + bytes.len() > MAX_BUFFER {
            self.init.clear();
        }
        self.init.extend_from_slice(bytes);
        crate::session::resync_frames(&mut self.resync[0], &mut self.init, 7, find_mbap);
        if !self.resync[0] {
            drain_frames(&mut self.init, out);
        }
    }

    fn feed_responder(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<Self::Message>) {
        if self.resp.len() + bytes.len() > MAX_BUFFER {
            self.resp.clear();
        }
        self.resp.extend_from_slice(bytes);
        crate::session::resync_frames(&mut self.resync[1], &mut self.resp, 7, find_mbap);
        if !self.resync[1] {
            drain_frames(&mut self.resp, out);
        }
    }

    /// Drop the partial frame and resume at the next plausible MBAP
    /// header.
    fn on_gap(
        &mut self,
        side: crate::FlowSide,
        _missing: u64,
        _ts: Timestamp,
        _out: &mut Vec<ModbusMessage>,
    ) -> crate::GapResponse {
        let i = usize::from(side == crate::FlowSide::Responder);
        match side {
            crate::FlowSide::Initiator => self.init.clear(),
            crate::FlowSide::Responder => self.resp.clear(),
        }
        self.resync[i] = true;
        crate::GapResponse::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::FlowSide;

    fn ts() -> Timestamp {
        Timestamp::default()
    }

    fn build_read_holding(txn: u16, unit: u8, start: u16, qty: u16) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&txn.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&6u16.to_be_bytes());
        buf.push(unit);
        buf.push(3);
        buf.extend_from_slice(&start.to_be_bytes());
        buf.extend_from_slice(&qty.to_be_bytes());
        buf
    }

    #[test]
    fn parser_kind_label() {
        assert_eq!(ModbusParser::new().parser_kind().as_str(), "modbus");
        assert_eq!(MODBUS_PORT, 502);
    }

    #[test]
    fn split_feed_reassembles_one_frame() {
        let buf = build_read_holding(0x42, 1, 0, 5);
        let mut p = ModbusParser::new();
        let mut out = Vec::new();
        p.feed_initiator(&buf[..5], ts(), &mut out);
        assert!(out.is_empty());
        p.feed_initiator(&buf[5..], ts(), &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].transaction_id, 0x42);
        let _ = FlowSide::Initiator;
    }

    #[test]
    fn pipelined_frames_drain_in_order() {
        let a = build_read_holding(0x01, 1, 0, 2);
        let b = build_read_holding(0x02, 1, 10, 4);
        let mut buf = a.clone();
        buf.extend_from_slice(&b);
        let mut p = ModbusParser::new();
        let mut out = Vec::new();
        p.feed_initiator(&buf, ts(), &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].transaction_id, 0x01);
        assert_eq!(out[1].transaction_id, 0x02);
    }

    #[test]
    fn a_gap_resyncs_on_the_next_mbap_header() {
        let mut p = ModbusParser::new();
        let mut out = Vec::new();
        let f = build_read_holding(7, 1, 100, 2);
        p.feed_initiator(&f[..4], ts(), &mut out);
        let r = p.on_gap(FlowSide::Initiator, 3, ts(), &mut out);
        assert_eq!(r, crate::GapResponse::Continue);
        let mut tail = f[7..].to_vec();
        tail.extend_from_slice(&f);
        p.feed_initiator(&tail, ts(), &mut out);
        assert_eq!(out.len(), 1);
    }
}

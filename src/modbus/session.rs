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
}

const MAX_BUFFER: usize = 65_536;

impl ModbusParser {
    pub fn new() -> Self {
        Self::default()
    }
}

impl SessionParser for ModbusParser {
    type Message = ModbusMessage;

    fn parser_kind(&self) -> &'static str {
        PARSER_KIND
    }

    fn feed_initiator(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<Self::Message>) {
        if self.init.len() + bytes.len() > MAX_BUFFER {
            self.init.clear();
        }
        self.init.extend_from_slice(bytes);
        drain_frames(&mut self.init, out);
    }

    fn feed_responder(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<Self::Message>) {
        if self.resp.len() + bytes.len() > MAX_BUFFER {
            self.resp.clear();
        }
        self.resp.extend_from_slice(bytes);
        drain_frames(&mut self.resp, out);
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
        assert_eq!(ModbusParser::new().parser_kind(), "modbus");
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
}

//! Modbus/TCP wire-format parsing.

use bytes::BytesMut;

use super::types::{ModbusExceptionCode, ModbusFunction, ModbusMessage};

/// MBAP header is 7 bytes (transaction_id 2 + protocol_id 2
/// + length 2 + unit_id 1).
pub(crate) const MBAP_HEADER_LEN: usize = 7;

/// Failure mode for [`parse_one`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// Not enough bytes yet for a complete frame (either the
    /// 7-byte MBAP header or the full `6 + length` frame).
    Incomplete,
    /// The MBAP `protocol_id` field wasn't 0 (the Modbus/TCP
    /// constant).
    BadProtocolId,
    /// The MBAP `length` field was < 2 (minimum unit_id +
    /// function_code).
    InvalidLength,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Incomplete => f.write_str("incomplete Modbus frame (need more bytes)"),
            Self::BadProtocolId => f.write_str("bad Modbus/TCP protocol_id (expected 0)"),
            Self::InvalidLength => f.write_str("invalid Modbus length field (min 2)"),
        }
    }
}

impl std::error::Error for ParseError {}

impl From<ParseError> for crate::Error {
    fn from(e: ParseError) -> Self {
        use crate::error::{ErrorCode, Module};
        let code = match &e {
            ParseError::Incomplete => ErrorCode::Truncated,
            ParseError::BadProtocolId | ParseError::InvalidLength => ErrorCode::Parse,
        };
        crate::Error::with_code(Module::Modbus, code, e.to_string())
    }
}

/// Parse a single Modbus/TCP frame from the front of `buf`.
/// Returns `(message, bytes_consumed)` on success, or a
/// [`ParseError`] when not enough bytes yet or the protocol_id
/// doesn't match the Modbus/TCP constant (0).
pub fn parse_one(buf: &[u8]) -> Result<(ModbusMessage, usize), ParseError> {
    if buf.len() < MBAP_HEADER_LEN {
        return Err(ParseError::Incomplete);
    }
    let transaction_id = u16::from_be_bytes([buf[0], buf[1]]);
    let protocol_id = u16::from_be_bytes([buf[2], buf[3]]);
    let length = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    if protocol_id != 0 {
        return Err(ParseError::BadProtocolId);
    }
    // `length` covers unit_id + function + data, so the
    // total frame is 6 + length.
    let total = 6 + length;
    if buf.len() < total {
        return Err(ParseError::Incomplete);
    }
    if length < 2 {
        // unit_id (1) + function_code (1) minimum.
        return Err(ParseError::InvalidLength);
    }
    let unit_id = buf[6];
    let raw_fn = buf[7];
    let is_exception = (raw_fn & 0x80) != 0;
    let function = ModbusFunction::from_raw(raw_fn);
    let pdu_data = &buf[8..total];

    let (address, quantity, exception_code) = if is_exception {
        let code = pdu_data.first().map(|&b| ModbusExceptionCode::from_raw(b));
        (None, None, code)
    } else {
        decode_request(&function, pdu_data)
    };

    Ok((
        ModbusMessage {
            transaction_id,
            unit_id,
            raw_function_code: raw_fn,
            function,
            is_exception,
            exception_code,
            address,
            quantity,
        },
        total,
    ))
}

/// Decode the address + quantity / value fields for the
/// common request shapes. Returns `(address, quantity, None)`.
fn decode_request(
    fc: &ModbusFunction,
    pdu: &[u8],
) -> (Option<u16>, Option<u16>, Option<ModbusExceptionCode>) {
    let two_u16 = |data: &[u8]| -> Option<(u16, u16)> {
        if data.len() < 4 {
            return None;
        }
        Some((
            u16::from_be_bytes([data[0], data[1]]),
            u16::from_be_bytes([data[2], data[3]]),
        ))
    };
    let address_and_value = match fc {
        // Read fcs: starting_address + quantity_of_coils/registers.
        ModbusFunction::ReadCoils
        | ModbusFunction::ReadDiscreteInputs
        | ModbusFunction::ReadHoldingRegisters
        | ModbusFunction::ReadInputRegisters => two_u16(pdu),
        // Write single: register/coil address + value.
        ModbusFunction::WriteSingleCoil | ModbusFunction::WriteSingleRegister => two_u16(pdu),
        // Write multiple: starting_address + quantity.
        ModbusFunction::WriteMultipleCoils | ModbusFunction::WriteMultipleRegisters => two_u16(pdu),
        // Mask write register: address + and_mask (use as quantity).
        ModbusFunction::MaskWriteRegister => two_u16(pdu),
        _ => None,
    };
    match address_and_value {
        Some((a, q)) => (Some(a), Some(q), None),
        None => (None, None, None),
    }
}

/// Drain as many Modbus/TCP frames from `buf` as possible.
/// Each consumed frame is pushed to `out`. Returns when the
/// buffer is empty or contains an incomplete frame.
pub(crate) fn drain_frames(buf: &mut BytesMut, out: &mut Vec<ModbusMessage>) {
    use bytes::Buf;
    loop {
        let (msg, consumed) = match parse_one(buf) {
            Ok(v) => v,
            Err(_) => return,
        };
        out.push(msg);
        buf.advance(consumed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_read_holding(txn: u16, unit: u8, start: u16, qty: u16) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&txn.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes()); // protocol_id
        buf.extend_from_slice(&6u16.to_be_bytes()); // length
        buf.push(unit);
        buf.push(3); // Read Holding Registers
        buf.extend_from_slice(&start.to_be_bytes());
        buf.extend_from_slice(&qty.to_be_bytes());
        buf
    }

    #[test]
    fn parse_read_holding_request() {
        let buf = build_read_holding(0x1234, 0x01, 0x0064, 0x000a);
        let (msg, consumed) = parse_one(&buf).expect("parse");
        assert_eq!(consumed, buf.len());
        assert_eq!(msg.transaction_id, 0x1234);
        assert_eq!(msg.unit_id, 0x01);
        assert_eq!(msg.function, ModbusFunction::ReadHoldingRegisters);
        assert!(!msg.is_exception);
        assert_eq!(msg.address, Some(0x0064));
        assert_eq!(msg.quantity, Some(10));
    }

    #[test]
    fn parse_exception_response_decodes_code() {
        let mut buf = build_read_holding(0x1234, 0x01, 0x0064, 0x000a);
        // Flip the function code to exception (function | 0x80)
        // and overwrite the data to be a 1-byte exception code.
        let length = 3u16; // unit + function + 1 byte exception
        buf[4..6].copy_from_slice(&length.to_be_bytes());
        buf[7] = 0x83; // 0x03 | 0x80
        buf.truncate(8);
        buf.push(0x02); // Illegal Data Address
        let (msg, _consumed) = parse_one(&buf).expect("parse");
        assert!(msg.is_exception);
        assert_eq!(msg.function, ModbusFunction::ReadHoldingRegisters);
        assert_eq!(
            msg.exception_code,
            Some(ModbusExceptionCode::IllegalDataAddress)
        );
    }

    #[test]
    fn rejects_non_modbus_protocol_id() {
        let mut buf = build_read_holding(0x1234, 0x01, 0x0064, 0x000a);
        buf[2..4].copy_from_slice(&1u16.to_be_bytes());
        assert!(parse_one(&buf).is_err());
    }

    #[test]
    fn rejects_truncated_frame() {
        let mut buf = build_read_holding(0x1234, 0x01, 0x0064, 0x000a);
        buf.pop();
        assert!(parse_one(&buf).is_err());
    }

    #[test]
    fn rejects_too_short_for_header() {
        assert!(parse_one(&[0u8; 5]).is_err());
    }

    #[test]
    fn write_single_coil_decoded_as_address_value() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&6u16.to_be_bytes());
        buf.push(1);
        buf.push(5); // Write Single Coil
        buf.extend_from_slice(&0x00abu16.to_be_bytes()); // address
        buf.extend_from_slice(&0xff00u16.to_be_bytes()); // value: ON
        let (msg, _) = parse_one(&buf).expect("parse");
        assert_eq!(msg.function, ModbusFunction::WriteSingleCoil);
        assert_eq!(msg.address, Some(0x00ab));
        assert_eq!(msg.quantity, Some(0xff00));
    }

    #[test]
    fn unknown_function_is_other_with_value() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&2u16.to_be_bytes());
        buf.push(1);
        buf.push(0x42);
        let (msg, _) = parse_one(&buf).expect("parse");
        assert_eq!(msg.function, ModbusFunction::Other(0x42));
        assert_eq!(msg.address, None);
        assert_eq!(msg.quantity, None);
    }

    #[test]
    fn drain_handles_multiple_frames() {
        let a = build_read_holding(0x0001, 1, 0, 2);
        let b = build_read_holding(0x0002, 1, 10, 2);
        let mut combined = BytesMut::new();
        combined.extend_from_slice(&a);
        combined.extend_from_slice(&b);
        let mut out = Vec::new();
        drain_frames(&mut combined, &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].transaction_id, 0x0001);
        assert_eq!(out[1].transaction_id, 0x0002);
        assert!(combined.is_empty());
    }

    #[test]
    fn drain_stops_at_partial_frame() {
        let a = build_read_holding(0x0001, 1, 0, 2);
        let mut combined = BytesMut::new();
        combined.extend_from_slice(&a);
        combined.extend_from_slice(&a[..5]); // partial second
        let mut out = Vec::new();
        drain_frames(&mut combined, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(combined.len(), 5, "partial bytes preserved for next call");
    }

    #[test]
    fn function_predicates() {
        assert!(ModbusFunction::ReadCoils.is_read());
        assert!(ModbusFunction::WriteSingleCoil.is_write());
        assert!(!ModbusFunction::ReadCoils.is_write());
        assert!(!ModbusFunction::Diagnostics.is_read());
    }
}

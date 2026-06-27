//! Modbus/TCP — TCP/502 passive parser.
//!
//! Gated by the `modbus` Cargo feature. Decodes Modbus/TCP
//! per the Open Modbus 1.1b spec — MBAP header + function
//! code + data. Passive observation is the **only** safe
//! mode for ICS networks; active probing of Modbus devices
//! routinely crashes PLCs.
//!
//! # What this surfaces
//!
//! Each Modbus/TCP frame (one per MBAP header) becomes one
//! [`ModbusMessage`]:
//!
//! - `transaction_id` / `unit_id` — for correlation.
//! - `function_code` — decoded to [`ModbusFunction`].
//! - `is_exception` — `true` when the high bit of the
//!   function code is set (server-side error response).
//! - `exception_code` — populated when `is_exception` is
//!   true (illegal function / data address / data value /
//!   server failure / etc.).
//! - `address` / `quantity` — populated for the common
//!   read/write functions (1/2/3/4 read; 5/6/15/16 write).
//!
//! # Modbus pipelining
//!
//! A single TCP segment can carry multiple MBAP frames;
//! the parser drains them all in order. A single MBAP
//! frame is fully self-describing (the `length` field of
//! the header is the source of truth).
//!
//! # What this is NOT
//!
//! - Modbus/RTU (RS-485 serial) — different framing (CRC).
//!   Trivial to add a separate `modbus-rtu` feature if
//!   someone asks.
//! - DNP3 — a sibling ICS protocol, separately tracked
//!   (note Suricata's DNP3 DoS CVE history; passive
//!   observation only).
//! - Modbus security validation. We do not validate that
//!   coil counts are within range — the spec says servers
//!   must check, we just surface what crosses the wire.
//!
//! Issue #14 (Tier-2 row 6 — ICS).

mod parser;
mod session;
mod types;

pub use parser::{ParseError, parse_one};
pub use session::{MODBUS_PORT, ModbusParser, PARSER_KIND};
pub use types::{ModbusExceptionCode, ModbusFunction, ModbusMessage};

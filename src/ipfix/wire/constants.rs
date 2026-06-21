//! RFC 7011 wire constants.

/// IPFIX protocol version, RFC 7011 §3.1.
pub const IPFIX_VERSION: u16 = 0x000A;

/// Length of the IPFIX Message header (RFC 7011 §3.1) —
/// 16 bytes (version 2 + length 2 + export time 4 +
/// sequence number 4 + observation domain id 4).
pub const MESSAGE_HEADER_LEN: usize = 16;

/// Length of an RFC 7011 §3.3.2 Set header — 4 bytes
/// (set id 2 + length 2).
pub const SET_HEADER_LEN: usize = 4;

/// Length of an RFC 7011 §3.4.1 Template Record's fixed
/// header — 4 bytes (template id 2 + field count 2). Each
/// Field Specifier that follows is 4 or 8 bytes depending
/// on whether the enterprise-bit is set.
pub const TEMPLATE_HEADER_LEN: usize = 4;

/// RFC 7011 §3.4.1 Set ID 2 = Template Set.
pub const SET_ID_TEMPLATE: u16 = 2;

/// RFC 7011 §3.4.2 Set ID 3 = Options Template Set.
pub const SET_ID_OPTIONS_TEMPLATE: u16 = 3;

/// RFC 7011 §3.4.3 Set IDs >= 256 are Data Sets (their ID
/// matches the Template Record they were defined against).
pub const SET_ID_DATA_MIN: u16 = 256;

/// Sentinel field length per RFC 7011 §3.2 — `0xFFFF`
/// means the field is variable-length (a 1- or 3-byte
/// length prefix is emitted before the value on the wire).
pub const FIELD_LENGTH_VARIABLE: u16 = 0xFFFF;

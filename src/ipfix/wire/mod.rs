//! Binary IPFIX wire encoder per RFC 7011 / 7012.
//!
//! Gated by the `ipfix-export` Cargo feature. Turns the
//! typed [`crate::FlowRecord`] into RFC 7011 Message bytes
//! suitable for transport over UDP, SCTP, or a file. The
//! transport layer itself (socket I/O, template
//! retransmission timer, sequence-number bookkeeping across
//! reconnects) is **out of scope** for this module — it
//! produces complete Message byte buffers and trusts the
//! caller to push them on the wire.
//!
//! # Why this is in flowscope
//!
//! flowscope already owns the typed `FlowRecord` and every
//! emitter that produces it. Adding the binary IPFIX
//! emitter here keeps the "every emitter is a view over
//! FlowRecord" invariant intact and avoids inverting the
//! flowscope/netring dependency direction. Pure byte
//! serialization, no runtime requirement.
//!
//! # Quick start
//!
//! ```rust,ignore
//! use flowscope::FlowRecord;
//! use flowscope::ipfix::wire::{
//!     MessageBuilder, TemplateRegistry,
//!     FLOWSCOPE_TEMPLATE_FLOW_IPV4,
//! };
//!
//! let mut reg = TemplateRegistry::new(0xDEAD_BEEF);
//! reg.register(FLOWSCOPE_TEMPLATE_FLOW_IPV4.clone());
//!
//! // Round 1: emit the template definition.
//! let mut msg = MessageBuilder::new(&reg, 1, 1700000000);
//! msg.add_template_set(&[FLOWSCOPE_TEMPLATE_FLOW_IPV4.template_id])?;
//! let bytes = msg.finalize();
//! // Send `bytes` over UDP/SCTP.
//!
//! // Round 2: emit data records under the template.
//! let mut msg = MessageBuilder::new(&reg, 2, 1700000001);
//! msg.add_data_record(&rec, FLOWSCOPE_TEMPLATE_FLOW_IPV4.template_id)?;
//! let bytes = msg.finalize();
//! ```
//!
//! # Limits
//!
//! - Only the most-common abstract types (unsigned8/16/32/64,
//!   ipv4Address, ipv6Address, dateTimeMilliseconds) are
//!   emitted. The exotic IE 351 (`layer2SegmentId`,
//!   8 bytes) plus variable-length string types
//!   (`applicationName`) ship in the default templates'
//!   field list but skip emission with a zero-length
//!   placeholder when absent from the record.
//! - No fixed-MTU truncation logic. Callers building large
//!   messages must check `MessageBuilder::current_length()`
//!   and split themselves.
//! - No Options Templates (Template Set type 3) yet.

mod builder;
mod constants;
mod templates;

pub use builder::{EncodeError, MessageBuilder};
pub use constants::{
    FIELD_LENGTH_VARIABLE, IPFIX_VERSION, MESSAGE_HEADER_LEN, SET_HEADER_LEN, SET_ID_DATA_MIN,
    SET_ID_OPTIONS_TEMPLATE, SET_ID_TEMPLATE, TEMPLATE_HEADER_LEN,
};
pub use templates::{
    FLOWSCOPE_TEMPLATE_FLOW_IPV4, FLOWSCOPE_TEMPLATE_FLOW_IPV6, FieldSpec, TEMPLATE_ID_FLOW_IPV4,
    TEMPLATE_ID_FLOW_IPV6, TemplateDefinition, TemplateRegistry,
};

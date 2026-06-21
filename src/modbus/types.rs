//! Public types for the Modbus parser.

/// One parsed Modbus/TCP frame.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct ModbusMessage {
    /// MBAP transaction identifier — pairs request with reply.
    pub transaction_id: u16,
    /// Unit / server identifier (1-247 for normal servers,
    /// 0 broadcast, 255 gateway-bridge).
    pub unit_id: u8,
    /// Raw function code (1-127 normal, 129-255 exception).
    pub raw_function_code: u8,
    /// Decoded function (vocabulary mapping; `Other(n)`
    /// preserves any value the spec doesn't enumerate).
    pub function: ModbusFunction,
    /// `true` when the high bit of the function code was set
    /// (server-side error response).
    pub is_exception: bool,
    /// For exception responses, the 1-byte exception code.
    /// `None` otherwise.
    pub exception_code: Option<ModbusExceptionCode>,
    /// Starting address / register address for read or write
    /// requests (functions 1-4 + 5-6 + 15-16 + 23 covered).
    /// `None` when the function doesn't carry one.
    pub address: Option<u16>,
    /// Number of coils / registers being read/written, or
    /// the value being written for single-coil/single-register
    /// functions. `None` when not applicable.
    pub quantity: Option<u16>,
}

/// Decoded Modbus function-code vocabulary. The list mirrors
/// the Modbus Application Protocol v1.1b §6 PDU function
/// codes. Values outside the enumerated set are preserved
/// as `Other(u8)`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum ModbusFunction {
    ReadCoils,
    ReadDiscreteInputs,
    ReadHoldingRegisters,
    ReadInputRegisters,
    WriteSingleCoil,
    WriteSingleRegister,
    ReadExceptionStatus,
    Diagnostics,
    GetCommEventCounter,
    GetCommEventLog,
    WriteMultipleCoils,
    WriteMultipleRegisters,
    ReportServerId,
    ReadFileRecord,
    WriteFileRecord,
    MaskWriteRegister,
    ReadWriteMultipleRegisters,
    ReadFifoQueue,
    EncapsulatedInterfaceTransport,
    Other(u8),
}

impl ModbusFunction {
    /// Map a raw function code (strip the exception bit
    /// first) to the enum.
    pub fn from_raw(code: u8) -> Self {
        let base = code & 0x7f;
        match base {
            1 => Self::ReadCoils,
            2 => Self::ReadDiscreteInputs,
            3 => Self::ReadHoldingRegisters,
            4 => Self::ReadInputRegisters,
            5 => Self::WriteSingleCoil,
            6 => Self::WriteSingleRegister,
            7 => Self::ReadExceptionStatus,
            8 => Self::Diagnostics,
            11 => Self::GetCommEventCounter,
            12 => Self::GetCommEventLog,
            15 => Self::WriteMultipleCoils,
            16 => Self::WriteMultipleRegisters,
            17 => Self::ReportServerId,
            20 => Self::ReadFileRecord,
            21 => Self::WriteFileRecord,
            22 => Self::MaskWriteRegister,
            23 => Self::ReadWriteMultipleRegisters,
            24 => Self::ReadFifoQueue,
            43 => Self::EncapsulatedInterfaceTransport,
            n => Self::Other(n),
        }
    }

    /// `true` for the four "read" function codes.
    pub fn is_read(&self) -> bool {
        matches!(
            self,
            Self::ReadCoils
                | Self::ReadDiscreteInputs
                | Self::ReadHoldingRegisters
                | Self::ReadInputRegisters
        )
    }

    /// `true` for the four "write" function codes.
    pub fn is_write(&self) -> bool {
        matches!(
            self,
            Self::WriteSingleCoil
                | Self::WriteSingleRegister
                | Self::WriteMultipleCoils
                | Self::WriteMultipleRegisters
        )
    }
}

/// Modbus exception code vocabulary per Open Modbus 1.1b §7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum ModbusExceptionCode {
    IllegalFunction,
    IllegalDataAddress,
    IllegalDataValue,
    ServerDeviceFailure,
    Acknowledge,
    ServerDeviceBusy,
    MemoryParityError,
    GatewayPathUnavailable,
    GatewayTargetDeviceFailedToRespond,
    Other(u8),
}

impl ModbusExceptionCode {
    pub fn from_raw(code: u8) -> Self {
        match code {
            1 => Self::IllegalFunction,
            2 => Self::IllegalDataAddress,
            3 => Self::IllegalDataValue,
            4 => Self::ServerDeviceFailure,
            5 => Self::Acknowledge,
            6 => Self::ServerDeviceBusy,
            8 => Self::MemoryParityError,
            10 => Self::GatewayPathUnavailable,
            11 => Self::GatewayTargetDeviceFailedToRespond,
            n => Self::Other(n),
        }
    }
}

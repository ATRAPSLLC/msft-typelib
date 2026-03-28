//! [`FuncRecord`] -- zero-copy view of a variable-length `MSFT_FuncRecord`.
//!
//! Each function record describes one method or property accessor within a
//! TypeInfo.  The record layout is:
//!
//! ```text
//! [Info: u32] [DataType: i32] [Flags: u32] [VtableOff: i16] [FuncDescSize: i16]
//! [FKCCIC: u32] [NrArgs: i16] [NrOArgs: i16]
//! [optional attrs 0..N as i32]
//! [per-arg custom data offsets, if FKCCIC bit 12 set]
//! [ParameterInfo entries, nrargs * 12 bytes]
//! ```
//!
//! The optional attributes (in order) are: help context, help string offset,
//! oEntry/DISPID, name offset, help string context, and custom data offset.

use crate::{
    ParameterInfo,
    util::{read_i16_le, read_i32_le, read_u32_le},
};

/// Zero-copy view of a variable-length `MSFT_FuncRecord`.
///
/// The base fixed portion is [`BASE_SIZE`](Self::BASE_SIZE) (0x18) bytes.
/// Optional attribute DWORDs and per-parameter data follow.
///
/// Constructed by [`FuncIter`](crate::FuncIter); the backing slice length
/// equals the record size encoded in the `Info` field.
#[derive(Clone, Copy, Debug)]
pub struct FuncRecord<'a> {
    bytes: &'a [u8],
}

impl<'a> FuncRecord<'a> {
    /// Wraps raw record bytes as a `FuncRecord`.  The caller is responsible
    /// for slicing `bytes` to exactly the record's encoded size.
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Minimum record size (the fixed fields before optional attributes).
    pub const BASE_SIZE: usize = 0x18;

    /// Returns the raw backing bytes for this record.
    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Raw `Info` field at offset 0x00.
    ///
    /// Low 16 bits = record size in bytes; high 16 bits = member index.
    #[inline]
    pub fn info(&self) -> u32 {
        read_u32_le(self.bytes, 0x00).unwrap_or(0)
    }

    /// Record size in bytes (low 16 bits of [`info`](Self::info)).
    #[inline]
    pub fn record_size(&self) -> usize {
        (self.info() & 0xFFFF) as usize
    }

    /// Return type (encoded `DataType` at offset 0x04).
    ///
    /// Negative values encode simple `VT_*` types inline.
    /// Non-negative values are offsets into the type descriptor table.
    #[inline]
    pub fn datatype(&self) -> i32 {
        read_i32_le(self.bytes, 0x04).unwrap_or(-1)
    }

    /// `FUNCFLAG_*` flags at offset 0x08.
    #[inline]
    pub fn flags(&self) -> u32 {
        read_u32_le(self.bytes, 0x08).unwrap_or(0)
    }

    /// VTable slot offset at offset 0x0C.
    #[inline]
    pub fn vtable_offset(&self) -> i16 {
        read_i16_le(self.bytes, 0x0C).unwrap_or(0)
    }

    /// `FUNCDESC` size at offset 0x0E.
    #[inline]
    pub fn funcdesc_size(&self) -> i16 {
        read_i16_le(self.bytes, 0x0E).unwrap_or(0)
    }

    /// `FKCCIC` field at offset 0x10.
    ///
    /// Encodes function kind (bits 0-2), invoke kind (bits 3-6),
    /// calling convention (bits 8-11), and flags (bits 7, 12).
    #[inline]
    pub fn fkccic(&self) -> u32 {
        read_u32_le(self.bytes, 0x10).unwrap_or(0)
    }

    /// `FUNC_*` kind (bits 0-2 of [`fkccic`](Self::fkccic)).
    ///
    /// 0 = Virtual, 1 = PureVirtual, 2 = NonVirtual, 3 = Static, 4 = Dispatch.
    #[inline]
    pub fn func_kind(&self) -> u8 {
        (self.fkccic() & 0x07) as u8
    }

    /// `INVOKE_*` kind (bits 3-6 of [`fkccic`](Self::fkccic)).
    ///
    /// 1 = Func, 2 = PropertyGet, 4 = PropertyPut, 8 = PropertyPutRef.
    #[inline]
    pub fn invoke_kind(&self) -> u8 {
        ((self.fkccic() >> 3) & 0x0F) as u8
    }

    /// Calling convention (bits 8-11 of [`fkccic`](Self::fkccic)).
    ///
    /// 0 = FastCall, 1 = CDecl, 2 = Pascal, 4 = StdCall.
    #[inline]
    pub fn callconv(&self) -> u8 {
        ((self.fkccic() >> 8) & 0x0F) as u8
    }

    /// Number of parameters at offset 0x14.
    #[inline]
    pub fn nrargs(&self) -> i16 {
        read_i16_le(self.bytes, 0x14).unwrap_or(0)
    }

    /// Number of optional parameters at offset 0x16.
    #[inline]
    pub fn nroargs(&self) -> i16 {
        read_i16_le(self.bytes, 0x16).unwrap_or(0)
    }

    /// Number of standard optional-attribute DWORDs between the base
    /// fixed fields and the parameter array.
    ///
    /// The record layout after `BASE_SIZE` is:
    ///
    /// ```text
    /// [standard attrs: 0..6 DWORDs] [arg cust data: nrargs DWORDs if bit 12]
    /// [ParameterInfo: nrargs * 12 bytes]
    /// ```
    ///
    /// This method returns only the count of standard attribute DWORDs
    /// (up to 6), excluding per-argument custom data.
    fn nrattribs(&self) -> usize {
        let size = self.record_size();
        let nrargs = self.nrargs().max(0) as usize;
        let params_size = nrargs * ParameterInfo::SIZE;
        let arg_cust_size = if self.has_arg_cust_data() {
            nrargs * 4
        } else {
            0
        };
        size.saturating_sub(Self::BASE_SIZE)
            .saturating_sub(params_size)
            .saturating_sub(arg_cust_size)
            / 4
    }

    /// Whether this function has custom data (FKCCIC bit 7).
    #[inline]
    pub fn has_cust_data(&self) -> bool {
        self.fkccic() & 0x80 != 0
    }

    /// Whether this function has per-argument custom data (FKCCIC bit 12).
    #[inline]
    pub fn has_arg_cust_data(&self) -> bool {
        self.fkccic() & 0x1000 != 0
    }

    /// Help context (attribute 0, offset 0x18).
    ///
    /// Returns `None` if the record is too short to contain this field.
    pub fn help_context(&self) -> Option<i32> {
        if self.nrattribs() > 0 {
            read_i32_le(self.bytes, 0x18)
        } else {
            None
        }
    }

    /// Help string offset in the string table (attribute 1, offset 0x1C).
    ///
    /// Returns `None` if the record is too short to contain this field.
    pub fn help_string_offset(&self) -> Option<i32> {
        if self.nrattribs() > 1 {
            read_i32_le(self.bytes, 0x1C)
        } else {
            None
        }
    }

    /// `oEntry` / DISPID (attribute 2, offset 0x20).
    ///
    /// For `DISPATCH` interfaces this is the DISPID.
    /// For `MODULE` types this is a name offset or ordinal.
    ///
    /// Returns `None` if the record is too short to contain this field.
    pub fn oentry(&self) -> Option<i32> {
        if self.nrattribs() > 2 {
            read_i32_le(self.bytes, 0x20)
        } else {
            None
        }
    }

    /// Function name offset in the name table (attribute 3, offset 0x24).
    ///
    /// Note: in practice, function names are read from the auxiliary
    /// arrays via [`TypeLib::func_name`](crate::TypeLib::func_name)
    /// rather than from this record attribute.
    ///
    /// Returns `None` if the record is too short to contain this field.
    pub fn name_offset(&self) -> Option<i32> {
        if self.nrattribs() > 3 {
            read_i32_le(self.bytes, 0x24)
        } else {
            None
        }
    }

    /// Help string context (attribute 4, offset 0x28).
    ///
    /// Returns `None` if the record is too short to contain this field.
    pub fn helpstringcontext(&self) -> Option<i32> {
        if self.nrattribs() > 4 {
            read_i32_le(self.bytes, 0x28)
        } else {
            None
        }
    }

    /// Offset into the CDGuids directory for this function's custom data
    /// (attribute 5, offset 0x2C).
    ///
    /// Only meaningful when [`has_cust_data`](Self::has_cust_data) returns `true`.
    ///
    /// Returns `None` if the record is too short to contain this field.
    pub fn cust_data_offset(&self) -> Option<i32> {
        if self.nrattribs() > 5 {
            read_i32_le(self.bytes, 0x2C)
        } else {
            None
        }
    }

    /// Returns the custom data offset for argument `arg_index`.
    ///
    /// The per-argument custom data array follows all optional attributes
    /// (when FKCCIC bit 12 is set). Returns `None` if the function has
    /// no per-argument custom data or the index is out of bounds.
    pub fn arg_cust_data_offset(&self, arg_index: usize) -> Option<i32> {
        if !self.has_arg_cust_data() {
            return None;
        }
        let nrargs = self.nrargs().max(0) as usize;
        if arg_index >= nrargs {
            return None;
        }
        let attrs = self.nrattribs();
        let offset = Self::BASE_SIZE + attrs * 4 + arg_index * 4;
        read_i32_le(self.bytes, offset)
    }
}

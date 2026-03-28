//! [`VarRecord`] -- zero-copy view of a variable-length `MSFT_VarRecord`.
//!
//! Each variable record describes one constant, field, or dispatch property
//! within a TypeInfo.  The record layout is:
//!
//! ```text
//! [Info: u32] [DataType: i32] [Flags: u32] [VarKind: i16] [VarDescSize: i16]
//! [OffsValue: i32]
//! [optional attrs 0..N as i32]
//! ```
//!
//! The optional attributes (in order) are: help context, help string offset,
//! reserved (always -1), custom data offset, and help string context.

use crate::{
    Error,
    util::{read_i16_le, read_i32_le, read_u32_le},
};

/// Zero-copy view of a variable-length `MSFT_VarRecord`.
///
/// The base fixed portion is [`BASE_SIZE`](Self::BASE_SIZE) (0x14) bytes.
/// Optional attribute DWORDs follow.
///
/// Constructed by [`VarIter`](crate::VarIter) or [`VarRecord::from_raw`].
#[derive(Clone, Copy, Debug)]
pub struct VarRecord<'a> {
    bytes: &'a [u8],
}

impl<'a> VarRecord<'a> {
    /// Wraps raw record bytes as a `VarRecord`.  The caller is responsible
    /// for slicing `bytes` to exactly the record's encoded size.
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Minimum record size (the fixed fields).
    pub const BASE_SIZE: usize = 0x14;

    /// Creates a [`VarRecord`] from an already-sliced byte buffer.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooShort`] if `bytes.len() < BASE_SIZE`.
    pub fn from_raw(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < Self::BASE_SIZE {
            return Err(Error::TooShort {
                expected: Self::BASE_SIZE,
                actual: bytes.len(),
                context: "VarRecord",
            });
        }
        Ok(VarRecord { bytes })
    }

    /// Returns the raw backing bytes.
    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Raw `Info` field.
    ///
    /// Low 8 bits = record size in bytes; upper bits = member index.
    #[inline]
    pub fn info(&self) -> u32 {
        read_u32_le(self.bytes, 0x00).unwrap_or(0)
    }

    /// Record size in bytes (low 16 bits of [`info`](Self::info)).
    #[inline]
    pub fn record_size(&self) -> usize {
        (self.info() & 0xFFFF) as usize
    }

    /// Variable type (encoded `DataType`).
    ///
    /// Negative values encode simple `VT_*` types inline.
    /// Non-negative values are offsets into the type descriptor table.
    #[inline]
    pub fn datatype(&self) -> i32 {
        read_i32_le(self.bytes, 0x04).unwrap_or(-1)
    }

    /// `VARFLAG_*` flags.
    #[inline]
    pub fn flags(&self) -> u32 {
        read_u32_le(self.bytes, 0x08).unwrap_or(0)
    }

    /// `VAR_*` kind.
    ///
    /// 0 = `VAR_PERINSTANCE`, 2 = `VAR_CONST`, 3 = `VAR_DISPATCH`.
    #[inline]
    pub fn varkind(&self) -> i16 {
        read_i16_le(self.bytes, 0x0C).unwrap_or(0)
    }

    /// `VARDESC` size.
    #[inline]
    pub fn vardesc_size(&self) -> i16 {
        read_i16_le(self.bytes, 0x0E).unwrap_or(0)
    }

    /// For `VAR_CONST`: inline value or offset into the custom data segment.
    /// For `VAR_PERINSTANCE`: byte offset within the instance.
    #[inline]
    pub fn offs_value(&self) -> i32 {
        read_i32_le(self.bytes, 0x10).unwrap_or(0)
    }

    /// Number of optional attribute DWORDs after the base fixed fields.
    ///
    /// The record layout after `BASE_SIZE` is simply `[attrs: 0..5 DWORDs]`.
    /// Attributes (in order): help context, help string offset, reserved,
    /// custom data offset, help string context.
    fn nrattribs(&self) -> usize {
        self.record_size().saturating_sub(Self::BASE_SIZE) / 4
    }

    /// Help context (attribute 0, offset 0x14).
    ///
    /// Returns `None` if the record is too short to contain this field.
    pub fn help_context(&self) -> Option<i32> {
        if self.nrattribs() > 0 {
            read_i32_le(self.bytes, 0x14)
        } else {
            None
        }
    }

    /// Help string offset (attribute 1, offset 0x18).
    ///
    /// Returns `None` if the record is too short to contain this field.
    pub fn help_string_offset(&self) -> Option<i32> {
        if self.nrattribs() > 1 {
            read_i32_le(self.bytes, 0x18)
        } else {
            None
        }
    }

    /// Reserved field (attribute 2, offset 0x1C).
    ///
    /// Always `-1` in practice. Wine identifies this as `res9`.
    ///
    /// Returns `None` if the record is too short to contain this field.
    pub fn res9(&self) -> Option<i32> {
        if self.nrattribs() > 2 {
            read_i32_le(self.bytes, 0x1C)
        } else {
            None
        }
    }

    /// Offset into the CDGuids directory for this variable's custom data
    /// (attribute 3, offset 0x20).
    ///
    /// Returns `None` if the record is too short to contain this field.
    pub fn cust_data_offset(&self) -> Option<i32> {
        if self.nrattribs() > 3 {
            read_i32_le(self.bytes, 0x20)
        } else {
            None
        }
    }

    /// Help string context (attribute 4, offset 0x24).
    ///
    /// Returns `None` if the record is too short to contain this field.
    pub fn helpstringcontext(&self) -> Option<i32> {
        if self.nrattribs() > 4 {
            read_i32_le(self.bytes, 0x24)
        } else {
            None
        }
    }
}

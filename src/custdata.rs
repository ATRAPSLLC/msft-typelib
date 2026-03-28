//! [`CustDataEntry`] -- custom data GUID directory (segment 12).
//!
//! COM type libraries can attach arbitrary named attributes (custom data)
//! to the library, each TypeInfo, each function, each parameter, and each
//! variable.  These attributes are identified by GUID and carry a variant
//! value stored in the custom-data table (segment 11).
//!
//! The CDGuids directory (segment 12) is a set of 12-byte entries that
//! form hash-chained linked lists.  Given an `oCustData` offset (from
//! the header, a TypeInfo, or a record attribute), you walk the chain
//! via [`CustDataEntry::next`] until it returns `-1`.
//!
//! Use [`TypeLib::resolve_cust_data_entry`](crate::TypeLib::resolve_cust_data_entry)
//! to decode each entry into a `(Guid, ConstValue)` pair.

use crate::util::read_i32_le;

/// One entry in the CDGuids directory (12 bytes).
///
/// Each entry links a GUID to a custom data value and forms a
/// linked list via the [`next`](Self::next) field.
#[derive(Clone, Copy, Debug)]
pub struct CustDataEntry<'a> {
    bytes: &'a [u8],
}

impl<'a> CustDataEntry<'a> {
    /// Wraps a 12-byte slice as a `CustDataEntry`.
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Size of one CDGuids entry in bytes.
    pub const SIZE: usize = 12;

    /// Offset into the GUID table for the attribute's GUID.
    #[inline]
    pub fn guid_offset(&self) -> i32 {
        read_i32_le(self.bytes, 0x00).unwrap_or(-1)
    }

    /// Offset into the custom data segment (segment 11) for the value.
    #[inline]
    pub fn data_offset(&self) -> i32 {
        read_i32_le(self.bytes, 0x04).unwrap_or(-1)
    }

    /// Offset of the next entry in the chain, or `-1` if last.
    #[inline]
    pub fn next(&self) -> i32 {
        read_i32_le(self.bytes, 0x08).unwrap_or(-1)
    }
}

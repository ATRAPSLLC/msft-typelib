//! [`ParameterInfo`] -- zero-copy view of an `MSFT_ParameterInfo` (12 bytes).

use crate::util::{read_i32_le, read_u32_le};

/// Zero-copy view of an `MSFT_ParameterInfo` (12 bytes).
///
/// Each entry describes one parameter of a function: its type, name,
/// and flags (in/out/optional/retval).
///
/// Constructed by [`ParamIter`](crate::ParamIter); the backing slice
/// is guaranteed to be at least [`SIZE`](Self::SIZE) bytes.
#[derive(Clone, Copy, Debug)]
pub struct ParameterInfo<'a> {
    bytes: &'a [u8],
}

impl<'a> ParameterInfo<'a> {
    /// Wraps a 12-byte slice as a `ParameterInfo`.
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Size of one `MSFT_ParameterInfo` in bytes.
    pub const SIZE: usize = 12;

    /// Parameter type (encoded `DataType`).
    ///
    /// Negative values encode simple `VT_*` types inline.
    /// Non-negative values are offsets into the type descriptor table.
    #[inline]
    pub fn datatype(&self) -> i32 {
        read_i32_le(self.bytes, 0x00).unwrap_or(-1)
    }

    /// Offset into the name table for this parameter's name.
    #[inline]
    pub fn name_offset(&self) -> i32 {
        read_i32_le(self.bytes, 0x04).unwrap_or(-1)
    }

    /// `PARAMFLAG_*` flags.
    #[inline]
    pub fn flags(&self) -> u32 {
        read_u32_le(self.bytes, 0x08).unwrap_or(0)
    }

    /// `PARAMFLAG_FIN` (bit 0) -- parameter is an input.
    #[inline]
    pub fn is_in(&self) -> bool {
        self.flags() & 0x01 != 0
    }

    /// `PARAMFLAG_FOUT` (bit 1) -- parameter is an output.
    #[inline]
    pub fn is_out(&self) -> bool {
        self.flags() & 0x02 != 0
    }

    /// `PARAMFLAG_FRETVAL` (bit 3) -- parameter carries the return value.
    #[inline]
    pub fn is_retval(&self) -> bool {
        self.flags() & 0x08 != 0
    }

    /// `PARAMFLAG_FOPT` (bit 4) -- parameter is optional.
    #[inline]
    pub fn is_optional(&self) -> bool {
        self.flags() & 0x10 != 0
    }
}

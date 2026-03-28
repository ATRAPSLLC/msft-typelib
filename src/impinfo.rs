//! [`ImpInfo`] -- zero-copy view of an `MSFT_ImpInfo` (12 bytes).
//!
//! The import-info table (segment 1) lists every type that is referenced
//! from an external type library.  Each 12-byte entry contains flags
//! (including the imported `TYPEKIND`), an offset into the import-files
//! table (segment 2) identifying *which* library, and an offset into the
//! GUID table for the imported type's GUID.
//!
//! Use [`TypeLib::imp_file`](crate::TypeLib::imp_file) to resolve the
//! `imp_file_offset` to an [`ImpFile`](crate::ImpFile) with the library
//! name and version.

use crate::util::{read_i32_le, read_u32_le};

/// Zero-copy view of an `MSFT_ImpInfo` import record (12 bytes).
///
/// Each entry describes one imported type library reference.
#[derive(Clone, Copy, Debug)]
pub struct ImpInfo<'a> {
    bytes: &'a [u8],
}

impl<'a> ImpInfo<'a> {
    /// Wraps a 12-byte slice as an `ImpInfo`.
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Size of one `MSFT_ImpInfo` in bytes.
    pub const SIZE: usize = 12;

    /// Import flags (bits 0-1 = `TKIND`; bit 16 = offset-is-GUID).
    #[inline]
    pub fn flags(&self) -> u32 {
        read_u32_le(self.bytes, 0x00).unwrap_or(0)
    }

    /// Offset into the import-files table.
    #[inline]
    pub fn imp_file_offset(&self) -> i32 {
        read_i32_le(self.bytes, 0x04).unwrap_or(-1)
    }

    /// Offset into the GUID table for this import.
    #[inline]
    pub fn guid_offset(&self) -> i32 {
        read_i32_le(self.bytes, 0x08).unwrap_or(-1)
    }
}

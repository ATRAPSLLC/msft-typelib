//! [`ImpFile`] -- zero-copy view of an import-file entry in segment 2.
//!
//! The import-files table (segment 2) stores one variable-length entry per
//! external type library that this library depends on.  Each entry contains
//! the library's GUID (as an offset into the GUID table), its LCID and
//! version, and its filename.
//!
//! The entry layout is:
//!
//! ```text
//! [GuidOffset: i32] [LCID: i32] [MajVer: u16] [MinVer: u16] [SizeField: u16]
//! [filename bytes, padded to 4-byte alignment]
//! ```
//!
//! The filename length is `SizeField >> 2`; the low 2 bits of `SizeField`
//! are flags.

use crate::util::{read_i32_le, read_u16_le};

/// Zero-copy view of a variable-length import-file entry.
///
/// Each entry describes one imported type library: its GUID, locale,
/// version, and filename.
#[derive(Clone, Copy, Debug)]
pub struct ImpFile<'a> {
    bytes: &'a [u8],
}

impl<'a> ImpFile<'a> {
    /// Minimum header size before the filename (GUID offset + LCID + version + size field).
    pub const HEADER_SIZE: usize = 0x0E;

    /// Wraps a variable-length slice as an `ImpFile`.
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Offset into the GUID table for this imported library's GUID.
    #[inline]
    pub fn guid_offset(&self) -> i32 {
        read_i32_le(self.bytes, 0x00).unwrap_or(-1)
    }

    /// Locale identifier (LCID) of the imported library.
    #[inline]
    pub fn lcid(&self) -> i32 {
        read_i32_le(self.bytes, 0x04).unwrap_or(0)
    }

    /// Major version of the imported library.
    #[inline]
    pub fn major_version(&self) -> u16 {
        read_u16_le(self.bytes, 0x08).unwrap_or(0)
    }

    /// Minor version of the imported library.
    #[inline]
    pub fn minor_version(&self) -> u16 {
        read_u16_le(self.bytes, 0x0A).unwrap_or(0)
    }

    /// Raw size field at offset 0x0C.
    ///
    /// The filename length in bytes is `size_field >> 2`.
    /// The low 2 bits are flags.
    #[inline]
    pub fn size_field(&self) -> u16 {
        read_u16_le(self.bytes, 0x0C).unwrap_or(0)
    }

    /// The filename of the imported library.
    pub fn filename(&self) -> Option<&'a str> {
        let name_len = (self.size_field() >> 2) as usize;
        let name_bytes = self
            .bytes
            .get(Self::HEADER_SIZE..Self::HEADER_SIZE + name_len)?;
        std::str::from_utf8(name_bytes).ok()
    }

    /// Total size of this entry in bytes (header + name, padded to 4-byte alignment).
    pub fn entry_size(&self) -> usize {
        let name_len = (self.size_field() >> 2) as usize;
        let unpadded = Self::HEADER_SIZE + name_len;
        (unpadded + 3) & !3
    }
}

//! [`TypeInfoEntry`] -- zero-copy view of an `MSFT_TypeInfoBase` (0x64 bytes).
//!
//! Each TypeInfo describes one top-level type in the library: an enum,
//! record (struct), module, COM interface, dispatch interface, coclass,
//! alias (typedef), or union.  The 0x64-byte structure contains the type
//! kind, function/variable counts, a GUID, flags, offsets into the name
//! and string tables, version, custom data offset, and more.

use crate::{
    TypeKind,
    util::{read_i16_le, read_i32_le, read_u32_le},
};

/// Zero-copy view of an `MSFT_TypeInfoBase` structure (0x64 bytes).
///
/// Each TypeInfo describes one type in the library: an enum, struct,
/// module, COM interface, dispatch interface, coclass, alias, or union.
///
/// Constructed by [`TypeLib::typeinfo`](crate::TypeLib::typeinfo);
/// the backing slice is guaranteed to be at least [`SIZE`](Self::SIZE) bytes.
#[derive(Clone, Copy, Debug)]
pub struct TypeInfoEntry<'a> {
    bytes: &'a [u8],
}

impl<'a> TypeInfoEntry<'a> {
    /// Wraps a 0x64-byte slice as a `TypeInfoEntry`.
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Size of the fixed `MSFT_TypeInfoBase` structure in bytes.
    pub const SIZE: usize = 0x64;

    /// Returns the raw backing bytes.
    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Type kind (low 4 bits of the `typekind` field).
    #[inline]
    pub fn typekind(&self) -> TypeKind {
        let raw = read_u32_le(self.bytes, 0x00).unwrap_or(0);
        TypeKind::from_raw((raw & 0x0F) as u8)
    }

    /// Raw `typekind` field (includes alignment in bits 11-15).
    #[inline]
    pub fn typekind_raw(&self) -> u32 {
        read_u32_le(self.bytes, 0x00).unwrap_or(0)
    }

    /// Absolute file offset to the func/var data block.
    ///
    /// Returns a negative value when no data block exists.
    #[inline]
    pub fn memoffset(&self) -> i32 {
        read_i32_le(self.bytes, 0x04).unwrap_or(-1)
    }

    /// Reserved field at offset 0x08 (0 for every coclass of the samples;
    /// the first reference is at [`datatype1`](Self::datatype1)).
    #[inline]
    pub fn res2(&self) -> i32 {
        read_i32_le(self.bytes, 0x08).unwrap_or(-1)
    }

    /// Raw `cElement` field.
    ///
    /// Low 16 bits = function count, high 16 bits = variable count.
    #[inline]
    pub fn celement(&self) -> u32 {
        read_u32_le(self.bytes, 0x18).unwrap_or(0)
    }

    /// Number of functions (low 16 bits of `cElement`).
    #[inline]
    pub fn func_count(&self) -> u16 {
        (self.celement() & 0xFFFF) as u16
    }

    /// Number of variables (high 16 bits of `cElement`).
    #[inline]
    pub fn var_count(&self) -> u16 {
        (self.celement() >> 16) as u16
    }

    /// Offset into the GUID table, or `-1` if this type has no GUID.
    #[inline]
    pub fn guid_offset(&self) -> i32 {
        read_i32_le(self.bytes, 0x2C).unwrap_or(-1)
    }

    /// `TYPEFLAG_*` flags.
    #[inline]
    pub fn flags(&self) -> u32 {
        read_u32_le(self.bytes, 0x30).unwrap_or(0)
    }

    /// Offset into the name table for this type's name.
    #[inline]
    pub fn name_offset(&self) -> i32 {
        read_i32_le(self.bytes, 0x34).unwrap_or(-1)
    }

    /// Element version (set with `SetVersion`).
    #[inline]
    pub fn version(&self) -> u32 {
        read_u32_le(self.bytes, 0x38).unwrap_or(0)
    }

    /// Offset into the string table for the doc string, or `-1`.
    #[inline]
    pub fn docstring_offset(&self) -> i32 {
        read_i32_le(self.bytes, 0x3C).unwrap_or(-1)
    }

    /// Number of implemented interfaces (for coclasses).
    #[inline]
    pub fn cimpltypes(&self) -> i16 {
        read_i16_le(self.bytes, 0x4C).unwrap_or(0)
    }

    /// Virtual function table size in bytes.
    #[inline]
    pub fn cb_size_vft(&self) -> i16 {
        read_i16_le(self.bytes, 0x4E).unwrap_or(0)
    }

    /// Instance size in bytes.
    #[inline]
    pub fn size(&self) -> i32 {
        read_i32_le(self.bytes, 0x50).unwrap_or(0)
    }

    /// For `COCLASS` types: the offset in the reference table of the first
    /// implemented interface. For `ALIAS` types: the aliased type
    /// descriptor. Otherwise `-1`.
    #[inline]
    pub fn datatype1(&self) -> i32 {
        read_i32_le(self.bytes, 0x54).unwrap_or(-1)
    }

    /// For `ALIAS` types: secondary aliased type descriptor. Otherwise `-1`.
    #[inline]
    pub fn datatype2(&self) -> i32 {
        read_i32_le(self.bytes, 0x58).unwrap_or(-1)
    }

    /// Help string context at offset 0x40.
    #[inline]
    pub fn helpstringcontext(&self) -> i32 {
        read_i32_le(self.bytes, 0x40).unwrap_or(0)
    }

    /// Help context at offset 0x44.
    #[inline]
    pub fn helpcontext(&self) -> i32 {
        read_i32_le(self.bytes, 0x44).unwrap_or(0)
    }

    /// Offset into the CDGuids directory for this type's custom data, or `-1`.
    #[inline]
    pub fn cust_data_offset(&self) -> i32 {
        read_i32_le(self.bytes, 0x48).unwrap_or(-1)
    }

    /// Reserved field at offset 0x0C (`-1` if no element, else `(N-1)*0x38`).
    #[inline]
    pub fn res3(&self) -> i32 {
        read_i32_le(self.bytes, 0x0C).unwrap_or(-1)
    }

    /// Reserved field at offset 0x5C (always 0).
    #[inline]
    pub fn res18(&self) -> i32 {
        read_i32_le(self.bytes, 0x5C).unwrap_or(0)
    }

    /// Reserved field at offset 0x60 (always `-1`).
    #[inline]
    pub fn res19(&self) -> i32 {
        read_i32_le(self.bytes, 0x60).unwrap_or(-1)
    }
}

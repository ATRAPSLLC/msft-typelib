//! [`GuidEntry`] -- zero-copy view of an `MSFT_GuidEntry` (24 bytes).
//!
//! The GUID table (segment 5) is an array of 24-byte entries.  Each entry
//! stores a 16-byte GUID, an `hreftype` linking it to the TypeInfo that
//! owns the GUID (or `-2` for the library's own GUID), and a hash-chain
//! pointer for the GUID hash table (segment 4).

use crate::{Guid, util::read_i32_le};

/// Zero-copy view of an `MSFT_GuidEntry` (24 bytes) in the GUID table.
///
/// Each entry stores a 16-byte GUID, an `hreftype` linking it to a
/// TypeInfo (or `-2` for the typelib's own GUID), and a hash chain pointer.
#[derive(Clone, Copy, Debug)]
pub struct GuidEntry<'a> {
    bytes: &'a [u8],
}

impl<'a> GuidEntry<'a> {
    /// Wraps a 24-byte slice as a `GuidEntry`.
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Size of one `MSFT_GuidEntry` in bytes.
    pub const SIZE: usize = 24;

    /// The 16-byte GUID value.
    #[inline]
    pub fn guid(&self) -> Guid<'a> {
        Guid::new(self.bytes.get(..16).unwrap_or(&[0; 16]))
    }

    /// `hreftype` of the associated TypeInfo.
    ///
    /// `-2` indicates this is the typelib's own GUID.
    #[inline]
    pub fn hreftype(&self) -> i32 {
        read_i32_le(self.bytes, 16).unwrap_or(-1)
    }

    /// Offset of the next entry in the hash chain, or `-1` if last.
    #[inline]
    pub fn next_hash(&self) -> i32 {
        read_i32_le(self.bytes, 20).unwrap_or(-1)
    }
}

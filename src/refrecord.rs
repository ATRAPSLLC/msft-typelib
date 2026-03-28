//! [`RefRecord`] -- zero-copy view of a reference table entry (16 bytes).
//!
//! The reference table (segment 3) stores the list of interfaces that a
//! coclass implements.  Entries form a singly-linked list via the
//! [`onext`](RefRecord::onext) field; the chain starts at
//! [`TypeInfoEntry::res2`](crate::TypeInfoEntry::res2).  Each entry
//! carries an `hreftype` identifying the implemented interface and
//! `IMPLTYPEFLAG_*` bits (default, source, restricted).

use crate::util::{read_i32_le, read_u32_le};

/// Zero-copy view of a reference table entry (16 bytes).
///
/// Used to describe implemented interfaces on a coclass.
/// Entries form a linked list via [`onext`](Self::onext).
#[derive(Clone, Copy, Debug)]
pub struct RefRecord<'a> {
    bytes: &'a [u8],
}

impl<'a> RefRecord<'a> {
    /// Wraps a 16-byte slice as a `RefRecord`.
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Size of one reference table entry in bytes.
    pub const SIZE: usize = 16;

    /// `hreftype` of the referenced interface.
    #[inline]
    pub fn reftype(&self) -> i32 {
        read_i32_le(self.bytes, 0x00).unwrap_or(-1)
    }

    /// `IMPLTYPEFLAG_*` flags.
    #[inline]
    pub fn flags(&self) -> u32 {
        read_u32_le(self.bytes, 0x04).unwrap_or(0)
    }

    /// Offset of the next entry in the chain, or `-1` if last.
    #[inline]
    pub fn onext(&self) -> i32 {
        read_i32_le(self.bytes, 0x0C).unwrap_or(-1)
    }

    /// `IMPLTYPEFLAG_FDEFAULT` (bit 0).
    #[inline]
    pub fn is_default(&self) -> bool {
        self.flags() & 0x01 != 0
    }

    /// `IMPLTYPEFLAG_FSOURCE` (bit 1).
    #[inline]
    pub fn is_source(&self) -> bool {
        self.flags() & 0x02 != 0
    }

    /// `IMPLTYPEFLAG_FRESTRICTED` (bit 2).
    #[inline]
    pub fn is_restricted(&self) -> bool {
        self.flags() & 0x04 != 0
    }
}

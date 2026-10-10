//! [`ArrayDesc`] -- zero-copy view of an array descriptor in segment 10.
//!
//! When a type descriptor has `VT_CARRAY` (28), the `extra` field is an
//! offset into the array-descriptor table (segment 10).  Each descriptor
//! stores the element type, the number of dimensions, and per-dimension
//! bounds (`count` and `lower_bound`).
//!
//! ```text
//! [element_type: i32] [num_dims: u16] [flags: u16]
//! [SafeArrayBound * num_dims]  -- each: [cElements: u32] [lLbound: i32]
//! ```

use crate::util::{read_i32_le, read_u16_le, read_u32_le};

/// Zero-copy view of a `VT_CARRAY` array descriptor.
///
/// Describes a fixed-size array: its element type, number of dimensions,
/// and bounds for each dimension.
#[derive(Clone, Copy, Debug)]
pub struct ArrayDesc<'a> {
    bytes: &'a [u8],
}

impl<'a> ArrayDesc<'a> {
    /// Wraps a variable-length slice as an `ArrayDesc`.
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Element type descriptor at offset 0x00.
    ///
    /// Negative values encode simple `VT_*` types inline.
    /// Non-negative values are offsets into the type descriptor table.
    #[inline]
    pub fn element_type(&self) -> i32 {
        read_i32_le(self.bytes, 0x00).unwrap_or(-1)
    }

    /// Number of array dimensions.
    #[inline]
    pub fn num_dims(&self) -> u16 {
        read_u16_le(self.bytes, 0x04).unwrap_or(0)
    }

    /// Flags / extra field at offset 0x06.
    #[inline]
    pub fn flags(&self) -> u16 {
        read_u16_le(self.bytes, 0x06).unwrap_or(0)
    }

    /// Returns the bounds for dimension `index`.
    ///
    /// Each bound has a count (number of elements) and a lower bound.
    /// Returns `None` if `index >= num_dims` or the data is too short.
    pub fn bound(&self, index: usize) -> Option<SafeArrayBound> {
        if index >= self.num_dims() as usize {
            return None;
        }
        let base = index.checked_mul(8)?.checked_add(0x08)?;
        let c_elements = read_u32_le(self.bytes, base)?;
        let l_lbound = read_i32_le(self.bytes, base.checked_add(4)?)?;
        Some(SafeArrayBound {
            c_elements,
            l_lbound,
        })
    }

    /// Total size of this descriptor in bytes.
    #[inline]
    pub fn size(&self) -> usize {
        (self.num_dims() as usize)
            .saturating_mul(8)
            .saturating_add(0x08)
    }
}

/// One dimension of a SAFEARRAY descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SafeArrayBound {
    c_elements: u32,
    l_lbound: i32,
}

impl SafeArrayBound {
    /// Number of elements in this dimension.
    #[inline]
    pub fn count(&self) -> u32 {
        self.c_elements
    }

    /// Lower bound of this dimension (starting index).
    #[inline]
    pub fn lower_bound(&self) -> i32 {
        self.l_lbound
    }
}

//! [`Guid`] -- zero-copy view of a 16-byte COM GUID.
//!
//! GUIDs (Globally Unique Identifiers) are 128-bit values used throughout
//! COM to identify interfaces, coclasses, and type libraries.  The on-disk
//! layout is: `Data1` (LE u32) + `Data2` (LE u16) + `Data3` (LE u16) +
//! `Data4` (8 raw bytes).

use crate::util::{read_u16_le, read_u32_le};
use std::fmt;

/// Zero-copy view of a 16-byte COM GUID.
///
/// Layout: `Data1` (LE32) + `Data2` (LE16) + `Data3` (LE16) + `Data4` (8 bytes).
///
/// Display format: `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Guid<'a> {
    bytes: &'a [u8],
}

impl<'a> Guid<'a> {
    /// Wraps a 16-byte slice as a `Guid`.
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    /// Returns the raw 16-byte GUID data.
    #[inline]
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// First GUID component (little-endian `u32` at offset 0).
    #[inline]
    pub fn data1(&self) -> u32 {
        // bytes is always exactly 16 bytes (enforced at construction)
        read_u32_le(self.bytes, 0).unwrap_or(0)
    }

    /// Second GUID component (little-endian `u16` at offset 4).
    #[inline]
    pub fn data2(&self) -> u16 {
        read_u16_le(self.bytes, 4).unwrap_or(0)
    }

    /// Third GUID component (little-endian `u16` at offset 6).
    #[inline]
    pub fn data3(&self) -> u16 {
        read_u16_le(self.bytes, 6).unwrap_or(0)
    }

    /// Last 8 bytes of the GUID (bytes 8..16).
    #[inline]
    pub fn data4(&self) -> &'a [u8] {
        self.bytes.get(8..16).unwrap_or(&[0; 8])
    }
}

impl fmt::Display for Guid<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g, h, i] = <[u8; 8]>::try_from(self.data4()).unwrap_or([0; 8]);
        write!(
            f,
            "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
            self.data1(),
            self.data2(),
            self.data3(),
            a,
            b,
            c,
            d,
            e,
            g,
            h,
            i
        )
    }
}

impl fmt::Debug for Guid<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Guid({})", self)
    }
}

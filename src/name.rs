//! [`NameEntry`] -- a decoded entry from the MSFT name table.
//!
//! The name table (segment 7) stores all identifier names used in the type
//! library.  Each entry has a 12-byte header:
//!
//! ```text
//! [hreftype: i32] [next_hash: i32] [namelen: u8] [flags: u8] [hashcode: u16]
//! [name bytes, padded to 4-byte alignment]
//! ```
//!
//! The `hreftype` links the name to the TypeInfo it belongs to (or `-1`
//! for names without a TypeInfo, such as parameter names).  The
//! `next_hash` and `hashcode` fields support the name hash table
//! (segment 6) for fast lookups.

/// A decoded name table entry yielded by [`NameIter`](crate::NameIter).
pub struct NameEntry<'a> {
    offset: usize,
    name: &'a str,
    hreftype: i32,
    next_hash: i32,
    flags: u8,
    hashcode: u16,
}

impl<'a> NameEntry<'a> {
    /// Creates a `NameEntry` from its decoded components.
    pub(crate) fn new(
        offset: usize,
        name: &'a str,
        hreftype: i32,
        next_hash: i32,
        flags: u8,
        hashcode: u16,
    ) -> Self {
        Self {
            offset,
            name,
            hreftype,
            next_hash,
            flags,
            hashcode,
        }
    }

    /// Byte offset of this entry relative to the name table segment start.
    #[inline]
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// The name string (UTF-8, borrowed from file data).
    #[inline]
    pub fn name(&self) -> &'a str {
        self.name
    }

    /// `hreftype` of the TypeInfo this name belongs to, or `-1` for global names.
    #[inline]
    pub fn hreftype(&self) -> i32 {
        self.hreftype
    }

    /// Offset of the next entry in the name hash chain, or `-1` if last.
    #[inline]
    pub fn next_hash(&self) -> i32 {
        self.next_hash
    }

    /// Flags from the name table header (high byte of the namelen word).
    ///
    /// Known flags: `0x10` = used as variable name, `0x20` = name in enum.
    #[inline]
    pub fn name_flags(&self) -> u8 {
        self.flags
    }

    /// Hash code for this name entry.
    #[inline]
    pub fn hashcode(&self) -> u16 {
        self.hashcode
    }
}

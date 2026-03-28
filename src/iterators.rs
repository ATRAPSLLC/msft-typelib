//! Iterators for traversing MSFT type library structures.
//!
//! Most iterators walk fixed-size or self-describing entries within a
//! segment.  Two use linked-list chains: [`ImplTypeIter`] follows
//! `onext` pointers in the reference table, and [`CustDataIter`]
//! follows `next` pointers in the CDGuids directory.

use crate::{
    CustDataEntry, Error, FuncRecord, GuidEntry, ImpFile, ImpInfo, NameEntry, ParameterInfo,
    RefRecord, TypeInfoEntry, TypeLib, VarRecord,
    util::{read_i32_le, read_u16_le, read_u32_le},
};

/// Iterator over [`TypeInfoEntry`] values in a type library.
///
/// Yields `Result<TypeInfoEntry, Error>` for each entry (index `0..typeinfo_count`).
pub struct TypeInfoIter<'a> {
    lib: &'a TypeLib<'a>,
    index: usize,
}

impl<'a> TypeInfoIter<'a> {
    /// Creates a new iterator starting at index 0.
    pub(crate) fn new(lib: &'a TypeLib<'a>) -> Self {
        Self { lib, index: 0 }
    }
}

impl<'a> Iterator for TypeInfoIter<'a> {
    type Item = Result<TypeInfoEntry<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.index >= self.lib.typeinfo_count() {
            return None;
        }
        let result = self.lib.typeinfo(self.index);
        self.index += 1;
        Some(result)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let rem = self.lib.typeinfo_count() - self.index;
        (rem, Some(rem))
    }
}

/// Iterator over [`FuncRecord`] values within a TypeInfo's func/var data block.
pub struct FuncIter<'a> {
    data: &'a [u8],
    pos: usize,
    end: usize,
    remaining: usize,
}

impl<'a> FuncIter<'a> {
    /// Creates a new iterator over the `[pos..end]` byte range.
    pub(crate) fn new(data: &'a [u8], pos: usize, end: usize, remaining: usize) -> Self {
        Self {
            data,
            pos,
            end,
            remaining,
        }
    }
}

impl<'a> Iterator for FuncIter<'a> {
    type Item = FuncRecord<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 || self.pos >= self.end {
            return None;
        }
        let info_raw = read_u32_le(self.data, self.pos)?;
        let size = (info_raw & 0xFFFF) as usize;
        if size < FuncRecord::BASE_SIZE {
            return None;
        }
        let end = self.pos.checked_add(size)?;
        if end > self.data.len() {
            return None;
        }
        let record = FuncRecord::new(&self.data[self.pos..end]);
        self.pos = end;
        self.remaining -= 1;
        Some(record)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.remaining))
    }
}

/// Iterator over [`VarRecord`] values within a TypeInfo's func/var data block.
pub struct VarIter<'a> {
    data: &'a [u8],
    pos: usize,
    end: usize,
    remaining: usize,
}

impl<'a> VarIter<'a> {
    /// Creates a new iterator over the `[pos..end]` byte range.
    pub(crate) fn new(data: &'a [u8], pos: usize, end: usize, remaining: usize) -> Self {
        Self {
            data,
            pos,
            end,
            remaining,
        }
    }
}

impl<'a> Iterator for VarIter<'a> {
    type Item = VarRecord<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 || self.pos >= self.end {
            return None;
        }
        let info_raw = read_u32_le(self.data, self.pos)?;
        let size = (info_raw & 0xFFFF) as usize;
        if size < VarRecord::BASE_SIZE {
            return None;
        }
        let end = self.pos.checked_add(size)?;
        if end > self.data.len() {
            return None;
        }
        let record = VarRecord::new(&self.data[self.pos..end]);
        self.pos = end;
        self.remaining -= 1;
        Some(record)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (0, Some(self.remaining))
    }
}

/// Iterator over [`ParameterInfo`] entries within a [`FuncRecord`].
pub struct ParamIter<'a> {
    data: &'a [u8],
    pos: usize,
    remaining: usize,
}

impl<'a> ParamIter<'a> {
    /// Creates a new iterator starting at `pos` within `data`.
    pub(crate) fn new(data: &'a [u8], pos: usize, remaining: usize) -> Self {
        Self {
            data,
            pos,
            remaining,
        }
    }
}

impl<'a> Iterator for ParamIter<'a> {
    type Item = ParameterInfo<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let end = self.pos.checked_add(ParameterInfo::SIZE)?;
        if end > self.data.len() {
            return None;
        }
        let param = ParameterInfo::new(&self.data[self.pos..end]);
        self.pos = end;
        self.remaining -= 1;
        Some(param)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.remaining, Some(self.remaining))
    }
}

impl ExactSizeIterator for ParamIter<'_> {}

/// Iterator over [`GuidEntry`] values in the GUID table segment.
pub struct GuidEntryIter<'a> {
    data: &'a [u8],
    pos: usize,
    end: usize,
}

impl<'a> GuidEntryIter<'a> {
    /// Creates a new iterator over the `[pos..end]` byte range.
    pub(crate) fn new(data: &'a [u8], pos: usize, end: usize) -> Self {
        Self { data, pos, end }
    }
}

impl<'a> Iterator for GuidEntryIter<'a> {
    type Item = GuidEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let end = self.pos.checked_add(GuidEntry::SIZE)?;
        if end > self.end || end > self.data.len() {
            return None;
        }
        let entry = GuidEntry::new(&self.data[self.pos..end]);
        self.pos = end;
        Some(entry)
    }
}

/// Iterator over entries in the name table segment.
///
/// Yields [`NameEntry`] values containing the name string, its byte offset,
/// and the `hreftype` linking the name to a TypeInfo.
pub struct NameIter<'a> {
    data: &'a [u8],
    pos: usize,
    end: usize,
    seg_start: usize,
}

impl<'a> NameIter<'a> {
    /// Creates a new iterator over the `[pos..end]` byte range.
    pub(crate) fn new(data: &'a [u8], pos: usize, end: usize, seg_start: usize) -> Self {
        Self {
            data,
            pos,
            end,
            seg_start,
        }
    }
}

impl<'a> Iterator for NameIter<'a> {
    type Item = NameEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        // Header: hreftype(4) + next_hash(4) + namelen(1) + flags(1) + hashcode(2) = 12
        let header_end = self.pos.checked_add(12)?;
        if header_end > self.end || header_end > self.data.len() {
            return None;
        }
        let hreftype = read_i32_le(self.data, self.pos)?;
        let next_hash = read_i32_le(self.data, self.pos + 4)?;
        let namelen = *self.data.get(self.pos + 8)? as usize;
        let flags = *self.data.get(self.pos + 9)?;
        let hashcode = read_u16_le(self.data, self.pos + 10)?;
        let name_start = header_end;
        let name_end = name_start.checked_add(namelen)?;
        if name_end > self.data.len() {
            return None;
        }
        let offset = self.pos - self.seg_start;
        let name = std::str::from_utf8(self.data.get(name_start..name_end)?).ok()?;
        // Advance past name + padding to 4-byte alignment
        let padded = (namelen + 3) & !3;
        self.pos = name_start.checked_add(padded)?;
        Some(NameEntry::new(
            offset, name, hreftype, next_hash, flags, hashcode,
        ))
    }
}

/// Iterator over implemented interfaces for a coclass (via `pRefTab` chain).
///
/// Yields [`RefRecord`] entries following the linked-list chain until
/// an `onext` value of `-1` is reached.
pub struct ImplTypeIter<'a> {
    data: &'a [u8],
    seg_offset: usize,
    next_offset: i32,
}

impl<'a> ImplTypeIter<'a> {
    /// Creates a new iterator starting at `next_offset` in the reference table.
    pub(crate) fn new(data: &'a [u8], seg_offset: usize, next_offset: i32) -> Self {
        Self {
            data,
            seg_offset,
            next_offset,
        }
    }
}

impl<'a> Iterator for ImplTypeIter<'a> {
    type Item = RefRecord<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_offset < 0 {
            return None;
        }
        let abs = self.seg_offset.checked_add(self.next_offset as usize)?;
        let end = abs.checked_add(RefRecord::SIZE)?;
        if end > self.data.len() {
            return None;
        }
        let rec = RefRecord::new(&self.data[abs..end]);
        self.next_offset = rec.onext();
        Some(rec)
    }
}

/// Iterator over [`ImpInfo`] entries in the import-info segment.
pub struct ImpInfoIter<'a> {
    data: &'a [u8],
    pos: usize,
    end: usize,
}

impl<'a> ImpInfoIter<'a> {
    /// Creates a new iterator over the `[pos..end]` byte range.
    pub(crate) fn new(data: &'a [u8], pos: usize, end: usize) -> Self {
        Self { data, pos, end }
    }
}

impl<'a> Iterator for ImpInfoIter<'a> {
    type Item = ImpInfo<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let end = self.pos.checked_add(ImpInfo::SIZE)?;
        if end > self.end || end > self.data.len() {
            return None;
        }
        let entry = ImpInfo::new(&self.data[self.pos..end]);
        self.pos = end;
        Some(entry)
    }
}

/// Iterator over [`ImpFile`] entries in the import-files segment (segment 2).
///
/// Entries are variable-length; each entry's size is derived from its
/// `size_field`.
pub struct ImpFileIter<'a> {
    data: &'a [u8],
    pos: usize,
    end: usize,
}

impl<'a> ImpFileIter<'a> {
    /// Creates a new iterator over variable-length entries in `[pos..end]`.
    pub(crate) fn new(data: &'a [u8], pos: usize, end: usize) -> Self {
        Self { data, pos, end }
    }
}

impl<'a> Iterator for ImpFileIter<'a> {
    type Item = ImpFile<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos.checked_add(ImpFile::HEADER_SIZE)? > self.end {
            return None;
        }
        let size_field = read_u16_le(self.data, self.pos + 0x0C)?;
        let name_len = (size_field >> 2) as usize;
        let unpadded = ImpFile::HEADER_SIZE + name_len;
        let entry_size = (unpadded + 3) & !3;
        let end = self.pos.checked_add(entry_size)?;
        if end > self.end || end > self.data.len() {
            return None;
        }
        let entry = ImpFile::new(&self.data[self.pos..end]);
        self.pos = end;
        Some(entry)
    }
}

/// Iterator that walks a custom data chain in the CDGuids directory (segment 12).
///
/// Each [`CustDataEntry`] links to the next via its `next` field.
/// The chain ends when `next` is `-1`.
pub struct CustDataIter<'a> {
    data: &'a [u8],
    seg_offset: usize,
    next_offset: i32,
}

impl<'a> CustDataIter<'a> {
    /// Creates a new iterator starting at `next_offset` in the CDGuids directory.
    pub(crate) fn new(data: &'a [u8], seg_offset: usize, next_offset: i32) -> Self {
        Self {
            data,
            seg_offset,
            next_offset,
        }
    }
}

impl<'a> Iterator for CustDataIter<'a> {
    type Item = CustDataEntry<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.next_offset < 0 {
            return None;
        }
        let abs = self.seg_offset.checked_add(self.next_offset as usize)?;
        let end = abs.checked_add(CustDataEntry::SIZE)?;
        if end > self.data.len() {
            return None;
        }
        let entry = CustDataEntry::new(&self.data[abs..end]);
        self.next_offset = entry.next();
        Some(entry)
    }
}

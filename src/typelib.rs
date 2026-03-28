//! [`TypeLib`] -- the main entry point for parsing MSFT type libraries.
//!
//! [`TypeLib::parse`] validates the header and caches the segment
//! directory.  All subsequent lookups (`name`, `guid`, `string`,
//! `typeinfo`, `type_desc`, `const_value`, etc.) are `O(1)` offset
//! calculations into the backing `&[u8]`, except for iterators and
//! chain-walking methods which are `O(n)` in the number of entries.

use crate::{
    ArrayDesc, ConstValue, CustDataEntry, CustDataIter, Error, FuncIter, FuncRecord, Guid,
    GuidEntryIter, ImpFile, ImpFileIter, ImpInfo, ImpInfoIter, ImplTypeIter, NameIter, ParamIter,
    ParameterInfo, TypeInfoEntry, TypeInfoIter, VarIter,
    util::{
        read_f32_le, read_f64_le, read_i16_le, read_i32_le, read_i64_le, read_u16_le, read_u32_le,
        read_u64_le,
    },
};

/// The result of resolving an `hreftype` via
/// [`TypeLib::resolve_hreftype_full`].
#[derive(Debug)]
pub enum ResolvedHreftype<'a> {
    /// An internal TypeInfo, identified by its index.
    Internal(usize),
    /// An external type from an imported library.
    External {
        /// The import-info entry describing this reference.
        imp_info: ImpInfo<'a>,
        /// The import file entry (library name, version, etc.), if resolvable.
        imp_file: Option<ImpFile<'a>>,
    },
}

/// Segment 0: TypeInfo table -- fixed 0x64-byte `MSFT_TypeInfoBase` entries.
const SEG_TYPEINFO: usize = 0;
/// Segment 1: Import-info table -- 12-byte `MSFT_ImpInfo` entries.
const SEG_IMPINFO: usize = 1;
/// Segment 2: Import-files table -- variable-length entries with filename, GUID, version.
const SEG_IMPFILES: usize = 2;
/// Segment 3: Reference table -- 16-byte linked-list entries for coclass impl-types.
const SEG_REFTAB: usize = 3;
/// Segment 4: GUID hash table -- bucket array for O(1) GUID lookup.
const SEG_GUIDHASH: usize = 4;
/// Segment 5: GUID table -- 24-byte entries (GUID + hreftype + hash chain).
const SEG_GUIDTAB: usize = 5;
/// Segment 6: Name hash table -- bucket array for O(1) name lookup.
const SEG_NAMEHASH: usize = 6;
/// Segment 7: Name table -- variable-length entries (12-byte header + name string).
const SEG_NAMETAB: usize = 7;
/// Segment 8: String table -- variable-length entries (2-byte length + string bytes).
const SEG_STRINGTAB: usize = 8;
/// Segment 9: Type-descriptor table -- 8-byte `(vt, extra)` pairs encoding `TYPEDESC` trees.
const SEG_TYPDESC: usize = 9;
/// Segment 10: Array-descriptor table -- variable-length `ARRAYDESC` entries.
const SEG_ARRAYDESC: usize = 10;
/// Segment 11: Custom-data table -- variant-tagged values (2-byte VT tag + payload).
const SEG_CUSTDATA: usize = 11;
/// Segment 12: Custom-data GUID directory -- 12-byte linked-list entries mapping GUIDs to values.
const SEG_CDGUIDS: usize = 12;
/// Total number of segments in the segment directory (indices 0..14; 13 and 14 are reserved).
const NUM_SEGMENTS: usize = 15;

/// Zero-copy view over an MSFT-format type library file.
///
/// Created via [`TypeLib::parse`], which validates the header and segment
/// directory. All subsequent accessors borrow from the original byte slice
/// without copying.
///
/// # Example
///
/// ```no_run
/// # fn main() -> Result<(), msft_typelib::Error> {
/// let data = std::fs::read("library.tlb").unwrap();
/// let lib = msft_typelib::TypeLib::parse(&data)?;
/// println!("{} typeinfos", lib.typeinfo_count());
/// # Ok(())
/// # }
/// ```
pub struct TypeLib<'a> {
    /// Raw file data backing all zero-copy views.
    data: &'a [u8],
    /// Number of TypeInfo entries (from header offset 0x20).
    nrtypeinfos: usize,
    /// Byte offset of the TypeInfo offset table (immediately after the header).
    offset_table_start: usize,
    /// Cached segment directory: `(file_offset, length)` for each of the 15 segments.
    seg_offsets: [(i32, i32); NUM_SEGMENTS],
}

impl<'a> TypeLib<'a> {
    /// Size of the fixed MSFT header in bytes.
    pub const HEADER_SIZE: usize = 0x54;
    /// Expected magic value at offset 0 (`"MSFT"` in little-endian).
    pub const MAGIC: u32 = 0x5446534D;
    /// Offset added to hreftypes for dispatch-side references in dual interfaces.
    pub const DISPATCH_HREF_OFFSET: u32 = 0x0100_0000;

    /// Size of one segment-directory entry: `offset(i32) + length(i32) + res08(i32) + res0c(i32)`.
    const SEGDIR_ENTRY_SIZE: usize = 16;

    /// Parses an MSFT type library from raw file bytes.
    ///
    /// Validates the magic signature, reads the segment directory,
    /// and returns a zero-copy view over the data.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TooShort`] if the buffer is smaller than the
    /// header or segment directory requires.
    ///
    /// Returns [`Error::BadMagic`] if the first four bytes are not `"MSFT"`.
    ///
    /// Returns [`Error::InvalidData`] if required fields cannot be read
    /// or computed offsets overflow.
    pub fn parse(data: &'a [u8]) -> Result<Self, Error> {
        if data.len() < Self::HEADER_SIZE {
            return Err(Error::TooShort {
                expected: Self::HEADER_SIZE,
                actual: data.len(),
                context: "MSFT header",
            });
        }

        let magic = read_u32_le(data, 0x00).ok_or(Error::InvalidData {
            context: "cannot read magic",
        })?;
        if magic != Self::MAGIC {
            return Err(Error::BadMagic {
                expected: Self::MAGIC,
                got: magic,
            });
        }

        let nrtypeinfos = read_i32_le(data, 0x20).ok_or(Error::InvalidData {
            context: "cannot read nrtypeinfos",
        })? as usize;

        // Layout: Header(0x54) + OffsetTable(n*4) + ExtraField(4) + SegDir(15*16)
        // Note: Wine conditionally includes the ExtraField based on
        // `varflags & HELPDLLFLAG (0x100)`, but empirical testing shows
        // it is always present.  See `has_help_dll()` for the flag accessor.
        let offset_table_start = Self::HEADER_SIZE;
        let segdir_start = offset_table_start
            .checked_add(nrtypeinfos.checked_mul(4).ok_or(Error::InvalidData {
                context: "typeinfo count overflow",
            })?)
            .and_then(|v| v.checked_add(4))
            .ok_or(Error::InvalidData {
                context: "segdir offset overflow",
            })?;
        let segdir_end = segdir_start
            .checked_add(NUM_SEGMENTS * Self::SEGDIR_ENTRY_SIZE)
            .ok_or(Error::InvalidData {
                context: "segdir size overflow",
            })?;

        if data.len() < segdir_end {
            return Err(Error::TooShort {
                expected: segdir_end,
                actual: data.len(),
                context: "segment directory",
            });
        }

        let mut seg_offsets = [(0i32, 0i32); NUM_SEGMENTS];
        for (i, entry) in seg_offsets.iter_mut().enumerate() {
            let pos = segdir_start + i * Self::SEGDIR_ENTRY_SIZE;
            *entry = (
                read_i32_le(data, pos).unwrap_or(-1),
                read_i32_le(data, pos + 4).unwrap_or(0),
            );
        }

        Ok(TypeLib {
            data,
            nrtypeinfos,
            offset_table_start,
            seg_offsets,
        })
    }

    /// Returns the complete raw file data backing this type library.
    #[inline]
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Format version word at offset 0x04 (typically `0x00010002`).
    #[inline]
    pub fn format_version(&self) -> u32 {
        read_u32_le(self.data, 0x04).unwrap_or(0)
    }

    /// Offset of the library GUID in the GUID table segment.
    #[inline]
    pub fn lib_guid_offset(&self) -> i32 {
        read_i32_le(self.data, 0x08).unwrap_or(-1)
    }

    /// Locale identifier (LCID) of this type library.
    #[inline]
    pub fn lcid(&self) -> u32 {
        read_u32_le(self.data, 0x0C).unwrap_or(0)
    }

    /// Secondary locale identifier at offset 0x10.
    #[inline]
    pub fn lcid2(&self) -> u32 {
        read_u32_le(self.data, 0x10).unwrap_or(0)
    }

    /// Variable flags at offset 0x14.
    ///
    /// Bits 0-3 encode `SYSKIND` (target platform).
    /// Bit 8 (`HELPDLLFLAG`) indicates a help-string DLL is present.
    #[inline]
    pub fn varflags(&self) -> u32 {
        read_u32_le(self.data, 0x14).unwrap_or(0)
    }

    /// Target platform (`SYSKIND`, bits 0-3 of [`varflags`](Self::varflags)).
    ///
    /// 0 = Win16, 1 = Win32, 2 = Mac, 3 = Win64.
    #[inline]
    pub fn syskind(&self) -> u8 {
        (self.varflags() & 0x0F) as u8
    }

    /// Whether a help-string DLL offset is present (`HELPDLLFLAG`, bit 8 of
    /// [`varflags`](Self::varflags)).
    #[inline]
    pub fn has_help_dll(&self) -> bool {
        self.varflags() & 0x100 != 0
    }

    /// Library version (set with `SetVersion`).
    ///
    /// Low 16 bits = major, high 16 bits = minor.
    #[inline]
    pub fn version(&self) -> u32 {
        read_u32_le(self.data, 0x18).unwrap_or(0)
    }

    /// Major version number (low 16 bits of [`version`](Self::version)).
    #[inline]
    pub fn version_major(&self) -> u16 {
        (self.version() & 0xFFFF) as u16
    }

    /// Minor version number (high 16 bits of [`version`](Self::version)).
    #[inline]
    pub fn version_minor(&self) -> u16 {
        (self.version() >> 16) as u16
    }

    /// Library flags at offset 0x1C.
    #[inline]
    pub fn flags(&self) -> u32 {
        read_u32_le(self.data, 0x1C).unwrap_or(0)
    }

    /// Number of TypeInfo entries in this library.
    #[inline]
    pub fn typeinfo_count(&self) -> usize {
        self.nrtypeinfos
    }

    /// Offset of the help string in the string table, or `-1`.
    #[inline]
    pub fn helpstring_offset(&self) -> i32 {
        read_i32_le(self.data, 0x24).unwrap_or(-1)
    }

    /// Library-level help string context at offset 0x28.
    #[inline]
    pub fn helpstringcontext(&self) -> i32 {
        read_i32_le(self.data, 0x28).unwrap_or(0)
    }

    /// Library-level help context at offset 0x2C.
    #[inline]
    pub fn helpcontext(&self) -> i32 {
        read_i32_le(self.data, 0x2C).unwrap_or(0)
    }

    /// Number of entries in the name table at offset 0x30.
    #[inline]
    pub fn nametablecount(&self) -> i32 {
        read_i32_le(self.data, 0x30).unwrap_or(0)
    }

    /// Number of characters in the name table at offset 0x34.
    #[inline]
    pub fn nametablechars(&self) -> i32 {
        read_i32_le(self.data, 0x34).unwrap_or(0)
    }

    /// Offset of the library name in the name table.
    #[inline]
    pub fn name_offset(&self) -> i32 {
        read_i32_le(self.data, 0x38).unwrap_or(-1)
    }

    /// Offset of the help-file name in the string table, or `-1`.
    #[inline]
    pub fn helpfile_offset(&self) -> i32 {
        read_i32_le(self.data, 0x3C).unwrap_or(-1)
    }

    /// Offset into the CDGuids directory for library-level custom data, or `-1`.
    #[inline]
    pub fn custom_data_offset(&self) -> i32 {
        read_i32_le(self.data, 0x40).unwrap_or(-1)
    }

    /// Dispatch hreftype at offset 0x4C.
    ///
    /// For dual interfaces, this is the hreftype of the `IDispatch` base.
    /// Used with [`DISPATCH_HREF_OFFSET`](Self::DISPATCH_HREF_OFFSET).
    #[inline]
    pub fn dispatchpos(&self) -> i32 {
        read_i32_le(self.data, 0x4C).unwrap_or(-1)
    }

    /// Number of import-info entries.
    #[inline]
    pub fn nimpinfos(&self) -> i32 {
        read_i32_le(self.data, 0x50).unwrap_or(0)
    }

    /// Returns `(file_offset, length)` for the segment at `index`.
    ///
    /// Returns `None` if the segment is empty (offset < 0 or length <= 0).
    pub fn segment(&self, index: usize) -> Option<(usize, usize)> {
        let &(offset, length) = self.seg_offsets.get(index)?;
        if offset < 0 || length <= 0 {
            return None;
        }
        Some((offset as usize, length as usize))
    }

    /// Returns the raw bytes for the segment at `index`.
    ///
    /// Returns `None` if the segment is empty or extends past the end of file.
    pub fn segment_data(&self, index: usize) -> Option<&'a [u8]> {
        let (offset, length) = self.segment(index)?;
        let end = offset.checked_add(length)?;
        self.data.get(offset..end)
    }

    /// Returns the raw GUID hash table data (segment 4).
    pub fn guid_hash_data(&self) -> Option<&'a [u8]> {
        self.segment_data(SEG_GUIDHASH)
    }

    /// Returns the raw name hash table data (segment 6).
    pub fn name_hash_data(&self) -> Option<&'a [u8]> {
        self.segment_data(SEG_NAMEHASH)
    }

    /// Looks up a name by byte offset into the name table segment.
    ///
    /// Returns `None` if `offset` is negative, the segment is missing,
    /// the entry is out of bounds, or the bytes are not valid UTF-8.
    pub fn name(&self, offset: i32) -> Option<&'a str> {
        if offset < 0 {
            return None;
        }
        let (seg_offset, _) = self.segment(SEG_NAMETAB)?;
        let abs = seg_offset.checked_add(offset as usize)?;
        // Header: hreftype(4) + next_hash(4) + namelen(1) + flags(1) + hashcode(2)
        let namelen = *self.data.get(abs.checked_add(8)?)? as usize;
        let name_start = abs.checked_add(12)?;
        let name_end = name_start.checked_add(namelen)?;
        std::str::from_utf8(self.data.get(name_start..name_end)?).ok()
    }

    /// Looks up a GUID by byte offset into the GUID table segment.
    ///
    /// Returns `None` if `offset` is negative, the segment is missing,
    /// or the entry is out of bounds.
    pub fn guid(&self, offset: i32) -> Option<Guid<'a>> {
        if offset < 0 {
            return None;
        }
        let (seg_offset, _) = self.segment(SEG_GUIDTAB)?;
        let abs = seg_offset.checked_add(offset as usize)?;
        let end = abs.checked_add(16)?;
        Some(Guid::new(self.data.get(abs..end)?))
    }

    /// Looks up a string by byte offset into the string table segment.
    ///
    /// Returns `None` if `offset` is negative, the segment is missing,
    /// out of bounds, or not valid UTF-8.
    pub fn string(&self, offset: i32) -> Option<&'a str> {
        if offset < 0 {
            return None;
        }
        let (seg_offset, _) = self.segment(SEG_STRINGTAB)?;
        let abs = seg_offset.checked_add(offset as usize)?;
        let len = read_u16_le(self.data, abs)? as usize;
        let start = abs.checked_add(2)?;
        let end = start.checked_add(len)?;
        std::str::from_utf8(self.data.get(start..end)?).ok()
    }

    /// Returns the library name from the name table.
    pub fn lib_name(&self) -> Option<&'a str> {
        self.name(self.name_offset())
    }

    /// Returns the library GUID from the GUID table.
    pub fn lib_guid(&self) -> Option<Guid<'a>> {
        self.guid(self.lib_guid_offset())
    }

    /// Returns the library help string from the string table.
    pub fn lib_helpstring(&self) -> Option<&'a str> {
        self.string(self.helpstring_offset())
    }

    /// Returns the byte offset of `TypeInfo[index]` within the TypeInfo segment.
    ///
    /// Returns `None` if `index >= typeinfo_count`.
    pub fn typeinfo_offset(&self, index: usize) -> Option<i32> {
        if index >= self.nrtypeinfos {
            return None;
        }
        let pos = self.offset_table_start.checked_add(index.checked_mul(4)?)?;
        read_i32_le(self.data, pos)
    }

    /// Collects member names for `TypeInfo[index]` by scanning the name table.
    ///
    /// Returns the ordered list of member names (excluding the TypeInfo's
    /// own name). Names are matched by `hreftype == typeinfo_offset`.
    pub fn member_names(&self, index: usize) -> Vec<&'a str> {
        let ti_offset = match self.typeinfo_offset(index) {
            Some(o) => o,
            None => return Vec::new(),
        };
        let mut names: Vec<&'a str> = Vec::new();
        for entry in self.names() {
            if entry.hreftype() == ti_offset {
                names.push(entry.name());
            }
        }
        if !names.is_empty() {
            names.remove(0);
        }
        names
    }

    /// Returns the `TypeInfo` entry at the given index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::TypeInfoOutOfRange`] if `index >= typeinfo_count`.
    ///
    /// Returns [`Error::TooShort`] or [`Error::InvalidData`] if the
    /// entry cannot be read from the file data.
    pub fn typeinfo(&self, index: usize) -> Result<TypeInfoEntry<'a>, Error> {
        if index >= self.nrtypeinfos {
            return Err(Error::TypeInfoOutOfRange {
                index,
                count: self.nrtypeinfos,
            });
        }
        let offset_pos =
            self.offset_table_start
                .checked_add(index * 4)
                .ok_or(Error::InvalidData {
                    context: "offset table position overflow",
                })?;
        let ti_offset = read_i32_le(self.data, offset_pos).ok_or(Error::InvalidData {
            context: "cannot read typeinfo offset",
        })?;
        if ti_offset < 0 {
            return Err(Error::TypeInfoOutOfRange {
                index,
                count: self.nrtypeinfos,
            });
        }
        let (seg_offset, _) = self.segment(SEG_TYPEINFO).ok_or(Error::InvalidData {
            context: "typeinfo segment missing",
        })?;
        let abs = seg_offset
            .checked_add(ti_offset as usize)
            .ok_or(Error::InvalidData {
                context: "typeinfo absolute offset overflow",
            })?;
        if abs + TypeInfoEntry::SIZE > self.data.len() {
            return Err(Error::TooShort {
                expected: TypeInfoEntry::SIZE,
                actual: self.data.len().saturating_sub(abs),
                context: "TypeInfoBase",
            });
        }
        Ok(TypeInfoEntry::new(
            &self.data[abs..abs + TypeInfoEntry::SIZE],
        ))
    }

    /// Returns an iterator over all TypeInfo entries.
    pub fn typeinfos(&'a self) -> TypeInfoIter<'a> {
        TypeInfoIter::new(self)
    }

    /// Returns an iterator over [`FuncRecord`] values for the given TypeInfo.
    ///
    /// Returns an empty iterator if the TypeInfo has no functions or its
    /// `memoffset` is invalid.
    pub fn funcs(&self, ti: &TypeInfoEntry<'_>) -> FuncIter<'a> {
        let empty = FuncIter::new(self.data, 0, 0, 0);
        let memoffset = ti.memoffset();
        let func_count = ti.func_count();
        if memoffset < 0 || func_count == 0 {
            return empty;
        }
        let block_start = memoffset as usize;
        let block_size = match read_u32_le(self.data, block_start) {
            Some(v) => v as usize,
            None => return empty,
        };
        let funcs_start = match block_start.checked_add(4) {
            Some(v) => v,
            None => return empty,
        };
        let end = match funcs_start.checked_add(block_size) {
            Some(v) => v,
            None => return empty,
        };
        FuncIter::new(self.data, funcs_start, end, func_count as usize)
    }

    /// Returns an iterator over [`VarRecord`](crate::VarRecord) values for the given TypeInfo.
    ///
    /// Internally skips past all function records first, since variable
    /// records follow functions in the data block.
    ///
    /// Returns an empty iterator if the TypeInfo has no variables or its
    /// `memoffset` is invalid.
    pub fn vars(&self, ti: &TypeInfoEntry<'_>) -> VarIter<'a> {
        let empty = VarIter::new(self.data, 0, 0, 0);
        let memoffset = ti.memoffset();
        let var_count = ti.var_count();
        if memoffset < 0 || var_count == 0 {
            return empty;
        }
        let block_start = memoffset as usize;
        let block_size = match read_u32_le(self.data, block_start) {
            Some(v) => v as usize,
            None => return empty,
        };
        let mut pos = match block_start.checked_add(4) {
            Some(v) => v,
            None => return empty,
        };
        let end = match pos.checked_add(block_size) {
            Some(v) => v,
            None => return empty,
        };
        // Skip all func records
        for _ in 0..ti.func_count() {
            let size = match read_u32_le(self.data, pos) {
                Some(v) => (v & 0xFFFF) as usize,
                None => return empty,
            };
            if size == 0 {
                break;
            }
            pos = match pos.checked_add(size) {
                Some(v) => v,
                None => return empty,
            };
        }
        VarIter::new(self.data, pos, end, var_count as usize)
    }

    /// Returns an iterator over [`ParameterInfo`] entries for a function.
    ///
    /// Parameters occupy the last `nrargs * 12` bytes of the record.
    /// Returns an empty iterator if the function has no parameters.
    pub fn params(&self, func: &FuncRecord<'a>) -> ParamIter<'a> {
        let nrargs = func.nrargs().max(0) as usize;
        if nrargs == 0 {
            return ParamIter::new(&[], 0, 0);
        }
        let record_len = func.as_bytes().len();
        let params_size = match nrargs.checked_mul(ParameterInfo::SIZE) {
            Some(v) => v,
            None => return ParamIter::new(&[], 0, 0),
        };
        if params_size > record_len {
            return ParamIter::new(&[], 0, 0);
        }
        ParamIter::new(func.as_bytes(), record_len - params_size, nrargs)
    }

    /// Computes the file offset where auxiliary arrays begin for a TypeInfo.
    ///
    /// Each TypeInfo's func/var data block has the layout:
    ///
    /// ```text
    /// [block_size: u32] [func records...] [var records...] [aux arrays...]
    /// ```
    ///
    /// The auxiliary arrays immediately follow the last record and contain
    /// five parallel arrays of `i32` values:
    ///
    /// 1. `func_memids[func_count]` -- MEMBERID / DISPID for each function
    /// 2. `var_memids[var_count]` -- MEMBERID for each variable
    /// 3. `func_names[func_count]` -- name-table offset for each function
    /// 4. `var_names[var_count]` -- name-table offset for each variable
    /// 5. `record_offsets[func_count + var_count]` -- byte offsets of records
    ///
    /// Returns `None` if the TypeInfo has no data block (`memoffset < 0`).
    fn aux_start(&self, ti: &TypeInfoEntry<'_>) -> Option<usize> {
        let memoffset = ti.memoffset();
        if memoffset < 0 {
            return None;
        }
        let block_start = memoffset as usize;
        let block_size = read_u32_le(self.data, block_start)? as usize;
        block_start.checked_add(4)?.checked_add(block_size)
    }

    /// Reads one `i32` from the auxiliary arrays at the given flat index.
    ///
    /// The flat index spans all five sub-arrays contiguously.  Callers
    /// (e.g. [`func_memid`](Self::func_memid), [`var_name`](Self::var_name))
    /// compute the correct index from the func/var counts.
    fn read_aux_i32(&self, ti: &TypeInfoEntry<'_>, array_index: usize) -> Option<i32> {
        let aux = self.aux_start(ti)?;
        let pos = aux.checked_add(array_index.checked_mul(4)?)?;
        read_i32_le(self.data, pos)
    }

    /// Returns the MEMBERID (DISPID) for `function[index]`.
    ///
    /// Read from the auxiliary array that follows all func/var records.
    /// Returns `None` if the TypeInfo has no data block or `index` is
    /// out of bounds.
    pub fn func_memid(&self, ti: &TypeInfoEntry<'_>, index: usize) -> Option<i32> {
        self.read_aux_i32(ti, index)
    }

    /// Returns the MEMBERID for `variable[index]`.
    ///
    /// Read from the auxiliary array that follows all func/var records.
    /// Returns `None` if the TypeInfo has no data block or `index` is
    /// out of bounds.
    pub fn var_memid(&self, ti: &TypeInfoEntry<'_>, index: usize) -> Option<i32> {
        let fc = ti.func_count() as usize;
        self.read_aux_i32(ti, fc.checked_add(index)?)
    }

    /// Returns the name of `function[index]` from the auxiliary name array.
    ///
    /// Returns `None` if the TypeInfo has no data block, `index` is out of
    /// bounds, or the name-table offset is invalid.
    pub fn func_name(&self, ti: &TypeInfoEntry<'_>, index: usize) -> Option<&'a str> {
        let fc = ti.func_count() as usize;
        let vc = ti.var_count() as usize;
        let array_idx = fc.checked_add(vc)?.checked_add(index)?;
        let name_offset = self.read_aux_i32(ti, array_idx)?;
        self.name(name_offset)
    }

    /// Returns the name of `variable[index]` from the auxiliary name array.
    ///
    /// Returns `None` if the TypeInfo has no data block, `index` is out of
    /// bounds, or the name-table offset is invalid.
    pub fn var_name(&self, ti: &TypeInfoEntry<'_>, index: usize) -> Option<&'a str> {
        let fc = ti.func_count() as usize;
        let vc = ti.var_count() as usize;
        let array_idx = fc.checked_mul(2)?.checked_add(vc)?.checked_add(index)?;
        let name_offset = self.read_aux_i32(ti, array_idx)?;
        self.name(name_offset)
    }

    /// Decodes a constant value from an `OffsValue` field.
    ///
    /// If `offs_value < 0` the value is packed inline:
    /// - VT code = `(offs_value >> 26) & 0x1F`
    /// - unsigned 26-bit value = `offs_value & 0x03FF_FFFF`
    ///
    /// If `offs_value >= 0` the value is stored in the custom-data segment
    /// at the given byte offset (2-byte VT tag + value bytes).
    ///
    /// Returns `None` if the offset is non-negative but the custom-data
    /// segment is missing or the entry is out of bounds.
    pub fn const_value(&self, offs_value: i32) -> Option<ConstValue<'a>> {
        if offs_value < 0 {
            let raw = offs_value as u32;
            let vt = ((raw & 0x7C00_0000) >> 26) as u16;
            let val = (raw & 0x03FF_FFFF) as i32;
            return Some(match vt {
                0 => ConstValue::Empty,
                1 => ConstValue::Null,
                2 => ConstValue::I2(val as i16),
                3 => ConstValue::I4(val),
                10 => ConstValue::Error(val),
                11 => ConstValue::Bool(val != 0),
                16 => ConstValue::I1(val as i8),
                17 => ConstValue::UI1(val as u8),
                18 => ConstValue::UI2(val as u16),
                19 => ConstValue::UI4(val as u32),
                22 => ConstValue::Int(val),
                23 => ConstValue::UInt(val as u32),
                24 => ConstValue::Void,
                25 => ConstValue::Hresult(val),
                _ => ConstValue::I4(val),
            });
        }
        let (seg_offset, _) = self.segment(SEG_CUSTDATA)?;
        let abs = seg_offset.checked_add(offs_value as usize)?;
        let vt = read_u16_le(self.data, abs)?;
        Some(match vt {
            0 => ConstValue::Empty,
            1 => ConstValue::Null,
            2 => ConstValue::I2(read_i32_le(self.data, abs + 2)? as i16),
            3 => ConstValue::I4(read_i32_le(self.data, abs + 2)?),
            4 => ConstValue::R4(read_f32_le(self.data, abs + 2)?),
            5 => ConstValue::R8(read_f64_le(self.data, abs + 2)?),
            6 => ConstValue::Cy(read_i64_le(self.data, abs + 2)?),
            7 => ConstValue::Date(read_f64_le(self.data, abs + 2)?),
            8 => {
                let len_raw = read_i32_le(self.data, abs + 2)?;
                if len_raw < 0 {
                    return None;
                }
                let len = len_raw as usize;
                let start = abs.checked_add(6)?;
                let end = start.checked_add(len)?;
                ConstValue::Bstr(self.data.get(start..end)?)
            }
            10 => ConstValue::Error(read_i32_le(self.data, abs + 2)?),
            11 => ConstValue::Bool(read_i16_le(self.data, abs + 2)? != 0),
            14 => {
                let start = abs.checked_add(2)?;
                let end = start.checked_add(16)?;
                ConstValue::Decimal(self.data.get(start..end)?)
            }
            16 => ConstValue::I1(read_i32_le(self.data, abs + 2)? as i8),
            17 => ConstValue::UI1(read_i32_le(self.data, abs + 2)? as u8),
            18 => ConstValue::UI2(read_i32_le(self.data, abs + 2)? as u16),
            19 => ConstValue::UI4(read_u32_le(self.data, abs + 2)?),
            20 => ConstValue::I8(read_i64_le(self.data, abs + 2)?),
            21 => ConstValue::UI8(read_u64_le(self.data, abs + 2)?),
            22 => ConstValue::Int(read_i32_le(self.data, abs + 2)?),
            23 => ConstValue::UInt(read_u32_le(self.data, abs + 2)?),
            24 => ConstValue::Void,
            25 => ConstValue::Hresult(read_i32_le(self.data, abs + 2)?),
            64 => ConstValue::Filetime(read_u64_le(self.data, abs + 2)?),
            _ => ConstValue::Raw {
                vt,
                bits: read_i32_le(self.data, abs + 2)?,
            },
        })
    }

    /// Reads a type-descriptor table entry at the given byte offset.
    ///
    /// Returns `(vt, extra)` where:
    /// - For `VT_PTR` (26): `extra` is the pointed-to type descriptor.
    /// - For `VT_USERDEFINED` (29): `extra` is the hreftype.
    /// - For `VT_SAFEARRAY` (27): `extra` is the element type descriptor.
    ///
    /// Returns `None` if `offset` is negative, the segment is missing,
    /// or the entry is out of bounds.
    pub fn type_desc(&self, offset: i32) -> Option<(i32, i32)> {
        if offset < 0 {
            return None;
        }
        let (seg_offset, _) = self.segment(SEG_TYPDESC)?;
        let abs = seg_offset.checked_add(offset as usize)?;
        Some((
            read_i32_le(self.data, abs)?,
            read_i32_le(self.data, abs + 4)?,
        ))
    }

    /// Resolves an `hreftype` to a TypeInfo index (internal references only).
    ///
    /// For internal references the hreftype is the byte offset of the
    /// TypeInfo within the TypeInfo segment; dividing by
    /// [`TypeInfoEntry::SIZE`] gives the index.
    ///
    /// Returns `None` if `hreftype` is negative or the computed index
    /// is out of range. For full resolution including external and
    /// dispatch references, use [`resolve_hreftype_full`](Self::resolve_hreftype_full).
    pub fn resolve_hreftype(&self, hreftype: i32) -> Option<usize> {
        if hreftype < 0 {
            return None;
        }
        let index = hreftype as usize / TypeInfoEntry::SIZE;
        if index < self.nrtypeinfos {
            Some(index)
        } else {
            None
        }
    }

    /// Resolves an `hreftype` to either an internal TypeInfo index or an
    /// external import reference.
    ///
    /// Handles [`DISPATCH_HREF_OFFSET`](Self::DISPATCH_HREF_OFFSET) by
    /// stripping the flag before resolution. Returns `None` if `hreftype`
    /// is negative.
    pub fn resolve_hreftype_full(&self, hreftype: i32) -> Option<ResolvedHreftype<'a>> {
        if hreftype < 0 {
            return None;
        }
        // Strip DISPATCH_HREF_OFFSET if present
        let effective = if (hreftype as u32) & Self::DISPATCH_HREF_OFFSET != 0 {
            (hreftype as u32 & !Self::DISPATCH_HREF_OFFSET) as i32
        } else {
            hreftype
        };

        // Try internal first
        let index = effective as usize / TypeInfoEntry::SIZE;
        if index < self.nrtypeinfos {
            return Some(ResolvedHreftype::Internal(index));
        }

        // External: hreftype (with low 2 bits masked) is a byte offset into ImpInfo segment
        let imp_byte_offset = (effective & !0x03) as usize;
        let (seg_offset, seg_len) = self.segment(SEG_IMPINFO)?;
        if imp_byte_offset + ImpInfo::SIZE > seg_len {
            return None;
        }
        let abs = seg_offset + imp_byte_offset;
        let imp_info = ImpInfo::new(&self.data[abs..abs + ImpInfo::SIZE]);
        let imp_file = self.imp_file(imp_info.imp_file_offset());
        Some(ResolvedHreftype::External { imp_info, imp_file })
    }

    /// Returns an iterator over all [`GuidEntry`](crate::GuidEntry) values in the GUID table.
    pub fn guids(&self) -> GuidEntryIter<'a> {
        let (offset, length) = self.segment(SEG_GUIDTAB).unwrap_or((0, 0));
        GuidEntryIter::new(self.data, offset, offset.saturating_add(length))
    }

    /// Returns an iterator over all entries in the name table.
    pub fn names(&self) -> NameIter<'a> {
        let (offset, length) = self.segment(SEG_NAMETAB).unwrap_or((0, 0));
        NameIter::new(self.data, offset, offset.saturating_add(length), offset)
    }

    /// Returns an iterator over implemented interfaces for a coclass.
    ///
    /// Traverses the linked list in the reference table starting from
    /// the TypeInfo's `res2` field.
    pub fn impl_types(&self, ti: &TypeInfoEntry<'_>) -> ImplTypeIter<'a> {
        let ref_offset = ti.res2();
        let (seg_offset, _) = self.segment(SEG_REFTAB).unwrap_or((0, 0));
        ImplTypeIter::new(self.data, seg_offset, ref_offset)
    }

    /// Returns an iterator over [`ImpInfo`](crate::ImpInfo) entries in the import table.
    pub fn imports(&self) -> ImpInfoIter<'a> {
        let (offset, length) = self.segment(SEG_IMPINFO).unwrap_or((0, 0));
        ImpInfoIter::new(self.data, offset, offset.saturating_add(length))
    }

    /// Returns an iterator over [`ImpFile`](crate::ImpFile) entries in the import-files
    /// segment (segment 2).
    pub fn imp_files(&self) -> ImpFileIter<'a> {
        let (offset, length) = self.segment(SEG_IMPFILES).unwrap_or((0, 0));
        ImpFileIter::new(self.data, offset, offset.saturating_add(length))
    }

    /// Looks up an import file by byte offset into the import-files segment.
    ///
    /// Use this to resolve [`ImpInfo::imp_file_offset`](crate::ImpInfo::imp_file_offset)
    /// to an [`ImpFile`](crate::ImpFile).
    ///
    /// Returns `None` if `offset` is negative, the segment is missing,
    /// or the entry is out of bounds.
    pub fn imp_file(&self, offset: i32) -> Option<ImpFile<'a>> {
        if offset < 0 {
            return None;
        }
        let (seg_offset, seg_len) = self.segment(SEG_IMPFILES)?;
        let abs = seg_offset.checked_add(offset as usize)?;
        if abs.checked_add(ImpFile::HEADER_SIZE)? > seg_offset.checked_add(seg_len)? {
            return None;
        }
        let size_field = read_u16_le(self.data, abs + 0x0C)?;
        let name_len = (size_field >> 2) as usize;
        let entry_size = (ImpFile::HEADER_SIZE + name_len + 3) & !3;
        let end = abs.checked_add(entry_size)?;
        if end > self.data.len() {
            return None;
        }
        Some(ImpFile::new(&self.data[abs..end]))
    }

    /// Returns an array descriptor at the given byte offset in segment 10.
    ///
    /// Returns `None` if `offset` is negative, the segment is missing,
    /// or the entry is out of bounds.
    pub fn array_desc(&self, offset: i32) -> Option<ArrayDesc<'a>> {
        if offset < 0 {
            return None;
        }
        let (seg_offset, _) = self.segment(SEG_ARRAYDESC)?;
        let abs = seg_offset.checked_add(offset as usize)?;
        // Need at least 8 bytes for the header (element_type + num_dims + flags)
        if abs.checked_add(8)? > self.data.len() {
            return None;
        }
        let num_dims = read_u16_le(self.data, abs + 4)? as usize;
        let size = 8 + num_dims * 8;
        let end = abs.checked_add(size)?;
        if end > self.data.len() {
            return None;
        }
        Some(ArrayDesc::new(&self.data[abs..end]))
    }

    /// Returns an iterator over the custom data chain starting at `offset`
    /// in the CDGuids directory (segment 12).
    ///
    /// The chain is a linked list of [`CustDataEntry`](crate::CustDataEntry)
    /// values, ending when `next` is `-1`.
    pub fn cust_data(&self, offset: i32) -> CustDataIter<'a> {
        let (seg_offset, _) = self.segment(SEG_CDGUIDS).unwrap_or((0, 0));
        CustDataIter::new(self.data, seg_offset, offset)
    }

    /// Returns the library-level custom data chain.
    pub fn lib_cust_data(&self) -> CustDataIter<'a> {
        self.cust_data(self.custom_data_offset())
    }

    /// Resolves one custom data entry into its GUID and value.
    ///
    /// Returns `None` if the GUID or data offset cannot be resolved.
    pub fn resolve_cust_data_entry(
        &self,
        entry: &CustDataEntry<'_>,
    ) -> Option<(Guid<'a>, ConstValue<'a>)> {
        let guid = self.guid(entry.guid_offset())?;
        let value = self.const_value(entry.data_offset())?;
        Some((guid, value))
    }
}

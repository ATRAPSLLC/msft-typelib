//! Allocation-free parser for MSFT-format type library (`.tlb`) files.
//!
//! MSFT is the binary format used by Microsoft COM type libraries since
//! the late 1990s.  A type library describes the interfaces, coclasses,
//! enumerations, and constants exposed by a COM component so that tools
//! and languages can use them at compile time or runtime.
//!
//! Record types borrow directly from the input `&[u8]` and carry a
//! lifetime that ties them to the original buffer.  Parsing requires no
//! heap allocations beyond what the caller performs to load the file;
//! individual accessor methods return small scalar values by copy.
//!
//! # Quick start
//!
//! ```no_run
//! # fn main() -> Result<(), msft_typelib::Error> {
//! let data = std::fs::read("library.tlb").unwrap();
//! let lib = msft_typelib::TypeLib::parse(&data)?;
//! println!("TypeLib: {} ({} typeinfos)",
//!     lib.lib_name().unwrap_or("?"), lib.typeinfo_count());
//! # Ok(())
//! # }
//! ```
//!
//! # Binary format overview
//!
//! An MSFT file begins with a 0x54-byte header (magic `"MSFT"`, version,
//! GUID offset, LCID, flags, etc.), followed by:
//!
//! 1. **Extra field** (4 bytes) -- the help-string DLL name's offset when the
//!    `HELPDLLFLAG` is set: present in the VB6 runtime's libraries, absent
//!    from the libraries the VB6 compiler embeds in ActiveX binaries.
//! 2. **Offset table** -- one `i32` per TypeInfo, giving its byte offset
//!    inside the TypeInfo segment.
//! 3. **Segment directory** -- 15 entries of 16 bytes each
//!    (`offset: i32, length: i32, res08, res0c`), pointing to the data
//!    segments that follow.
//!
//! The 15 segments are:
//!
//! | Index | Contents |
//! |------:|----------|
//! | 0 | TypeInfo table -- fixed-size (0x64 byte) entries |
//! | 1 | Import-info table -- 12-byte entries referencing external typelibs |
//! | 2 | Import-files table -- variable-length entries with library name, GUID, version |
//! | 3 | Reference table -- 16-byte linked-list entries for coclass impl-types |
//! | 4 | GUID hash table -- bucket array for fast GUID lookup |
//! | 5 | GUID table -- 24-byte entries (16-byte GUID + hreftype + hash chain) |
//! | 6 | Name hash table -- bucket array for fast name lookup |
//! | 7 | Name table -- variable-length entries (12-byte header + name bytes) |
//! | 8 | String table -- variable-length entries (2-byte length + string bytes) |
//! | 9 | Type-descriptor table -- 8-byte entries encoding `TYPEDESC` trees |
//! | 10 | Array-descriptor table -- variable-length `ARRAYDESC` entries |
//! | 11 | Custom-data table -- variant-tagged values (2-byte VT + payload) |
//! | 12 | Custom-data GUID directory -- 12-byte linked-list entries mapping GUIDs to custom data |
//! | 13--14 | Reserved (always empty) |
//!
//! Each TypeInfo has a func/var data block at an absolute file offset.
//! The block starts with a 4-byte size, followed by variable-length
//! function and variable records, then **auxiliary arrays** containing
//! MEMBERIDs and name-table offsets for each member.
//!
//! # Public types
//!
//! | Type | Description |
//! |------|-------------|
//! | [`TypeLib`] | Main entry point and all lookup / iteration methods |
//! | [`TypeInfoEntry`] | One type description (enum, struct, interface, ...) |
//! | [`FuncRecord`] | One function or property accessor |
//! | [`VarRecord`] | One variable or constant |
//! | [`ParameterInfo`] | One function parameter |
//! | [`GuidEntry`] | One GUID-table entry |
//! | [`RefRecord`] | One coclass-implements reference |
//! | [`ImpInfo`] | One imported-typelib reference |
//! | [`ImpFile`] | One imported-library file entry (name, version, GUID) |
//! | [`ArrayDesc`], [`SafeArrayBound`] | Array descriptor with per-dimension bounds |
//! | [`CustDataEntry`] | One entry in the custom data GUID directory |
//! | [`ResolvedHreftype`] | Result of resolving an hreftype (internal or external) |
//! | [`TypeKind`], [`ConstValue`], [`vt_name`] | Shared enumerations and helpers |
//! | [`Guid`] | 16-byte GUID display wrapper |
//! | [`NameEntry`] | A decoded entry from the name table |
//! | [`Error`] | Parse error type |

mod arraydesc;
mod custdata;
mod error;
mod func;
mod guid;
mod guidentry;
mod impfile;
mod impinfo;
mod iterators;
mod name;
mod param;
mod refrecord;
mod typeinfo;
mod typelib;
mod types;
pub(crate) mod util;
mod var;

pub use arraydesc::{ArrayDesc, SafeArrayBound};
pub use custdata::CustDataEntry;
pub use error::Error;
pub use func::FuncRecord;
pub use guid::Guid;
pub use guidentry::GuidEntry;
pub use impfile::ImpFile;
pub use impinfo::ImpInfo;
pub use iterators::{
    CustDataIter, FuncIter, GuidEntryIter, ImpFileIter, ImpInfoIter, ImplTypeIter, NameIter,
    ParamIter, TypeInfoIter, VarIter,
};
pub use name::NameEntry;
pub use param::ParameterInfo;
pub use refrecord::RefRecord;
pub use typeinfo::TypeInfoEntry;
pub use typelib::{ResolvedHreftype, TypeLib};
pub use types::{ConstValue, TypeDescription, TypeKind, vt_name};
pub use var::VarRecord;

#[cfg(test)]
mod tests;

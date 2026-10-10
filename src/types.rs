//! Shared enumerations and helper functions for MSFT type libraries.
//!
//! [`TypeKind`] mirrors the `TYPEKIND` enum from OLE Automation.
//! [`ConstValue`] decodes the variant-tagged constant values stored in
//! the custom-data table (segment 11) or packed inline in `OffsValue`
//! fields.  [`vt_name`] maps `VARTYPE` codes to human-readable names.
//!
//! `VARTYPE` codes (the `VT_*` constants) identify the data type of a
//! variant value.  Not all VT codes appear as `ConstValue` variants --
//! codes without an explicit variant are captured as [`ConstValue::Raw`].

use std::fmt;

use crate::ArrayDesc;

/// The kind of a TypeInfo entry (low 4 bits of the `typekind` field).
///
/// Mirrors the `TYPEKIND` enum from the OLE Automation specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TypeKind {
    /// `TKIND_ENUM` (0) -- An enumeration of named constants.
    Enum,
    /// `TKIND_RECORD` (1) -- A C-style struct / UDT.
    Record,
    /// `TKIND_MODULE` (2) -- A module containing global functions and constants.
    Module,
    /// `TKIND_INTERFACE` (3) -- A COM vtable-based interface.
    Interface,
    /// `TKIND_DISPATCH` (4) -- A COM `IDispatch`-based interface.
    Dispatch,
    /// `TKIND_COCLASS` (5) -- A COM coclass aggregating one or more interfaces.
    CoClass,
    /// `TKIND_ALIAS` (6) -- A typedef alias for another type.
    Alias,
    /// `TKIND_UNION` (7) -- A C-style union.
    Union,
    /// An unrecognised type kind value.
    Unknown(u8),
}

impl TypeKind {
    /// Converts a raw `u8` value (low 4 bits of `typekind`) to a [`TypeKind`].
    pub fn from_raw(raw: u8) -> Self {
        match raw {
            0 => TypeKind::Enum,
            1 => TypeKind::Record,
            2 => TypeKind::Module,
            3 => TypeKind::Interface,
            4 => TypeKind::Dispatch,
            5 => TypeKind::CoClass,
            6 => TypeKind::Alias,
            7 => TypeKind::Union,
            n => TypeKind::Unknown(n),
        }
    }
}

impl fmt::Display for TypeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TypeKind::Enum => write!(f, "ENUM"),
            TypeKind::Record => write!(f, "RECORD"),
            TypeKind::Module => write!(f, "MODULE"),
            TypeKind::Interface => write!(f, "INTERFACE"),
            TypeKind::Dispatch => write!(f, "DISPATCH"),
            TypeKind::CoClass => write!(f, "COCLASS"),
            TypeKind::Alias => write!(f, "ALIAS"),
            TypeKind::Union => write!(f, "UNION"),
            TypeKind::Unknown(n) => write!(f, "UNKNOWN({n})"),
        }
    }
}

/// A decoded `TYPEDESC`: the type a type field names (a function's return,
/// a parameter's or a variable's type, what an alias stands for).
///
/// A negative type field is a base type, its `VARTYPE` in the low twelve
/// bits. Any other is the byte offset of an entry in the type-descriptor
/// table (segment 9), whose second field is itself a type field (the
/// pointed-to or element type), an hreftype, or an array descriptor's offset.
/// Decoded one level at a time by [`TypeLib::type_description`](crate::TypeLib::type_description),
/// so nothing is allocated.
#[derive(Clone, Copy, Debug)]
pub enum TypeDescription<'a> {
    /// A base type, by its `VARTYPE` (`VT_I4`, `VT_BSTR`, `VT_UNKNOWN`, ...).
    Base(u16),
    /// `VT_PTR` (26): a pointer to the type this type field names.
    Pointer(i32),
    /// `VT_SAFEARRAY` (27) of the type this type field names.
    SafeArray(i32),
    /// `VT_USERDEFINED` (29): the type this hreftype names
    /// ([`TypeLib::resolve_hreftype_full`](crate::TypeLib::resolve_hreftype_full)).
    UserDefined(i32),
    /// `VT_CARRAY` (28): a fixed-size array, its element type and bounds.
    CArray(ArrayDesc<'a>),
}

/// A decoded constant value from a `VAR_CONST` variable record or custom data.
///
/// Values are either packed inline in the `OffsValue` field (small
/// positive integers) or stored in the custom data segment.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ConstValue<'a> {
    /// No value / empty (`VT_EMPTY`, 0).
    Empty,
    /// Null (`VT_NULL`, 1).
    Null,
    /// A 16-bit signed integer (`VT_I2`, 2).
    I2(i16),
    /// A 32-bit signed integer (`VT_I4`, 3).
    I4(i32),
    /// A 32-bit float (`VT_R4`, 4).
    R4(f32),
    /// A 64-bit float (`VT_R8`, 5).
    R8(f64),
    /// A currency value (`VT_CY`, 6) stored as a 64-bit integer scaled by 10000.
    Cy(i64),
    /// A date (`VT_DATE`, 7) stored as a 64-bit float (OLE Automation date).
    Date(f64),
    /// A byte-string (`VT_BSTR`, 8), borrowed from the file data.
    Bstr(&'a [u8]),
    /// A null byte-string (`VT_BSTR` stored with length -1), distinct from an
    /// empty one: VBA's `vbNullString`.
    NullBstr,
    /// An OLE error code (`VT_ERROR`, 10).
    Error(i32),
    /// A boolean (`VT_BOOL`, 11).
    Bool(bool),
    /// A signed byte (`VT_I1`, 16).
    I1(i8),
    /// An unsigned byte (`VT_UI1`, 17).
    UI1(u8),
    /// An unsigned 16-bit integer (`VT_UI2`, 18).
    UI2(u16),
    /// An unsigned 32-bit integer (`VT_UI4`, 19).
    UI4(u32),
    /// A 64-bit signed integer (`VT_I8`, 20).
    I8(i64),
    /// A 64-bit unsigned integer (`VT_UI8`, 21).
    UI8(u64),
    /// A signed integer (`VT_INT`, 22).
    Int(i32),
    /// An unsigned integer (`VT_UINT`, 23).
    UInt(u32),
    /// Void (`VT_VOID`, 24).
    Void,
    /// An HRESULT (`VT_HRESULT`, 25).
    Hresult(i32),
    /// A decimal value (`VT_DECIMAL`, 14), raw 16 bytes.
    Decimal(&'a [u8]),
    /// A FILETIME value (`VT_FILETIME`, 64).
    Filetime(u64),
    /// A value whose `VARTYPE` code has no dedicated variant above.
    ///
    /// The `vt` field is the 16-bit `VARTYPE` code (e.g. `VT_DISPATCH` = 9,
    /// `VT_VARIANT` = 12).  The `bits` field is the first 4 bytes of the
    /// value payload; for wider types the remaining bytes are not captured.
    Raw {
        /// The `VARTYPE` code.
        vt: u16,
        /// The first 4 bytes of the value payload, read as a little-endian `i32`.
        bits: i32,
    },
}

impl ConstValue<'_> {
    /// The value's `VARTYPE` (`VT_I4` is 3, `VT_BSTR` 8, ...).
    #[must_use]
    pub fn vt(&self) -> u16 {
        match self {
            ConstValue::Empty => 0,
            ConstValue::Null => 1,
            ConstValue::I2(_) => 2,
            ConstValue::I4(_) => 3,
            ConstValue::R4(_) => 4,
            ConstValue::R8(_) => 5,
            ConstValue::Cy(_) => 6,
            ConstValue::Date(_) => 7,
            ConstValue::Bstr(_) | ConstValue::NullBstr => 8,
            ConstValue::Error(_) => 10,
            ConstValue::Bool(_) => 11,
            ConstValue::Decimal(_) => 14,
            ConstValue::I1(_) => 16,
            ConstValue::UI1(_) => 17,
            ConstValue::UI2(_) => 18,
            ConstValue::UI4(_) => 19,
            ConstValue::I8(_) => 20,
            ConstValue::UI8(_) => 21,
            ConstValue::Int(_) => 22,
            ConstValue::UInt(_) => 23,
            ConstValue::Void => 24,
            ConstValue::Hresult(_) => 25,
            ConstValue::Filetime(_) => 64,
            ConstValue::Raw { vt, .. } => *vt,
        }
    }
}

impl fmt::Display for ConstValue<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConstValue::Empty => write!(f, "<empty>"),
            ConstValue::Null => write!(f, "<null>"),
            ConstValue::I2(v) => write!(f, "{v}"),
            ConstValue::I4(v) => write!(f, "{v}"),
            ConstValue::R4(v) => write!(f, "{v}"),
            ConstValue::R8(v) => write!(f, "{v}"),
            ConstValue::Cy(v) => {
                let whole = v / 10000;
                let frac = (v % 10000).unsigned_abs();
                write!(f, "{whole}.{frac:04}")
            }
            ConstValue::Date(v) => write!(f, "DATE({v})"),
            ConstValue::Bstr(v) => write!(f, "\"{}\"", String::from_utf8_lossy(v)),
            ConstValue::NullBstr => write!(f, "<null bstr>"),
            ConstValue::Error(v) => write!(f, "ERROR(0x{v:08X})"),
            ConstValue::Bool(true) => write!(f, "True"),
            ConstValue::Bool(false) => write!(f, "False"),
            ConstValue::I1(v) => write!(f, "{v}"),
            ConstValue::UI1(v) => write!(f, "{v}"),
            ConstValue::UI2(v) => write!(f, "{v}"),
            ConstValue::UI4(v) => write!(f, "{v}"),
            ConstValue::I8(v) => write!(f, "{v}"),
            ConstValue::UI8(v) => write!(f, "{v}"),
            ConstValue::Int(v) => write!(f, "{v}"),
            ConstValue::UInt(v) => write!(f, "{v}"),
            ConstValue::Void => write!(f, "<void>"),
            ConstValue::Hresult(v) => write!(f, "0x{v:08X}"),
            ConstValue::Decimal(v) => {
                write!(f, "DECIMAL(")?;
                for (i, b) in v.iter().enumerate() {
                    if i > 0 {
                        write!(f, " ")?;
                    }
                    write!(f, "{b:02X}")?;
                }
                write!(f, ")")
            }
            ConstValue::Filetime(v) => write!(f, "FILETIME(0x{v:016X})"),
            ConstValue::Raw { vt, bits } => write!(f, "raw(vt={vt}, 0x{bits:08X})"),
        }
    }
}

/// Returns a human-readable VB-style name for a `VARTYPE` code.
///
/// Common mappings: 2 = `"Integer"`, 3 = `"Long"`, 8 = `"String"`, etc.
/// Returns `"Unknown"` for unrecognised codes.
pub fn vt_name(vt: u16) -> &'static str {
    match vt {
        0 => "void",
        2 => "Integer",
        3 => "Long",
        4 => "Single",
        5 => "Double",
        6 => "Currency",
        7 => "Date",
        8 => "String",
        9 => "Object",
        10 => "SCODE",
        11 => "Boolean",
        12 => "Variant",
        13 => "IUnknown",
        16 => "SignedByte",
        17 => "Byte",
        18 => "UShort",
        19 => "ULong",
        20 => "LongLong",
        21 => "ULongLong",
        22 => "Int",
        23 => "UInt",
        24 => "void",
        25 => "HRESULT",
        26 => "Ptr",
        27 => "SafeArray",
        28 => "CArray",
        29 => "UserDefined",
        _ => "Unknown",
    }
}

# Changelog

All notable changes to this crate are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0]

This release breaks the 0.1 API: `FuncRecord::name_offset` and the old
`FuncRecord::helpstringcontext` are renamed (`res9`, `res_a`),
`FuncRecord::helpstringcontext` and `FuncRecord::cust_data_offset` read
different words, `TypeLib::resolve_hreftype` returns `None` for import
references, and `ConstValue` gains the `NullBstr` variant, so an exhaustive
`match` on it needs a new arm.

### Fixed

- The help-string DLL field follows the 0x54-byte header, before the TypeInfo
  offset table, and is present only when `HELPDLLFLAG` (varflags bit 0x100) is
  set, as Wine reads it. Read after the offset table and always, it shifted the
  table by one entry in a library that sets the flag (`TypeLib::typeinfo(i)`
  returned TypeInfo `i - 1`, and `typeinfo(0)` read the field as an offset),
  and in one that does not (the libraries the VB6 compiler embeds in ActiveX
  DLLs and OCXs, varflags 0x41) every typeinfo failed with "typeinfo segment
  missing".
- `TypeLib::impl_types` starts at the coclass's `datatype1` (+0x54), the offset of
  its first implemented interface in the reference table, not at `res2` (+0x08),
  which is 0 for every coclass: each coclass of a library listed the first
  coclass's interfaces.
- An hreftype names a TypeInfo of this library only when its low two bits are
  clear, as Wine reads it (`MSFT_HREFTYPE_INTHISFILE`). `resolve_hreftype_full`
  tried the TypeInfo index first, so an import reference whose import-info
  offset divided to a valid index resolved to a local type: every interface of
  a VB6-compiled library derives from stdole's `IDispatch` through hreftype
  0x1, which resolved to TypeInfo 0. `resolve_hreftype` now returns `None` for
  an import reference.
- A function record's optional attributes follow Wine's `MSFT_FuncRecord`:
  help context, help string, entry, two reserved words, the help string
  context (0x2C), the custom data (0x30), then per-argument custom data.
  `helpstringcontext` read the second reserved word (-1) and
  `cust_data_offset` read the help string context.
- FKCCIC bit 12 marks a parameter default-value array before the parameter
  records, not per-argument custom data; per-argument custom data follows the
  function's own custom data, when the custom-data bit (7) is set.

### Changed

- `FuncRecord::name_offset` (offset 0x24) is `FuncRecord::res9`: the word is
  reserved, and a function's name is in the auxiliary arrays
  (`TypeLib::func_name`). The word at 0x28 is `FuncRecord::res_a`.
- `FuncRecord::has_arg_cust_data` is true when the record holds per-argument
  custom data (custom-data bit set and attributes past `oCustData`).
- `ArrayDesc` derives `Clone`, `Copy` and `Debug`.
- The crate builds under strict lints, declared in its manifest:
  `missing_docs` and `unsafe_code` denied, and clippy's `unwrap_used`, `expect_used`, `panic`, `arithmetic_side_effects` and
  `indexing_slicing` denied. Every offset computation is checked and every
  slice read through `get`, so malformed input yields `None` or an error
  rather than a wrapped offset.

### Added

- `TypeLib::type_description` and `TypeDescription`: a type field decoded one
  level (base type, pointer, safe array, user-defined type, C array), without
  allocating.
- `FuncRecord::has_default_values` and `FuncRecord::default_value_offset`, for
  `TypeLib::const_value`.
- `ConstValue::vt`: a value's `VARTYPE`, whichever variant holds it.
- `ConstValue::NullBstr`: a string constant stored with length -1, a null
  BSTR (VBA's `vbNullString`). `TypeLib::const_value` returned `None` for
  it, as for a malformed entry.
- `TypeLib::name_bytes`, `ImpFile::filename_bytes`,
  `TypeLib::func_name_offset` and `TypeLib::var_name_offset`: names in the
  library's own code page, which the UTF-8 accessors (`TypeLib::name`,
  `ImpFile::filename`, `TypeLib::func_name`, `TypeLib::var_name`) refuse.
- Test sample `vb6_ocx.tlb`, the library of an ActiveX control compiled by VB6.

## [0.1.1]

### Changed

- Recorded ATRAPS LLC as copyright holder and added a `NOTICE` file. The Apache-2.0
  appendix said 2025, but every commit in this repository dates to 2026. No functional
  change.
- Dropped the deprecated `authors` field and repointed `repository` at the organisation.
  The URL also carried a trailing slash, which is now removed.
- CI gained formatting, clippy, and documentation gates. It previously ran only
  `cargo test` and `cargo doc`, so lint and formatting regressions went uncaught -
  the tree was in fact unformatted. Clippy runs `--all-targets`, and the docs job
  denies rustdoc warnings.
- Releases now verify that the tag matches the version declared in `Cargo.toml`, and
  refuse to publish a commit that is not contained in `main`.
- Publishing now uses crates.io trusted publishing instead of a stored registry token.

## [0.1.0]

Initial release.

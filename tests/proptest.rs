//! Property-based tests for MSFT type library parsing.
//!
//! These tests generate structurally varied inputs and verify the parser
//! never panics, regardless of the content.  They complement the
//! integration tests (which exercise real `.tlb` files) by exploring
//! edge cases that real files never contain.

use msft_typelib::TypeLib;
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Strategy: completely random bytes (unstructured fuzzing)
// ---------------------------------------------------------------------------

proptest! {
    /// The parser must never panic on arbitrary input.
    #[test]
    fn parse_random_bytes_never_panics(data in proptest::collection::vec(any::<u8>(), 0..1024)) {
        let _ = TypeLib::parse(&data);
    }
}

// ---------------------------------------------------------------------------
// Strategy: valid header with random segment directory and payload
// ---------------------------------------------------------------------------

/// Builds an MSFT file with a valid magic + header, a controlled number of
/// TypeInfos (0..8), a segment directory filled from `seg_bytes`, and
/// `payload` appended after the segment directory.
fn build_msft_file(
    nrtypeinfos: u8,
    varflags: u16,
    seg_bytes: &[u8],
    payload: &[u8],
) -> Vec<u8> {
    let n = nrtypeinfos as usize;
    // Header: 0x54 bytes
    // Offset table: n * 4 bytes
    // Extra field: 4 bytes (always present)
    // Segment directory: 15 * 16 = 240 bytes
    let segdir_start = 0x54 + n * 4 + 4;
    let data_start = segdir_start + 15 * 16;
    let total = data_start + payload.len();

    let mut buf = vec![0u8; total];

    // Magic "MSFT"
    buf[0..4].copy_from_slice(&0x5446534D_u32.to_le_bytes());
    // Format version
    buf[4..8].copy_from_slice(&0x00010002_u32.to_le_bytes());
    // varflags at 0x14
    buf[0x14..0x16].copy_from_slice(&varflags.to_le_bytes());
    // nrtypeinfos at 0x20
    buf[0x20..0x24].copy_from_slice(&(n as i32).to_le_bytes());

    // Offset table: each TypeInfo offset = i * 0x64 (pointing into segment 0)
    for i in 0..n {
        let off = 0x54 + i * 4;
        buf[off..off + 4].copy_from_slice(&((i * 0x64) as i32).to_le_bytes());
    }

    // Fill segment directory from seg_bytes (up to 240 bytes), rest stays 0
    let seg_len = seg_bytes.len().min(15 * 16);
    buf[segdir_start..segdir_start + seg_len].copy_from_slice(&seg_bytes[..seg_len]);

    // Append payload
    buf[data_start..data_start + payload.len()].copy_from_slice(payload);

    buf
}

proptest! {
    /// A structurally valid header with random segment data never panics.
    #[test]
    fn parse_valid_header_random_segments(
        nrtypeinfos in 0u8..8,
        varflags in any::<u16>(),
        seg_bytes in proptest::collection::vec(any::<u8>(), 0..240),
        payload in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let data = build_msft_file(nrtypeinfos, varflags, &seg_bytes, &payload);
        let _ = TypeLib::parse(&data);
    }

    /// Parse succeeds, then exercise every header accessor without panic.
    #[test]
    fn header_accessors_never_panic(
        nrtypeinfos in 0u8..4,
        varflags in any::<u16>(),
        payload in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let data = build_msft_file(nrtypeinfos, varflags, &[], &payload);
        if let Ok(lib) = TypeLib::parse(&data) {
            let _ = lib.data();
            let _ = lib.format_version();
            let _ = lib.lib_guid_offset();
            let _ = lib.lcid();
            let _ = lib.lcid2();
            let _ = lib.varflags();
            let _ = lib.syskind();
            let _ = lib.has_help_dll();
            let _ = lib.version();
            let _ = lib.version_major();
            let _ = lib.version_minor();
            let _ = lib.flags();
            let _ = lib.typeinfo_count();
            let _ = lib.helpstring_offset();
            let _ = lib.helpstringcontext();
            let _ = lib.helpcontext();
            let _ = lib.nametablecount();
            let _ = lib.nametablechars();
            let _ = lib.name_offset();
            let _ = lib.helpfile_offset();
            let _ = lib.custom_data_offset();
            let _ = lib.dispatchpos();
            let _ = lib.nimpinfos();
            let _ = lib.lib_name();
            let _ = lib.lib_guid();
            let _ = lib.lib_helpstring();
        }
    }
}

// ---------------------------------------------------------------------------
// Strategy: valid header + segment directory pointing into payload
// ---------------------------------------------------------------------------

/// Builds a file where segment 0 (TypeInfo) actually points into the payload.
fn build_msft_with_typeinfo_seg(nrtypeinfos: u8, typeinfo_payload: &[u8]) -> Vec<u8> {
    let n = nrtypeinfos as usize;
    let segdir_start = 0x54 + n * 4 + 4;
    let data_start = segdir_start + 15 * 16;
    let total = data_start + typeinfo_payload.len();

    let mut buf = vec![0u8; total];

    // Header
    buf[0..4].copy_from_slice(&0x5446534D_u32.to_le_bytes());
    buf[4..8].copy_from_slice(&0x00010002_u32.to_le_bytes());
    buf[0x20..0x24].copy_from_slice(&(n as i32).to_le_bytes());

    // Offset table
    for i in 0..n {
        let off = 0x54 + i * 4;
        buf[off..off + 4].copy_from_slice(&((i * 0x64) as i32).to_le_bytes());
    }

    // Segment 0 (TypeInfo): offset = data_start, length = typeinfo_payload.len()
    let seg0_off = segdir_start;
    buf[seg0_off..seg0_off + 4].copy_from_slice(&(data_start as i32).to_le_bytes());
    buf[seg0_off + 4..seg0_off + 8]
        .copy_from_slice(&(typeinfo_payload.len() as i32).to_le_bytes());

    // Payload
    buf[data_start..].copy_from_slice(typeinfo_payload);

    buf
}

proptest! {
    /// TypeInfo iteration never panics, even with garbage in the TypeInfo segment.
    #[test]
    fn typeinfo_iteration_never_panics(
        nrtypeinfos in 1u8..4,
        payload in proptest::collection::vec(any::<u8>(), 0..1024),
    ) {
        let data = build_msft_with_typeinfo_seg(nrtypeinfos, &payload);
        if let Ok(lib) = TypeLib::parse(&data) {
            for ti in lib.typeinfos().flatten() {
                let _ = ti.typekind();
                let _ = ti.func_count();
                let _ = ti.var_count();
                let _ = ti.name_offset();
                let _ = ti.guid_offset();
                let _ = ti.flags();
                let _ = ti.memoffset();
                let _ = ti.helpcontext();
                let _ = ti.cust_data_offset();
                let _ = lib.name(ti.name_offset());
                let _ = lib.guid(ti.guid_offset());

                // Try iterating funcs/vars -- should not panic
                for func in lib.funcs(&ti) {
                    let _ = func.info();
                    let _ = func.datatype();
                    let _ = func.nrargs();
                    for param in lib.params(&func) {
                        let _ = param.datatype();
                        let _ = param.flags();
                    }
                }
                for var in lib.vars(&ti) {
                    let _ = var.info();
                    let _ = var.datatype();
                    let _ = var.offs_value();
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Strategy: random offsets into lookup methods
// ---------------------------------------------------------------------------

fn load_vbvm60() -> Vec<u8> {
    std::fs::read("tests/samples/msvbvm60.tlb").unwrap()
}

proptest! {
    /// Lookup methods with random offsets never panic on a real file.
    #[test]
    fn random_offset_lookups_never_panic(offset in any::<i32>()) {
        let data = load_vbvm60();
        let lib = TypeLib::parse(&data).unwrap();
        let _ = lib.name(offset);
        let _ = lib.guid(offset);
        let _ = lib.string(offset);
        let _ = lib.type_desc(offset);
        let _ = lib.const_value(offset);
        let _ = lib.array_desc(offset);
        let _ = lib.imp_file(offset);
        let _ = lib.resolve_hreftype(offset);
        let _ = lib.resolve_hreftype_full(offset);
        let _ = lib.segment(offset as usize);
        let _ = lib.segment_data(offset as usize);
    }

    /// TypeInfo lookup with random indices never panics.
    #[test]
    fn random_typeinfo_index_never_panics(index in any::<usize>()) {
        let data = load_vbvm60();
        let lib = TypeLib::parse(&data).unwrap();
        let _ = lib.typeinfo(index);
        let _ = lib.typeinfo_offset(index);
        let _ = lib.member_names(index);
    }

    /// const_value with all possible inline values never panics.
    #[test]
    fn inline_const_value_never_panics(raw in any::<i32>()) {
        let data = load_vbvm60();
        let lib = TypeLib::parse(&data).unwrap();
        // Negative values are inline-encoded constants
        if let Some(cv) = lib.const_value(raw) {
            let _ = cv.to_string();
        }
    }

    /// VarRecord::from_raw with random data never panics (returns Err for short buffers).
    #[test]
    fn var_record_from_raw_never_panics(data in proptest::collection::vec(any::<u8>(), 0..128)) {
        if let Ok(var) = msft_typelib::VarRecord::from_raw(&data) {
            let _ = var.info();
            let _ = var.datatype();
            let _ = var.flags();
            let _ = var.varkind();
            let _ = var.offs_value();
            let _ = var.help_context();
            let _ = var.help_string_offset();
            let _ = var.res9();
            let _ = var.cust_data_offset();
            let _ = var.helpstringcontext();
        }
    }
}

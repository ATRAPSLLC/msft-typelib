//! Integration tests that exercise the full public API against real `.tlb` files.
//!
//! The goal is to walk every code path without panicking, not to assert
//! specific output values (those belong in unit tests).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

use msft_typelib::{ConstValue, ResolvedHreftype, TypeDescription, TypeKind, TypeLib, VarRecord};

fn load_vbvm60() -> Vec<u8> {
    std::fs::read("tests/samples/msvbvm60.tlb").unwrap()
}

fn load_controls() -> Vec<u8> {
    std::fs::read("tests/samples/msvbvm60_controls.tlb").unwrap()
}

fn load_vb6_ocx() -> Vec<u8> {
    std::fs::read("tests/samples/vb6_ocx.tlb").unwrap()
}

/// Walk every accessor on [`TypeLib`] itself.
#[test]
fn walk_typelib_header() {
    for data in [load_vbvm60(), load_controls()] {
        let lib = TypeLib::parse(&data).unwrap();
        let _ = lib.data();
        let _ = lib.format_version();
        let _ = lib.lib_guid_offset();
        let _ = lib.lcid();
        let _ = lib.version();
        let _ = lib.version_major();
        let _ = lib.version_minor();
        let _ = lib.flags();
        let _ = lib.typeinfo_count();
        let _ = lib.helpstring_offset();
        let _ = lib.name_offset();
        let _ = lib.helpfile_offset();
        let _ = lib.nimpinfos();
        let _ = lib.lib_name();
        let _ = lib.lib_guid();
        let _ = lib.lib_helpstring();
    }
}

/// Walk every segment slot (0..15).
#[test]
fn walk_segments() {
    for data in [load_vbvm60(), load_controls()] {
        let lib = TypeLib::parse(&data).unwrap();
        for seg in 0..15 {
            let _ = lib.segment(seg);
            let _ = lib.segment_data(seg);
        }
    }
}

/// Iterate every TypeInfo and touch every accessor on [`TypeInfoEntry`].
#[test]
fn walk_all_typeinfos() {
    for data in [load_vbvm60(), load_controls()] {
        let lib = TypeLib::parse(&data).unwrap();

        for result in lib.typeinfos() {
            let ti = result.unwrap();
            let _ = ti.as_bytes();
            let _ = ti.typekind();
            let _ = ti.typekind_raw();
            let _ = ti.memoffset();
            let _ = ti.res2();
            let _ = ti.celement();
            let _ = ti.func_count();
            let _ = ti.var_count();
            let _ = ti.guid_offset();
            let _ = ti.flags();
            let _ = ti.name_offset();
            let _ = ti.version();
            let _ = ti.docstring_offset();
            let _ = ti.cimpltypes();
            let _ = ti.cb_size_vft();
            let _ = ti.size();
            let _ = ti.datatype1();
            let _ = ti.datatype2();

            // Resolve name and GUID through the library
            let _ = lib.name(ti.name_offset());
            let _ = lib.guid(ti.guid_offset());
            let _ = lib.string(ti.docstring_offset());
        }
    }
}

/// Walk every function record and all its accessors and parameters.
#[test]
fn walk_all_funcs_and_params() {
    for data in [load_vbvm60(), load_controls()] {
        let lib = TypeLib::parse(&data).unwrap();

        for i in 0..lib.typeinfo_count() {
            let ti = lib.typeinfo(i).unwrap();

            for (fi, func) in lib.funcs(&ti).enumerate() {
                let _ = func.as_bytes();
                let _ = func.info();
                let _ = func.record_size();
                let _ = func.datatype();
                let _ = func.flags();
                let _ = func.vtable_offset();
                let _ = func.funcdesc_size();
                let _ = func.fkccic();
                let _ = func.func_kind();
                let _ = func.invoke_kind();
                let _ = func.callconv();
                let _ = func.nrargs();
                let _ = func.nroargs();
                let _ = func.help_context();
                let _ = func.help_string_offset();
                let _ = func.oentry();
                let _ = (func.res9(), func.res_a());

                let _ = lib.func_name(&ti, fi);
                let _ = lib.func_memid(&ti, fi);

                for param in lib.params(&func) {
                    let _ = param.datatype();
                    let _ = param.name_offset();
                    let _ = param.flags();
                    let _ = param.is_in();
                    let _ = param.is_out();
                    let _ = param.is_retval();
                    let _ = param.is_optional();
                    let _ = lib.name(param.name_offset());
                }
            }
        }
    }
}

/// Walk every variable record and all its accessors, including const values.
#[test]
fn walk_all_vars_and_consts() {
    for data in [load_vbvm60(), load_controls()] {
        let lib = TypeLib::parse(&data).unwrap();

        for i in 0..lib.typeinfo_count() {
            let ti = lib.typeinfo(i).unwrap();

            for (vi, var) in lib.vars(&ti).enumerate() {
                let _ = var.as_bytes();
                let _ = var.info();
                let _ = var.record_size();
                let _ = var.datatype();
                let _ = var.flags();
                let _ = var.varkind();
                let _ = var.vardesc_size();
                let _ = var.offs_value();
                let _ = var.help_context();
                let _ = var.help_string_offset();
                let _ = var.res9();
                let _ = var.cust_data_offset();
                let _ = var.helpstringcontext();

                let _ = lib.var_name(&ti, vi);
                let _ = lib.var_memid(&ti, vi);

                // Decode the constant value if this is VAR_CONST
                if var.varkind() == 2
                    && let Some(cv) = lib.const_value(var.offs_value())
                {
                    let _ = cv.to_string();
                }
            }
        }
    }
}

/// Walk the GUID table and exercise [`GuidEntry`] / [`Guid`] accessors.
#[test]
fn walk_guid_table() {
    for data in [load_vbvm60(), load_controls()] {
        let lib = TypeLib::parse(&data).unwrap();

        for entry in lib.guids() {
            let guid = entry.guid();
            let _ = guid.as_bytes();
            let _ = guid.data1();
            let _ = guid.data2();
            let _ = guid.data3();
            let _ = guid.data4();
            let _ = guid.to_string();
            let _ = format!("{:?}", guid);
            let _ = entry.hreftype();
            let _ = entry.next_hash();
        }
    }
}

/// Walk the name table and exercise [`NameEntry`] accessors.
#[test]
fn walk_name_table() {
    for data in [load_vbvm60(), load_controls()] {
        let lib = TypeLib::parse(&data).unwrap();

        for entry in lib.names() {
            let _ = entry.offset();
            let _ = entry.name();
            let _ = entry.hreftype();

            // Round-trip: look up by offset
            let _ = lib.name(entry.offset() as i32);
        }
    }
}

/// Walk coclass impl-type chains.
#[test]
fn walk_impl_types() {
    for data in [load_vbvm60(), load_controls()] {
        let lib = TypeLib::parse(&data).unwrap();

        for i in 0..lib.typeinfo_count() {
            let ti = lib.typeinfo(i).unwrap();
            if ti.typekind() != TypeKind::CoClass {
                continue;
            }
            for ref_rec in lib.impl_types(&ti) {
                let _ = ref_rec.reftype();
                let _ = ref_rec.flags();
                let _ = ref_rec.onext();
                let _ = ref_rec.is_default();
                let _ = ref_rec.is_source();
                let _ = ref_rec.is_restricted();
                let _ = lib.resolve_hreftype(ref_rec.reftype());
            }
        }
    }
}

/// Walk import-info entries.
#[test]
fn walk_imports() {
    for data in [load_vbvm60(), load_controls()] {
        let lib = TypeLib::parse(&data).unwrap();

        for imp in lib.imports() {
            let _ = imp.flags();
            let _ = imp.imp_file_offset();
            let _ = imp.guid_offset();
        }
    }
}

/// Resolve all type descriptors referenced by functions and variables.
#[test]
fn walk_type_descriptors() {
    for data in [load_vbvm60(), load_controls()] {
        let lib = TypeLib::parse(&data).unwrap();

        for i in 0..lib.typeinfo_count() {
            let ti = lib.typeinfo(i).unwrap();

            for func in lib.funcs(&ti) {
                let _ = lib.type_desc(func.datatype());
            }
            for var in lib.vars(&ti) {
                let _ = lib.type_desc(var.datatype());
            }

            // Alias types
            if ti.typekind() == TypeKind::Alias {
                let _ = lib.type_desc(ti.datatype1());
                let _ = lib.type_desc(ti.datatype2());
            }
        }
    }
}

/// Exercise [`TypeLib::member_names`] on every TypeInfo.
#[test]
fn walk_member_names() {
    for data in [load_vbvm60(), load_controls()] {
        let lib = TypeLib::parse(&data).unwrap();

        for i in 0..lib.typeinfo_count() {
            let _ = lib.member_names(i);
            let _ = lib.typeinfo_offset(i);
        }
    }
}

/// Exercise [`TypeKind`] Display impl for all variants.
#[test]
fn typekind_display() {
    for data in [load_vbvm60(), load_controls()] {
        let lib = TypeLib::parse(&data).unwrap();

        for i in 0..lib.typeinfo_count() {
            let ti = lib.typeinfo(i).unwrap();
            let _ = ti.typekind().to_string();
        }
    }
}

/// [`VarRecord::from_raw`] accepts a valid-sized buffer.
#[test]
fn var_record_from_raw_smoke() {
    let buf = [0u8; 0x14];
    let var = VarRecord::from_raw(&buf).unwrap();
    let _ = var.info();
    let _ = var.datatype();
}

/// Error types implement Display without panicking.
#[test]
fn error_display_smoke() {
    let short = TypeLib::parse(&[0u8; 10]).err().unwrap();
    let _ = short.to_string();

    let mut bad = load_vbvm60();
    bad[0] = 0xFF;
    let magic = TypeLib::parse(&bad).err().unwrap();
    let _ = magic.to_string();

    let data = load_vbvm60();
    let lib = TypeLib::parse(&data).unwrap();
    let oor = lib.typeinfo(9999).unwrap_err();
    let _ = oor.to_string();
}

/// Walk all new Phase 1 header accessors.
#[test]
fn walk_new_header_fields() {
    for data in [load_vbvm60(), load_controls()] {
        let lib = TypeLib::parse(&data).unwrap();
        let _ = lib.lcid2();
        let _ = lib.varflags();
        let _ = lib.syskind();
        let _ = lib.has_help_dll();
        let _ = lib.helpstringcontext();
        let _ = lib.helpcontext();
        let _ = lib.nametablecount();
        let _ = lib.nametablechars();
        let _ = lib.custom_data_offset();
        let _ = lib.dispatchpos();
        let _ = lib.guid_hash_data();
        let _ = lib.name_hash_data();
    }
}

/// Walk new TypeInfoEntry fields.
#[test]
fn walk_new_typeinfo_fields() {
    for data in [load_vbvm60(), load_controls()] {
        let lib = TypeLib::parse(&data).unwrap();
        for i in 0..lib.typeinfo_count() {
            let ti = lib.typeinfo(i).unwrap();
            let _ = ti.helpstringcontext();
            let _ = ti.helpcontext();
            let _ = ti.cust_data_offset();
            let _ = ti.res3();
            let _ = ti.res18();
            let _ = ti.res19();
        }
    }
}

/// Walk expanded NameEntry fields.
#[test]
fn walk_name_entry_fields() {
    for data in [load_vbvm60(), load_controls()] {
        let lib = TypeLib::parse(&data).unwrap();
        for entry in lib.names() {
            let _ = entry.offset();
            let _ = entry.name();
            let _ = entry.hreftype();
            let _ = entry.next_hash();
            let _ = entry.name_flags();
            let _ = entry.hashcode();
        }
    }
}

/// Walk new FuncRecord attributes.
#[test]
fn walk_new_func_attrs() {
    for data in [load_vbvm60(), load_controls()] {
        let lib = TypeLib::parse(&data).unwrap();
        for i in 0..lib.typeinfo_count() {
            let ti = lib.typeinfo(i).unwrap();
            for func in lib.funcs(&ti) {
                let _ = func.helpstringcontext();
                let _ = func.cust_data_offset();
                let _ = func.has_cust_data();
                let _ = func.has_arg_cust_data();
                let nrargs = func.nrargs().max(0) as usize;
                for ai in 0..nrargs {
                    let _ = func.arg_cust_data_offset(ai);
                }
            }
        }
    }
}

/// Walk import file entries.
#[test]
fn walk_imp_files() {
    for data in [load_vbvm60(), load_controls()] {
        let lib = TypeLib::parse(&data).unwrap();
        for imp_file in lib.imp_files() {
            let _ = imp_file.guid_offset();
            let _ = imp_file.lcid();
            let _ = imp_file.major_version();
            let _ = imp_file.minor_version();
            let _ = imp_file.size_field();
            let _ = imp_file.filename();
            let _ = imp_file.entry_size();
        }

        // Resolve each ImpInfo to its ImpFile
        for imp in lib.imports() {
            let _ = lib.imp_file(imp.imp_file_offset());
        }
    }
}

/// Walk custom data chains from library and TypeInfo levels.
#[test]
fn walk_cust_data() {
    for data in [load_vbvm60(), load_controls()] {
        let lib = TypeLib::parse(&data).unwrap();

        for entry in lib.lib_cust_data() {
            let _ = entry.guid_offset();
            let _ = entry.data_offset();
            let _ = entry.next();
            let _ = lib.resolve_cust_data_entry(&entry);
        }

        for i in 0..lib.typeinfo_count() {
            let ti = lib.typeinfo(i).unwrap();
            for entry in lib.cust_data(ti.cust_data_offset()) {
                let _ = lib.resolve_cust_data_entry(&entry);
            }
        }
    }
}

/// Walk array descriptors for any VT_CARRAY types found.
#[test]
fn walk_array_descs() {
    for data in [load_vbvm60(), load_controls()] {
        let lib = TypeLib::parse(&data).unwrap();
        for i in 0..lib.typeinfo_count() {
            let ti = lib.typeinfo(i).unwrap();
            for func in lib.funcs(&ti) {
                if let Some((vt, extra)) = lib.type_desc(func.datatype())
                    && (vt as u32 & 0xFFF) == 28
                    && let Some(ad) = lib.array_desc(extra)
                {
                    let _ = ad.element_type();
                    let _ = ad.num_dims();
                    let _ = ad.flags();
                    let _ = ad.size();
                    for d in 0..ad.num_dims() as usize {
                        if let Some(b) = ad.bound(d) {
                            let _ = b.count();
                            let _ = b.lower_bound();
                        }
                    }
                }
            }
        }
    }
}

/// Test resolve_hreftype_full on both internal and external refs.
#[test]
fn walk_resolve_hreftype_full() {
    for data in [load_vbvm60(), load_controls()] {
        let lib = TypeLib::parse(&data).unwrap();

        for i in 0..lib.typeinfo_count() {
            let ti = lib.typeinfo(i).unwrap();
            if ti.typekind() != TypeKind::CoClass {
                continue;
            }
            for ref_rec in lib.impl_types(&ti) {
                match lib.resolve_hreftype_full(ref_rec.reftype()) {
                    Some(ResolvedHreftype::Internal(idx)) => {
                        let _ = lib.typeinfo(idx);
                    }
                    Some(ResolvedHreftype::External { imp_info, imp_file }) => {
                        let _ = imp_info.flags();
                        if let Some(f) = imp_file {
                            let _ = f.filename();
                        }
                    }
                    None => {}
                }
            }
        }
    }
}

/// ConstValue Display for all variants.
#[test]
fn constvalue_display_all_variants() {
    use msft_typelib::ConstValue;
    let variants: Vec<ConstValue<'_>> = vec![
        ConstValue::Empty,
        ConstValue::Null,
        ConstValue::I2(42),
        ConstValue::I4(100),
        ConstValue::R4(1.5),
        ConstValue::R8(2.5),
        ConstValue::Cy(15000),
        ConstValue::Date(44000.0),
        ConstValue::Bstr(b"hello"),
        ConstValue::Error(0x80004005_u32 as i32),
        ConstValue::Bool(true),
        ConstValue::I1(-1),
        ConstValue::UI1(255),
        ConstValue::UI2(65535),
        ConstValue::UI4(0xDEADBEEF),
        ConstValue::I8(-9999),
        ConstValue::UI8(u64::MAX),
        ConstValue::Int(-42),
        ConstValue::UInt(42),
        ConstValue::Void,
        ConstValue::Hresult(0),
        ConstValue::Filetime(0),
        ConstValue::Raw { vt: 99, bits: 0 },
    ];
    for v in &variants {
        let _ = v.to_string();
    }
}

/// A library the VB6 compiler embeds in an ActiveX control (`HELPDLLFLAG`
/// clear, so no help-DLL field before the segment directory): its
/// coclasses' interfaces and its event dispinterfaces.
#[test]
fn vb6_compiled_library() {
    let data = std::fs::read("tests/samples/vb6_ocx.tlb").unwrap();
    let lib = TypeLib::parse(&data).unwrap();
    assert!(!lib.has_help_dll());
    assert_eq!(lib.lib_name(), Some("OcxLib"));
    assert_eq!(lib.typeinfo_count(), 8);
    let name_of = |index: usize| {
        let ti = lib.typeinfo(index).unwrap();
        lib.name(ti.name_offset()).unwrap().to_string()
    };
    let mut coclasses = Vec::new();
    let mut events = Vec::new();
    for index in 0..lib.typeinfo_count() {
        let ti = lib.typeinfo(index).unwrap();
        let name = lib.name(ti.name_offset()).unwrap();
        match ti.typekind() {
            TypeKind::CoClass => {
                let impls: Vec<String> = lib
                    .impl_types(&ti)
                    .map(|r| name_of(lib.resolve_hreftype(r.reftype()).unwrap()))
                    .collect();
                coclasses.push((name.to_string(), impls));
            }
            TypeKind::Dispatch if name.starts_with("__") => {
                let funcs: Vec<(String, i32)> = (0..usize::from(ti.func_count()))
                    .map(|k| {
                        (
                            lib.func_name(&ti, k).unwrap().to_string(),
                            lib.func_memid(&ti, k).unwrap(),
                        )
                    })
                    .collect();
                events.push((name.to_string(), funcs));
            }
            _ => {}
        }
    }
    let pair = |c: &str, i: &[&str]| {
        (
            c.to_string(),
            i.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
    };
    assert_eq!(
        coclasses,
        [
            pair("Knob", &["_Knob", "__Knob"]),
            pair("Panel", &["_Panel", "__Panel"]),
            pair("KnobPage", &["_KnobPage"]),
        ]
    );
    assert_eq!(
        events,
        [
            (
                "__Knob".to_string(),
                vec![("Turned".to_string(), 1), ("Reset".to_string(), 2)]
            ),
            ("__Panel".to_string(), vec![("Summary".to_string(), 1)]),
        ]
    );
}

/// An hreftype whose low two bits are set names an import, whatever its
/// value divided by the TypeInfo size would index: `_Knob` derives from
/// stdole's `IDispatch`, hreftype 0x1, which once resolved to TypeInfo 0.
#[test]
fn an_imported_base_interface_resolves_as_an_import() {
    let data = load_vb6_ocx();
    let lib = TypeLib::parse(&data).unwrap();
    let knob = (0..lib.typeinfo_count())
        .map(|i| lib.typeinfo(i).unwrap())
        .find(|ti| lib.name(ti.name_offset()) == Some("_Knob"))
        .expect("the library declares _Knob");
    let base = knob.datatype1();
    assert_eq!(base & 0x03, 1, "an import reference");
    assert_eq!(lib.resolve_hreftype(base), None);
    match lib.resolve_hreftype_full(base) {
        Some(ResolvedHreftype::External { imp_file, .. }) => {
            let file = imp_file.and_then(|f| f.filename()).unwrap_or_default();
            assert!(file.to_ascii_lowercase().contains("stdole"), "{file}");
        }
        other => panic!("resolved as {other:?}"),
    }
}

/// Every type a function names decodes, level by level: a pointer or safe
/// array to a decodable type, a user-defined type by hreftype, a C array, or
/// a base type.
#[test]
fn every_function_type_decodes() {
    fn decodes(lib: &TypeLib<'_>, datatype: i32, depth: u32) -> bool {
        depth < 16
            && match lib.type_description(datatype) {
                Some(TypeDescription::Pointer(inner) | TypeDescription::SafeArray(inner)) => {
                    decodes(lib, inner, depth + 1)
                }
                Some(TypeDescription::CArray(array)) => {
                    decodes(lib, array.element_type(), depth + 1)
                }
                Some(TypeDescription::Base(_) | TypeDescription::UserDefined(_)) => true,
                None => false,
            }
    }
    let mut pointers = 0;
    for data in [load_vbvm60(), load_controls(), load_vb6_ocx()] {
        let lib = TypeLib::parse(&data).unwrap();
        for ti in (0..lib.typeinfo_count()).map(|i| lib.typeinfo(i).unwrap()) {
            for func in lib.funcs(&ti) {
                let types =
                    std::iter::once(func.datatype()).chain(lib.params(&func).map(|p| p.datatype()));
                for datatype in types {
                    assert!(decodes(&lib, datatype, 0), "type field {datatype:#x}");
                    if matches!(
                        lib.type_description(datatype),
                        Some(TypeDescription::Pointer(_))
                    ) {
                        pointers += 1;
                    }
                }
            }
        }
    }
    assert!(pointers > 0, "the samples pass parameters by reference");
}

/// A parameter's default value is read from the array before the parameter
/// records, present when FKCCIC bit 12 is set: VBA's `InStr` defaults its
/// `Compare` to `vbBinaryCompare` (0), `Hyperlink.NavigateTo` its `Location`
/// and `FrameName` to empty strings.
#[test]
fn parameter_defaults_are_read() {
    let default_of = |data: &[u8], type_name: &str, func_name: &str, index: usize| {
        let lib = TypeLib::parse(data).unwrap();
        let ti = (0..lib.typeinfo_count())
            .map(|i| lib.typeinfo(i).unwrap())
            .find(|ti| lib.name(ti.name_offset()) == Some(type_name))
            .unwrap();
        let (_, func) = lib
            .funcs(&ti)
            .enumerate()
            .find(|(fi, _)| lib.func_name(&ti, *fi) == Some(func_name))
            .unwrap();
        assert!(func.has_default_values());
        let param = lib.params(&func).nth(index).unwrap();
        assert_ne!(param.flags() & 0x20, 0, "PARAMFLAG_FHASDEFAULT");
        format!(
            "{:?}",
            func.default_value_offset(index)
                .and_then(|o| lib.const_value(o))
        )
    };
    assert_eq!(
        default_of(&load_vbvm60(), "Strings", "InStr", 3),
        format!("{:?}", Some(ConstValue::I4(0)))
    );
    assert_eq!(
        default_of(&load_controls(), "Hyperlink", "NavigateTo", 1),
        format!("{:?}", Some(ConstValue::Bstr(&[])))
    );
}

/// A function record's optional attributes are Wine's `MSFT_FuncRecord`:
/// help context, help string, entry, two reserved words (-1), the help
/// string context, then custom data. The controls library gives each
/// function the same help context and help string context, which the two
/// reserved words once stood in for.
#[test]
fn function_attributes_follow_the_record_layout() {
    for data in [load_vbvm60(), load_controls()] {
        let lib = TypeLib::parse(&data).unwrap();
        for ti in (0..lib.typeinfo_count()).map(|i| lib.typeinfo(i).unwrap()) {
            for func in lib.funcs(&ti) {
                for reserved in [func.res9(), func.res_a()].into_iter().flatten() {
                    assert_eq!(reserved, -1);
                }
                if func.cust_data_offset().is_some() {
                    assert!(func.has_cust_data());
                }
            }
        }
    }
    let data = load_controls();
    let lib = TypeLib::parse(&data).unwrap();
    let mut paired = 0;
    for ti in (0..lib.typeinfo_count()).map(|i| lib.typeinfo(i).unwrap()) {
        for func in lib.funcs(&ti) {
            if let (Some(context), Some(string_context)) =
                (func.help_context(), func.helpstringcontext())
                && context != 0
            {
                assert_eq!(context, string_context);
                paired += 1;
            }
        }
    }
    assert!(paired > 100, "{paired}");
}

/// TypeInfo `i` is the `i`-th of the TypeInfo segment, in a library with a
/// help-string DLL field before its offset table as in one without: the
/// runtime library's first type is `PaletteModeConstants`, and every type of
/// all three samples has a name.
#[test]
fn typeinfos_are_read_in_order() {
    let data = load_controls();
    let lib = TypeLib::parse(&data).unwrap();
    assert!(lib.has_help_dll());
    let first = lib.typeinfo(0).unwrap();
    assert_eq!(lib.name(first.name_offset()), Some("PaletteModeConstants"));
    for data in [load_vbvm60(), load_controls(), load_vb6_ocx()] {
        let lib = TypeLib::parse(&data).unwrap();
        for index in 0..lib.typeinfo_count() {
            let ti = lib.typeinfo(index).unwrap();
            assert!(lib.name(ti.name_offset()).is_some(), "TypeInfo {index}");
            assert_eq!(lib.typeinfo_offset(index), i32::try_from(index * 0x64).ok());
        }
    }
}

use crate::*;

fn load_vbvm60() -> Vec<u8> {
    std::fs::read("tests/samples/msvbvm60.tlb").unwrap()
}

fn load_controls() -> Vec<u8> {
    std::fs::read("tests/samples/msvbvm60_controls.tlb").unwrap()
}

#[test]
fn parse_vbvm60_header() {
    let data = load_vbvm60();
    let lib = TypeLib::parse(&data).unwrap();
    assert_eq!(lib.typeinfo_count(), 29);
    assert_eq!(lib.version_major(), 6);
    assert_eq!(lib.version_minor(), 0);
    assert_eq!(lib.lcid(), 0x0009);
}

#[test]
fn parse_controls_header() {
    let data = load_controls();
    let lib = TypeLib::parse(&data).unwrap();
    assert_eq!(lib.typeinfo_count(), 96);
    assert_eq!(lib.version_major(), 6);
}

#[test]
fn lib_name_and_guid() {
    let data = load_vbvm60();
    let lib = TypeLib::parse(&data).unwrap();
    assert!(lib.lib_name().is_some());
    let guid = lib.lib_guid().unwrap();
    let s = guid.to_string();
    assert!(s.starts_with('{'));
    assert_eq!(s.len(), 38);
}

#[test]
fn typeinfo_names_exist() {
    let data = load_vbvm60();
    let lib = TypeLib::parse(&data).unwrap();
    let named = (0..lib.typeinfo_count())
        .filter_map(|i| lib.typeinfo(i).ok())
        .filter(|ti| lib.name(ti.name_offset()).is_some())
        .count();
    assert!(named > 0);
}

#[test]
fn guid_table_iteration() {
    let data = load_vbvm60();
    let lib = TypeLib::parse(&data).unwrap();
    assert!(lib.guids().count() > 0);
}

#[test]
fn vbvartype_enum_members() {
    let data = load_vbvm60();
    let lib = TypeLib::parse(&data).unwrap();
    let ti = lib.typeinfo(1).unwrap();
    assert_eq!(ti.typekind(), TypeKind::Enum);
    assert_eq!(lib.name(ti.name_offset()), Some("VbVarType"));
    assert_eq!(ti.var_count(), 18);
    assert_eq!(ti.func_count(), 0);

    assert_eq!(lib.var_name(&ti, 0), Some("vbEmpty"));
    assert_eq!(lib.var_name(&ti, 1), Some("vbNull"));
    assert_eq!(lib.var_name(&ti, 15), Some("vbByte"));

    let vars: Vec<_> = lib.vars(&ti).collect();
    assert_eq!(vars.len(), 18);
    assert!(matches!(
        lib.const_value(vars[0].offs_value()),
        Some(ConstValue::I4(0))
    ));
    assert!(matches!(
        lib.const_value(vars[8].offs_value()),
        Some(ConstValue::I4(8))
    ));
    assert!(matches!(
        lib.const_value(vars[17].offs_value()),
        Some(ConstValue::I4(8192))
    ));
}

#[test]
fn vbtristate_negative_values() {
    let data = load_vbvm60();
    let lib = TypeLib::parse(&data).unwrap();
    let ti = lib.typeinfo(13).unwrap();
    assert_eq!(lib.name(ti.name_offset()), Some("VbTriState"));
    let vars: Vec<_> = lib.vars(&ti).collect();
    assert_eq!(vars.len(), 3);
    assert!(matches!(
        lib.const_value(vars[0].offs_value()),
        Some(ConstValue::I4(-2))
    ));
    assert!(matches!(
        lib.const_value(vars[1].offs_value()),
        Some(ConstValue::I4(-1))
    ));
    assert!(matches!(
        lib.const_value(vars[2].offs_value()),
        Some(ConstValue::I4(0))
    ));
}

#[test]
fn errobject_dispatch_funcs() {
    let data = load_vbvm60();
    let lib = TypeLib::parse(&data).unwrap();
    let ti = lib.typeinfo(26).unwrap();
    assert_eq!(ti.typekind(), TypeKind::Dispatch);
    assert_eq!(lib.name(ti.name_offset()), Some("_ErrObject"));
    assert_eq!(ti.func_count(), 13);

    assert_eq!(lib.func_name(&ti, 0), Some("Number"));
    assert_eq!(lib.func_name(&ti, 10), Some("Raise"));
    assert_eq!(lib.func_name(&ti, 11), Some("Clear"));
    assert_eq!(lib.func_memid(&ti, 0), Some(0));
}

#[test]
fn collection_dispids() {
    let data = load_vbvm60();
    let lib = TypeLib::parse(&data).unwrap();
    let ti = lib.typeinfo(28).unwrap();
    assert_eq!(lib.name(ti.name_offset()), Some("_Collection"));
    assert_eq!(lib.func_memid(&ti, 4), Some(-4));
}

#[test]
fn constants_module_string_values() {
    let data = load_vbvm60();
    let lib = TypeLib::parse(&data).unwrap();
    let ti = lib.typeinfo(15).unwrap();
    assert_eq!(ti.typekind(), TypeKind::Module);
    assert_eq!(lib.name(ti.name_offset()), Some("Constants"));
    assert_eq!(ti.var_count(), 11);

    assert_eq!(lib.var_name(&ti, 0), Some("vbObjectError"));
    let vars: Vec<_> = lib.vars(&ti).collect();
    assert!(matches!(
        lib.const_value(vars[0].offs_value()),
        Some(ConstValue::I4(-2147221504))
    ));
}

#[test]
fn controls_func_iteration() {
    let data = load_controls();
    let lib = TypeLib::parse(&data).unwrap();
    let total_funcs: usize = (0..lib.typeinfo_count())
        .filter_map(|i| lib.typeinfo(i).ok())
        .map(|ti| lib.funcs(&ti).count())
        .sum();
    assert!(total_funcs > 100);
}

#[test]
fn name_table_iteration() {
    let data = load_vbvm60();
    let lib = TypeLib::parse(&data).unwrap();
    assert!(lib.names().count() > 0);
}

#[test]
fn bad_magic_rejected() {
    let mut data = load_vbvm60();
    data[0] = 0xFF;
    assert!(TypeLib::parse(&data).is_err());
}

#[test]
fn too_short_rejected() {
    let data = [0u8; 10];
    assert!(TypeLib::parse(&data).is_err());
}

#[test]
fn typeinfo_out_of_range() {
    let data = load_vbvm60();
    let lib = TypeLib::parse(&data).unwrap();
    assert!(lib.typeinfo(999).is_err());
}

#[test]
fn controls_has_dispatch_typeinfos() {
    let data = load_controls();
    let lib = TypeLib::parse(&data).unwrap();
    let count = (0..lib.typeinfo_count())
        .filter_map(|i| lib.typeinfo(i).ok())
        .filter(|ti| ti.typekind() == TypeKind::Dispatch)
        .count();
    assert!(count > 0);
}

#[test]
fn controls_has_coclass_typeinfos() {
    let data = load_controls();
    let lib = TypeLib::parse(&data).unwrap();
    let count = (0..lib.typeinfo_count())
        .filter_map(|i| lib.typeinfo(i).ok())
        .filter(|ti| ti.typekind() == TypeKind::CoClass)
        .count();
    assert!(count > 0);
}

#[test]
fn var_record_from_raw_too_short() {
    let data = [0u8; 4];
    assert!(VarRecord::from_raw(&data).is_err());
}

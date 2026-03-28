//! Dumps all type information from an MSFT-format type library (.tlb) file.

use msft_typelib::{ResolvedHreftype, TypeKind, TypeLib};
use std::{env, fs, process};

fn main() {
    let path = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: dump <path-to-tlb>");
        process::exit(1);
    });

    let data = fs::read(&path).unwrap_or_else(|e| {
        eprintln!("error: cannot read '{path}': {e}");
        process::exit(1);
    });

    let lib = TypeLib::parse(&data).unwrap_or_else(|e| {
        eprintln!("error: failed to parse type library: {e}");
        process::exit(1);
    });

    dump_typelib(&lib);
}

fn dump_typelib(lib: &TypeLib<'_>) {
    println!("TypeLib: {}", lib.lib_name().unwrap_or("<unnamed>"));
    println!("  Version: {}.{}", lib.version_major(), lib.version_minor());
    if let Some(guid) = lib.lib_guid() {
        println!("  GUID: {guid}");
    }
    println!("  LCID: 0x{:04X}", lib.lcid());
    if let Some(hs) = lib.lib_helpstring()
        && !hs.is_empty()
    {
        println!("  HelpString: {hs}");
    }
    println!("  TypeInfos: {}", lib.typeinfo_count());

    for i in 0..lib.typeinfo_count() {
        let ti = match lib.typeinfo(i) {
            Ok(ti) => ti,
            Err(e) => {
                println!("\n  [{i}] <error: {e}>");
                continue;
            }
        };

        let kind = ti.typekind();
        let name = lib.name(ti.name_offset()).unwrap_or("<unnamed>");
        let guid_str = lib
            .guid(ti.guid_offset())
            .map(|g| format!(" {g}"))
            .unwrap_or_default();

        println!("\n  [{i}] {kind} {name}{guid_str}");

        match kind {
            TypeKind::Enum => dump_vars(lib, &ti),
            TypeKind::Record | TypeKind::Union => dump_vars(lib, &ti),
            TypeKind::Module => {
                dump_funcs(lib, &ti, false);
                dump_vars(lib, &ti);
            }
            TypeKind::Interface => dump_funcs(lib, &ti, false),
            TypeKind::Dispatch => {
                dump_funcs(lib, &ti, true);
                dump_vars(lib, &ti);
            }
            TypeKind::CoClass => dump_coclass(lib, &ti),
            TypeKind::Alias => dump_alias(lib, &ti),
            _ => {}
        }
    }
}

fn dump_vars(lib: &TypeLib<'_>, ti: &msft_typelib::TypeInfoEntry<'_>) {
    for (vi, var) in lib.vars(ti).enumerate() {
        let name = lib.var_name(ti, vi).unwrap_or("?");
        let type_str = format_type(lib, var.datatype());
        if var.varkind() == 2 {
            // VAR_CONST
            let val = lib
                .const_value(var.offs_value())
                .map(|v| format!("{v}"))
                .unwrap_or_else(|| format!("0x{:08X}", var.offs_value()));
            println!("    {name} = {val}");
        } else {
            println!("    {name} As {type_str}");
        }
    }
}

fn dump_funcs(lib: &TypeLib<'_>, ti: &msft_typelib::TypeInfoEntry<'_>, show_dispid: bool) {
    for (fi, func) in lib.funcs(ti).enumerate() {
        let name = lib.func_name(ti, fi).unwrap_or("?");
        let memid = lib.func_memid(ti, fi);

        let invoke = func.invoke_kind();
        let prefix = match invoke {
            2 => "Property Get ",
            4 => "Property Put ",
            8 => "Property PutRef ",
            _ => "",
        };

        let params: Vec<String> = lib
            .params(&func)
            .map(|p| {
                let pname = lib.name(p.name_offset()).unwrap_or("param");
                let ptype = format_type(lib, p.datatype());
                let mut parts = String::new();
                if p.is_optional() {
                    parts.push_str("[Optional] ");
                }
                if p.is_retval() {
                    parts.push_str("[RetVal] ");
                }
                format!("{parts}{pname} As {ptype}")
            })
            .collect();
        let params_str = params.join(", ");

        let ret_type = format_type(lib, func.datatype());
        let ret_str = if ret_type == "void" {
            String::new()
        } else {
            format!(" As {ret_type}")
        };

        let mut suffix = String::new();
        if show_dispid
            && let Some(mid) = memid
        {
            suffix.push_str(&format!(" dispid={mid}"));
        }
        suffix.push_str(&format!(" vtable=0x{:04X}", func.vtable_offset()));

        println!("    [{fi}] {prefix}{name}({params_str}){ret_str}{suffix}");
    }
}

fn dump_coclass(lib: &TypeLib<'_>, ti: &msft_typelib::TypeInfoEntry<'_>) {
    for ref_rec in lib.impl_types(ti) {
        let hreftype = ref_rec.reftype();
        let iface_name = lib
            .resolve_hreftype(hreftype)
            .and_then(|idx| lib.typeinfo(idx).ok())
            .and_then(|iti| lib.name(iti.name_offset()));

        let name_str = iface_name.unwrap_or("?");
        let mut flags_parts = Vec::new();
        if ref_rec.is_default() {
            flags_parts.push("default");
        }
        if ref_rec.is_source() {
            flags_parts.push("source");
        }
        if ref_rec.is_restricted() {
            flags_parts.push("restricted");
        }
        if let Some(idx) = lib.resolve_hreftype(hreftype)
            && let Ok(iti) = lib.typeinfo(idx)
            && iti.typekind() == TypeKind::Dispatch
        {
            flags_parts.push("dispatch");
        }
        let flags_str = if flags_parts.is_empty() {
            String::new()
        } else {
            format!(" ({})", flags_parts.join(", "))
        };
        println!("    implements {name_str}{flags_str}");
    }
}

fn dump_alias(lib: &TypeLib<'_>, ti: &msft_typelib::TypeInfoEntry<'_>) {
    let type_str = format_type(lib, ti.datatype1());
    println!("    aliased to {type_str}");
}

fn format_type(lib: &TypeLib<'_>, datatype: i32) -> String {
    // Walk the type descriptor chain iteratively, collecting wrappers
    // (e.g. VT_PTR, VT_SAFEARRAY) that surround the leaf type.
    let mut current = datatype;
    let mut wrappers: Vec<u16> = Vec::new();

    for _ in 0..11 {
        if current < 0 {
            break;
        }
        match lib.type_desc(current) {
            Some((vt, extra)) => {
                let inner_vt = (vt as u32 & 0xFFF) as u16;
                match inner_vt {
                    // VT_PTR / VT_SAFEARRAY: peel one layer and continue
                    26 | 27 => {
                        wrappers.push(inner_vt);
                        current = extra;
                    }
                    // VT_USERDEFINED: resolve to a name and stop
                    29 => {
                        let name = match lib.resolve_hreftype_full(extra) {
                            Some(ResolvedHreftype::Internal(idx)) => lib
                                .typeinfo(idx)
                                .ok()
                                .and_then(|ti| lib.name(ti.name_offset()))
                                .map(String::from)
                                .unwrap_or_else(|| format!("TypeInfo({idx})")),
                            Some(ResolvedHreftype::External { imp_file, .. }) => imp_file
                                .and_then(|f| f.filename().map(String::from))
                                .unwrap_or_else(|| format!("External(href={extra})")),
                            None => format!("UserDefined(href={extra})"),
                        };
                        return wrap_type(name, &wrappers);
                    }
                    // Any other VT code: leaf type
                    _ => {
                        return wrap_type(msft_typelib::vt_name(inner_vt).to_string(), &wrappers);
                    }
                }
            }
            None => return wrap_type(format!("type({current})"), &wrappers),
        }
    }

    // `current` is now negative (inline VT) or we exhausted the depth limit
    let leaf = if current == -1 {
        "void".to_string()
    } else if current < 0 {
        let vt = (current as u32 & 0xFFF) as u16;
        msft_typelib::vt_name(vt).to_string()
    } else {
        "...".to_string()
    };
    wrap_type(leaf, &wrappers)
}

/// Apply collected wrappers (outermost first) around a leaf type name.
fn wrap_type(mut name: String, wrappers: &[u16]) -> String {
    for &vt in wrappers.iter().rev() {
        match vt {
            26 => name = format!("{name}*"),
            27 => name = format!("SafeArray({name})"),
            _ => {}
        }
    }
    name
}

# msft-typelib

Allocation-free parser for MSFT-format type library (`.tlb`) files.

MSFT is the binary format used by Microsoft COM type libraries since the late 1990s. A type library describes the interfaces, coclasses, enumerations, and constants exposed by a COM component so that tools and languages can use them at compile time or runtime.

## Features

- **Zero-allocation** -- record types borrow directly from the input `&[u8]`; parsing requires no heap allocations beyond loading the file
- **Full format coverage** -- parses all 13 active segments (TypeInfo, functions, variables, parameters, GUIDs, names, strings, type descriptors, array descriptors, imports, custom data, and more)
- **Type resolution** -- resolves `VT_PTR`, `VT_SAFEARRAY`, `VT_USERDEFINED`, and `VT_CARRAY` type descriptor chains
- **Import resolution** -- resolves external type references through the import-info and import-files tables
- **Custom data** -- walks per-library, per-type, per-function, and per-variable custom attribute chains
- **Constant decoding** -- decodes inline and segment-stored constants for 20+ `VARTYPE` codes

## Quick start

```rust
let data = std::fs::read("library.tlb").unwrap();
let lib = msft_typelib::TypeLib::parse(&data)?;

println!("Name: {}", lib.lib_name().unwrap_or("?"));
println!("GUID: {}", lib.lib_guid().unwrap());
println!("Types: {}", lib.typeinfo_count());

for result in lib.typeinfos() {
    let ti = result?;
    let name = lib.name(ti.name_offset()).unwrap_or("?");
    println!("  {} {name}", ti.typekind());
}
```

## Example

The included `dump` example prints a complete listing of a type library:

```sh
cargo run --example dump -- path/to/library.tlb
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

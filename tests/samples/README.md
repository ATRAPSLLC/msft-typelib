# Test samples

The `msvbvm60*.tlb` files in this directory are type libraries extracted
from Microsoft Visual Basic 6.0 runtime components. They are the property of
Microsoft Corporation and are included here **solely for automated testing
and interoperability research** under fair use. These files are **not**
covered by this project's Apache-2.0 license.

`vb6_ocx.tlb` is the type library of one of our own programs, compiled by
VB6.

| File | Origin |
|------|--------|
| `msvbvm60.tlb` | Type library embedded in `msvbvm60.dll` (VB6 runtime) |
| `msvbvm60_controls.tlb` | Type library embedded in `msvbvm60.dll` (VB6 controls) |
| `vb6_ocx.tlb` | Type library the VB6 compiler embedded in `ocx.ocx`, a test control of the `visualbasic` crate (our own program, not a Microsoft file) |

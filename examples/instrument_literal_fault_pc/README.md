# instrument_literal_fault_pc

Validates that AArch64 literal-load replay faults are reported at the original
patchpoint PC rather than inside the Rust replay helper.

Expected output on Linux `aarch64` with the payload loaded:

```text
fault_pc=0x... patchpoint=0x... match=1
```

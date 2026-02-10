# patchcode_add_to_mul

Demonstrates `sighook::patchcode` by replacing one instruction in `calc`.

- `aarch64`: `add w0, w8, w9` -> `mul w0, w8, w9`
- `linux x86_64`: `add eax, edx` (+ nops) -> `imul edx` (2-byte one-operand form; result in `eax`)

## Run (from repository root)

macOS:

```bash
cc -O0 -fno-inline examples/patchcode_add_to_mul/target.c -o examples/patchcode_add_to_mul/app
cargo build --example patchcode_add_to_mul
DYLD_INSERT_LIBRARIES="$PWD/target/debug/examples/libpatchcode_add_to_mul.dylib" examples/patchcode_add_to_mul/app
```

Linux:

```bash
cc -O0 -fno-inline -rdynamic examples/patchcode_add_to_mul/target.c -o examples/patchcode_add_to_mul/app
cargo build --example patchcode_add_to_mul
LD_PRELOAD="$PWD/target/debug/examples/libpatchcode_add_to_mul.so" examples/patchcode_add_to_mul/app
```

Expected output:

```text
calc(6, 7) = 42
```

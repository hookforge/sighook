# patch_asm_add_to_mul

Demonstrates `sighook::patch_asm` by assembling and patching one instruction in `calc`.

- AArch64 patch string: `mul w0, w8, w9`
- Linux x86_64 patch string: `imul %edx`

## Build

Enable feature `patch_asm`:

```bash
cargo build --example patch_asm_add_to_mul --features patch_asm
```

## Run (macOS)

```bash
cc -O0 -fno-inline examples/patch_asm_add_to_mul/target.c -o examples/patch_asm_add_to_mul/app
cargo build --example patch_asm_add_to_mul --features patch_asm
DYLD_INSERT_LIBRARIES="$PWD/target/debug/examples/libpatch_asm_add_to_mul.dylib" examples/patch_asm_add_to_mul/app
```

## Run (Linux)

```bash
cc -O0 -fno-inline -rdynamic examples/patch_asm_add_to_mul/target.c -o examples/patch_asm_add_to_mul/app
cargo build --example patch_asm_add_to_mul --features patch_asm
LD_PRELOAD="$PWD/target/debug/examples/libpatch_asm_add_to_mul.so" examples/patch_asm_add_to_mul/app
```

# inline_hook_far

Demonstrates `sighook::inline_hook_jump` at function entry.

The hook detours `target_add` to a replacement function in the injected dylib.

## Run (from repository root)

macOS:

```bash
cc -O0 -fno-inline examples/inline_hook_far/target.c -o examples/inline_hook_far/app
cargo build --example inline_hook_far
DYLD_INSERT_LIBRARIES="$PWD/target/debug/examples/libinline_hook_far.dylib" examples/inline_hook_far/app
```

Linux:

```bash
cc -O0 -fno-inline -rdynamic examples/inline_hook_far/target.c -o examples/inline_hook_far/app
cargo build --example inline_hook_far
LD_PRELOAD="$PWD/target/debug/examples/libinline_hook_far.so" examples/inline_hook_far/app
```

Expected output:

```text
target_add(6, 7) = 42
```

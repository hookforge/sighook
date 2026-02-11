# inline_hook_signal

Demonstrates `sighook::inline_hook` at function entry using trap + signal handler.

The callback writes return-value registers and lets `inline_hook` return to caller
automatically.

## Run (from repository root)

macOS:

```bash
cc -O0 -fno-inline examples/inline_hook_signal/target.c -o examples/inline_hook_signal/app
cargo build --example inline_hook_signal
DYLD_INSERT_LIBRARIES="$PWD/target/debug/examples/libinline_hook_signal.dylib" examples/inline_hook_signal/app
```

Linux:

```bash
cc -O0 -fno-inline -rdynamic examples/inline_hook_signal/target.c -o examples/inline_hook_signal/app
cargo build --example inline_hook_signal
LD_PRELOAD="$PWD/target/debug/examples/libinline_hook_signal.so" examples/inline_hook_signal/app
```

Expected output:

```text
target_add(6, 7) = 42
```

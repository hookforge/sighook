# instrument_unhook_restore

Demonstrates `sighook::instrument` + `sighook::unhook`.

Flow:

1. install an instruction hook
2. immediately call `unhook` on the same patchpoint
3. execute target function and verify original behavior is restored

The callback would force result to `123` if triggered:

- `aarch64`: set `x8 = 120`, `x9 = 3`, then original `add w0, w8, w9` runs
- `linux x86_64`: set `rax = 123`

Expected runtime output proves callback is not reached after unhook.

## Run (from repository root)

macOS:

```bash
cc -O0 -fno-inline examples/instrument_unhook_restore/target.c -o examples/instrument_unhook_restore/app
cargo build --example instrument_unhook_restore
DYLD_INSERT_LIBRARIES="$PWD/target/debug/examples/libinstrument_unhook_restore.dylib" examples/instrument_unhook_restore/app
```

Linux:

```bash
cc -O0 -fno-inline -rdynamic examples/instrument_unhook_restore/target.c -o examples/instrument_unhook_restore/app
cargo build --example instrument_unhook_restore
LD_PRELOAD="$PWD/target/debug/examples/libinstrument_unhook_restore.so" examples/instrument_unhook_restore/app
```

Expected output:

```text
calc(3, 4) = 7
```

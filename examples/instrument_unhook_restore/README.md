# instrument_unhook_restore

Demonstrates `sighook::instrument` + `sighook::unhook`.

Flow:

1. install an instruction hook
2. call `calc(3, 4)` once while hook is active and verify hooked value `123`
3. call `unhook` on the same patchpoint
4. execute target function again and verify original behavior is restored (`7`)

The callback would force result to `123` if triggered:

- `aarch64`: set `x8 = 120`, `x9 = 3`, then original `add w0, w8, w9` runs
- `linux x86_64`: set `rax = 123`

Expected runtime output proves both stages:

- callback is reached before unhook (`hooked_calc(3, 4) = 123`)
- original behavior is restored after unhook (`calc(3, 4) = 7`)

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
hooked_calc(3, 4) = 123
calc(3, 4) = 7
```

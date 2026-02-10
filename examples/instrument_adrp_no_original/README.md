# instrument_adrp_no_original

Demonstrates using `sighook::instrument_no_original` to hook an `adrp` patch point and emulate the original instruction manually in callback.

- Linux `aarch64`: patch point is `calc_adrp_insn` (`adrp x10, g_magic`)
- callback writes the expected page base into `x10`
- execution then continues to the following `add x10, x10, :lo12:g_magic`

## Run (from repository root)

Linux `aarch64`:

```bash
cc -O0 -fno-inline -rdynamic examples/instrument_adrp_no_original/target.c -o examples/instrument_adrp_no_original/app
cargo build --example instrument_adrp_no_original
LD_PRELOAD="$PWD/target/debug/examples/libinstrument_adrp_no_original.so" examples/instrument_adrp_no_original/app
```

Expected output:

```text
calc(5, 7) = 42
```

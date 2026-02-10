# instrument_adrp_no_original

Demonstrates using `sighook::instrument_no_original` to hook an `adrp` patch point and emulate the original instruction manually in callback.

- Linux `aarch64` patch point: `calc_adrp_insn` (`adrp x10, g_magic`)
- Next instructions keep the normal address flow: `add x10, x10, :lo12:g_magic` then `ldr w10, [x10, #4]`
- Callback replays only the `adrp` part by using `ctx.pc` and the decoded `adrp` page offset (`imm_pages`)

This demonstrates an `adrp + offset` scenario (`ldr ... #4`) while still using `instrument_no_original` safely.

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

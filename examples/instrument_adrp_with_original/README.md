# instrument_adrp_with_original

Demonstrates `sighook::instrument(...)` replaying a displaced AArch64 PC-relative
instruction (`adrp`) directly instead of running it from the out-of-line trampoline.

The callback only rewrites argument registers. It does not emulate `adrp` manually.
When replay works, the original `adrp` still resolves `g_magic` correctly and the
program prints:

```text
calc(5, 7) = 72
```

Linux AArch64 build/run:

```bash
cc -O0 -fno-inline -rdynamic examples/instrument_adrp_with_original/target.c -o examples/instrument_adrp_with_original/app
cargo build --example instrument_adrp_with_original
LD_PRELOAD="$PWD/target/debug/examples/libinstrument_adrp_with_original.so" examples/instrument_adrp_with_original/app
```

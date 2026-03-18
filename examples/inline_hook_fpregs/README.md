# inline_hook_fpregs

Demonstrates `sighook::inline_hook` with FP/SIMD return registers via `ctx.fpregs`.

- `aarch64`: callback writes a replacement vector into `v0`
- `x86_64 macOS`: callback writes a replacement vector into `xmm0`
- `x86_64 Linux`: callback writes a replacement vector into `ymm0`

## Run (from repository root)

macOS / Linux `aarch64`:

```bash
cc -O0 -fno-inline examples/inline_hook_fpregs/target.c -o examples/inline_hook_fpregs/app
cargo build --example inline_hook_fpregs
```

Linux `x86_64` (AVX return register path):

```bash
cc -O0 -fno-inline -mavx -rdynamic examples/inline_hook_fpregs/target.c -o examples/inline_hook_fpregs/app
cargo build --example inline_hook_fpregs
```

Run on macOS:

```bash
DYLD_INSERT_LIBRARIES="$PWD/target/debug/examples/libinline_hook_fpregs.dylib" examples/inline_hook_fpregs/app
```

Run on Linux:

```bash
LD_PRELOAD="$PWD/target/debug/examples/libinline_hook_fpregs.so" examples/inline_hook_fpregs/app
```

Expected output:

macOS / Linux `aarch64`:

```text
target_vec_add = [42, 43, 44, 45]
```

Linux `x86_64`:

```text
target_vec_add = [42, 43, 44, 45, 46, 47, 48, 49]
```

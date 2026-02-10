# sighook

[![crates.io](https://img.shields.io/crates/v/sighook.svg)](https://crates.io/crates/sighook)
[![docs.rs](https://docs.rs/sighook/badge.svg)](https://docs.rs/sighook)
[![CI](https://github.com/YinMo19/sighook/actions/workflows/ci.yml/badge.svg)](https://github.com/YinMo19/sighook/actions/workflows/ci.yml)
[![license](https://img.shields.io/crates/l/sighook.svg)](https://spdx.org/licenses/LGPL-2.1-only.html)

`Sighook` is a runtime patching crate focused on:

- instruction-level instrumentation via trap instruction + signal handler
- function-entry inline detours (near and far jump)

It is designed for low-level experimentation, reverse engineering, and custom runtime instrumentation workflows.

## Features

- `patchcode(address, opcode)` for instruction patching (x86_64 pads remaining bytes with NOPs when patch is shorter than current instruction)
- `patch_bytes(address, bytes)` for multi-byte/raw patching
- `patch_asm(address, asm)` for assembling then patching (feature-gated; x86_64 pads with NOPs when assembled bytes are shorter than current instruction)
- `instrument(address, callback)` to trap and then execute original opcode
- `instrument_no_original(address, callback)` to trap and skip original opcode
- `inline_hook(addr, replace_fn)` with automatic far-jump fallback
- zero-copy context remap (`HookContext`) in callbacks
- architecture-specific callback context (`aarch64` and `x86_64` layouts)

## Platform Support

- `aarch64-apple-darwin`: full API support (`patchcode` / `instrument` / `instrument_no_original` / `inline_hook`)
- `x86_64-apple-darwin`: full API support (`patchcode` / `instrument` / `instrument_no_original` / `inline_hook`)
- `aarch64-apple-ios`: full API support (`patchcode` / `instrument` / `instrument_no_original` / `inline_hook`)
- `aarch64-unknown-linux-gnu`: full API support (`patchcode` / `instrument` / `instrument_no_original` / `inline_hook`)
- `aarch64-linux-android`: full API support (`patchcode` / `instrument` / `instrument_no_original` / `inline_hook`)
- `x86_64-unknown-linux-gnu`: full API support; CI smoke validates `patchcode` / `instrument` / `instrument_no_original` / `inline_hook` examples
- single-thread model (`static mut` internal state)

`patch_asm` is currently available on:

- `aarch64-apple-darwin`
- `x86_64-apple-darwin`
- `aarch64-unknown-linux-gnu`
- `x86_64-unknown-linux-gnu`

## Installation

```toml
[dependencies]
sighook = "0.7.0"
```

Enable assembly-string patching support only when needed:

```toml
[dependencies]
sighook = { version = "0.7.0", features = ["patch_asm"] }
```

`patch_asm` pulls `keystone-engine`, which is a heavier dependency.

## Quick Start

### 1) BRK instrumentation (execute original opcode)

```rust,no_run
use sighook::{instrument, HookContext};

extern "C" fn on_hit(_address: u64, ctx: *mut HookContext) {
    let _ = ctx;
}

let target_instruction = 0x1000_0000_u64;
let _original = instrument(target_instruction, on_hit)?;
# Ok::<(), sighook::SigHookError>(())
```

### 0) Patch with asm string (feature `patch_asm`)

```rust,no_run
# #[cfg(feature = "patch_asm")]
# {
use sighook::patch_asm;

let target_instruction = 0x1000_0000_u64;
#[cfg(target_arch = "aarch64")]
let _original = patch_asm(target_instruction, "mul w0, w8, w9")?;

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
let _original = patch_asm(target_instruction, "imul %edx")?;
# }
# Ok::<(), sighook::SigHookError>(())
```

### 2) BRK instrumentation (do not execute original opcode)

```rust,no_run
use sighook::{instrument_no_original, HookContext};

extern "C" fn replace_logic(_address: u64, ctx: *mut HookContext) {
    let _ = ctx;
}

let target_instruction = 0x1000_0010_u64;
let _original = instrument_no_original(target_instruction, replace_logic)?;
# Ok::<(), sighook::SigHookError>(())
```

### 3) Inline function hook

```rust,no_run
use sighook::inline_hook;

extern "C" fn replacement() {}

let function_entry = 0x1000_1000_u64;
let replacement_addr = replacement as usize as u64;
let _original = inline_hook(function_entry, replacement_addr)?;
# Ok::<(), sighook::SigHookError>(())
```

## Example Loading Model

The examples are `cdylib` payloads that auto-run hook install logic via constructor sections:

- Apple targets (macOS/iOS) use `__DATA,__mod_init_func` + dyld preload/injection flow
- Linux/Android targets use `.init_array` + `LD_PRELOAD`-style flow

When your preload library resolves symbols from the target executable via `dlsym`, compile the target executable with `-rdynamic` on Linux/Android.

## Android Guide (`arm64-v8a`)

> For authorized security research and your own binaries only.

If your workflow is “build a hook payload `.so` with `sighook`, then inject it into an existing target `.so` with `patchelf`”, use this pattern:

1) Build hook payload

```bash
cargo build --release --target aarch64-linux-android
```

The output is usually:

`target/aarch64-linux-android/release/libsighook_payload.so`

2) Ensure constructor-based init in payload

- Android uses `.init_array` constructor flow.
- Put hook-install logic in an init function (same pattern as this repo examples).
- Keep hook target symbols stable (for AArch64 examples, prefer explicit patchpoint symbols instead of hardcoded offsets).

3) Inject payload into target `.so`

```bash
patchelf --add-needed libsighook_payload.so libtarget.so
```

Verify `DT_NEEDED`:

```bash
readelf -d libtarget.so | grep NEEDED
```

4) Package both `.so` files into APK

- Place both files under the same ABI directory: `lib/arm64-v8a/`.
- Keep SONAME / filenames consistent with what `DT_NEEDED` references.

5) Re-sign and install APK, then verify

- Sign with your own cert, install on test device, and inspect `logcat` for payload init logs.

### Android-specific notes

- Android linker namespace rules may block unexpected library paths/dependencies; keep payload dependencies minimal.
- `patchelf` does not bypass SELinux, code-signing, or app sandbox boundaries.
- For app-level preload-style experiments, Android `wrap.sh` (debuggable app) is another option, but `patchelf` patching is usually more deterministic for fixed target libs.

## Linux AArch64 Patchpoint Note

For AArch64 Linux examples, `calc`-based demos export a dedicated `calc_add_insn` symbol and patch that symbol directly. This avoids brittle fixed-offset assumptions in toolchain-generated function layout.

## API Notes

- `instrument(...)` executes original instruction through an internal trampoline.
- `instrument(...)` should not be used for PC-relative patch points (for example: `aarch64` `adr`/`adrp`, or `x86_64` RIP-relative `lea`/`mov`).
- `instrument_no_original(...)` skips original instruction unless callback changes control-flow register (`pc`/`rip`). For PC-relative patch points, prefer this API and emulate the instruction in callback.
- `inline_hook(...)` uses architecture-specific near jump first, then far-jump fallback.

## Safety Notes

This crate performs runtime code patching and raw context mutation.

- Ensure target addresses are valid runtime addresses.
- Ensure callback logic preserves ABI expectations.
- Test on disposable binaries first.

## License

LGPL-2.1-only

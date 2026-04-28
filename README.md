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
- `prepatched::instrument*` / `prepatched::inline_hook` for offline trap points (no runtime text patch; recommended for iOS signed text pages)
- `inline_hook(addr, callback)` for signal-based function-entry hooks
- `inline_hook_jump(addr, replace_fn)` with automatic far-jump fallback
- `unhook(address)` to restore bytes and remove hook runtime state
- callback context (`HookContext`) in callbacks
- architecture-specific callback context (`aarch64` and `x86_64` layouts), including FP/SIMD state via `ctx.fpregs`

## Platform Support

- `aarch64-apple-darwin`: full API support (`patchcode` / `instrument` / `instrument_no_original` / `inline_hook` / `inline_hook_jump`)
- `x86_64-apple-darwin`: full API support (`patchcode` / `instrument` / `instrument_no_original` / `inline_hook` / `inline_hook_jump`)
- `aarch64-apple-ios`: full API support (`patchcode` / `instrument` / `instrument_no_original` / `prepatched::*` / `inline_hook` / `inline_hook_jump`)
- `aarch64-unknown-linux-gnu`: full API support (`patchcode` / `instrument` / `instrument_no_original` / `inline_hook` / `inline_hook_jump`)
- `aarch64-linux-android`: full API support (`patchcode` / `instrument` / `instrument_no_original` / `inline_hook` / `inline_hook_jump`)
- `x86_64-unknown-linux-gnu`: full API support; CI smoke validates `patchcode` / `instrument` / `instrument_no_original` / `inline_hook` / `inline_hook_jump` examples

`patch_asm` is currently available on:

- `aarch64-apple-darwin`
- `x86_64-apple-darwin`
- `aarch64-unknown-linux-gnu`
- `x86_64-unknown-linux-gnu`

## Installation

```toml
[dependencies]
sighook = "0.10.0"
```

Enable assembly-string patching support only when needed:

```toml
[dependencies]
sighook = { version = "0.10.0", features = ["patch_asm"] }
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

### 3) Signal-based inline entry hook

```rust,no_run
use sighook::{inline_hook, HookContext};

extern "C" fn replacement(_address: u64, ctx: *mut HookContext) {
    unsafe {
        #[cfg(target_arch = "aarch64")]
        {
            (*ctx).regs.named.x0 = 42;
        }
        #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
        {
            (*ctx).rax = 42;
        }
    }
}

let function_entry = 0x1000_1000_u64;
let _original = inline_hook(function_entry, replacement)?;
# Ok::<(), sighook::SigHookError>(())
```

### 4) Jump-based inline detour

```rust,no_run
use sighook::inline_hook_jump;

extern "C" fn replacement() {}

let function_entry = 0x1000_1000_u64;
let replacement_addr = replacement as usize as u64;
let _original = inline_hook_jump(function_entry, replacement_addr)?;
# Ok::<(), sighook::SigHookError>(())
```

### 5) Unhook and restore

```rust,ignore
use sighook::{instrument, unhook, HookContext};

extern "C" fn on_hit(_address: u64, _ctx: *mut HookContext) {}

let target_instruction = 0x1000_0000_u64;
let _ = instrument(target_instruction, on_hit)?;
unhook(target_instruction)?;
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

## iOS Prepatch Requirement

For iOS hook workflows, `prepatched::*` is the primary path.

iOS executable pages are code-signed. In normal (non-jailbreak) runtime environments, writing trap opcodes into signed text pages is usually rejected, so purely runtime non-invasive patching is not reliable. To keep hook points valid on iOS, pre-patch trap instructions (`brk`) offline before signing/distribution, then register callbacks at runtime through `prepatched::*`.

- Prefer `prepatched::instrument_no_original(...)` and `prepatched::inline_hook(...)` on iOS.
- `prepatched::instrument(...)` (execute-original mode) requires original opcode metadata on `aarch64`; preload it with `prepatched::cache_original_opcode(...)`.
- `unhook(...)` removes runtime state for `prepatched::*`, but does not rewrite the prepatched text bytes.

## API Notes

- `instrument(...)` executes original instruction through an internal trampoline when needed.
- On `aarch64`, `instrument(...)` precomputes direct replay for common displaced instructions: `nop`, `br` / `blr` / `ret`, `adr`, `adrp`, literal `ldr` / `ldrsw` / `prfm`, `b` / `bl` / `b.cond`, `cbz` / `cbnz`, and `tbz` / `tbnz`.
- Other `aarch64` patch points are still not guaranteed safe in execute-original mode. Unsupported execute-original installs return `UnsupportedOperation` instead of silently falling back to an inexact trampoline. For those patch points, prefer `instrument_no_original(...)` and emulate the original instruction in callback.
- On `x86_64`, RIP-relative execute-original patch points are still unsupported (for example `lea` / `mov` using `[rip + disp]`).
- `instrument_no_original(...)` skips original instruction unless callback changes control-flow register (`pc`/`rip`).
- `HookContext` exposes FP/SIMD state in `ctx.fpregs`:
  - `aarch64`: `fpregs.v[0..31]` or `fpregs.regs.named.v0..v31`, plus `fpsr` / `fpcr`
  - `x86_64`: `fpregs.st[0..7]` or `fpregs.st.named.st0..st7`, `fpregs.xmm[0..15]` or `fpregs.xmm.named.xmm0..xmm15`, plus `mxcsr`; Linux also maps `fpregs.ymm_hi[0..15]` or `fpregs.ymm_hi.named.ymm0_hi..ymm15_hi`
- `prepatched::*` APIs assume the address is already trap-patched offline (`brk`/`int3`) and do not write executable pages at runtime.
- `prepatched::instrument(...)` needs original opcode metadata to execute original instruction (on `aarch64`, preload with `prepatched::cache_original_opcode(...)`).
- `prepatched::instrument(...)` execute-original mode is currently unsupported on `x86_64`; use `prepatched::instrument_no_original(...)`.
- `inline_hook(...)` installs an entry trap and returns to caller by default when callback leaves `pc`/`rip` unchanged.
- `inline_hook_jump(...)` uses architecture-specific near jump first, then far-jump fallback.
- `unhook(...)` restores patch bytes for runtime-patched hooks; for `prepatched::*` hooks it removes runtime state only.
- On `x86_64`, patch addresses must point to the first byte of an instruction. The decoder cannot reliably prove instruction boundaries from an arbitrary address inside a variable-length instruction stream.

## Safety Notes

This crate performs runtime code patching and raw context mutation.

- Ensure target addresses are valid runtime addresses.
- Ensure callback logic preserves ABI expectations.
- Treat callbacks as signal-handler context: keep them small and avoid allocation, locking, `dlopen`, `mprotect`, hook installation/removal, or other runtime/loader operations.
- Runtime patching temporarily pauses peer threads while changing executable pages. On Apple platforms this uses Mach thread suspension, so avoid patching while other threads may hold allocator, loader, Objective-C runtime, or VM-related locks.
- Test on disposable binaries first.

## License

LGPL-2.1-only

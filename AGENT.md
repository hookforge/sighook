# sighook Agent Notes

Last updated: 2026-02-08

## 1) Current Project Snapshot

- Crate: `sighook`
- Current version: `0.5.0`
- Status: multi-platform runtime hook crate with Apple/Linux/Android support (AArch64 + Linux x86_64).
- Current architecture focus: platform-specific backend code behind stable public API.

### Public APIs (stable signatures)

- `patchcode(address, new_opcode) -> Result<u32, SigHookError>`
- `instrument(address, callback) -> Result<u32, SigHookError>`
- `instrument_no_original(address, callback) -> Result<u32, SigHookError>`
- `inline_hook(addr, replace_fn) -> Result<u32, SigHookError>`
- `original_opcode(address) -> Option<u32>`

### Callback contract

- Callback signature is fixed:
  `extern "C" fn(address: u64, ctx: *mut HookContext)`
- Callback may mutate registers/PC in-place through `HookContext`.
- `instrument`: callback + original instruction trampoline.
- `instrument_no_original`: callback + skip original instruction (unless callback updates control flow).

## 2) Supported Platforms and Runtime Status

### Fully supported targets

- `aarch64-apple-darwin`
- `aarch64-apple-ios`
- `aarch64-unknown-linux-gnu`
- `aarch64-linux-android`
- `x86_64-unknown-linux-gnu`

### CI jobs (always-on for active matrix)

- `rust-macos-aarch64`: fmt/check/doc-test/clippy + 4 example smoke tests.
- `rust-linux-x86_64`: check/doc-test/clippy + 4 example smoke tests.
- `rust-linux-aarch64`: check/doc-test/clippy + 4 example smoke tests.
- `rust-ios-aarch64`: check/tests-compile/clippy + build all examples.
- `rust-android-aarch64`: check/tests-compile/clippy + build all examples (NDK linker configured).

### Example smoke outputs expected in CI

- `instrument_with_original`: `calc(1, 2) = 42`
- `instrument_no_original`: `calc(4, 5) = 99`
- `inline_hook_far`: `target_add(6, 7) = 42`
- `patchcode_add_to_mul`: `calc(6, 7) = 42`

## 3) Internal Architecture (Important)

### Module responsibilities

- `src/lib.rs`: stable API surface and platform-gated exports.
- `src/signal.rs`: signal handlers and trap dispatch flow.
- `src/context.rs`: `ucontext`/thread-state remap to `HookContext`.
- `src/memory.rs`: patching, page permission management, branch encoding.
- `src/trampoline.rs`: original instruction trampoline generation.
- `src/state.rs`: global slot registry + original bytes/opcode cache.

### Runtime model assumptions

- Single-thread model by design (`static mut` global state).
- Fixed instrument slot array (`MAX_INSTRUMENTS = 256`; no dynamic allocator-based slot registry).
- No locking primitives in hot path.

### Slot registry design rationale (important)

- Current implementation intentionally uses a fixed array + linear scan for slot lookup.
- Reason: signal-trap path prioritizes deterministic behavior and avoids allocator/locking complexity.
- At current scale (`<=256` active patchpoints), lookup overhead is acceptable compared with trap/signal overhead.
- Do **not** switch directly to `HashMap` in trap hot path without a signal-safety/concurrency design review.
- If future demand exceeds 256 hooks or profiling shows lookup bottleneck, prefer a preallocated table + lock-free read strategy rather than allocator-driven `HashMap` mutation in hot path.

### API/implementation conventions to keep

- Keep public API signatures stable unless explicitly planned as breaking change.
- Prefer single-entry helper APIs with target-specific `cfg` at function definition level (avoid duplicated call-site `cfg` branching when possible).
- Keep platform branches explicit in `context`/`signal`/`memory` modules; these branches are architecture/ABI-driven and should not be over-abstracted.

## 4) Platform-specific Decisions (Keep these)

### Linux AArch64 examples

- Use explicit patchpoint symbol `calc_add_insn` for `calc` examples.
- Do **not** rely on compiler-layout fixed offsets for Linux AArch64.

### Linux x86_64 examples

- `instrument*` examples use deterministic assembly layout + fixed patch offset (`+0x4` from `calc`).
- `patchcode_add_to_mul` uses deterministic assembly layout + fixed patch offset (`+0x6` from `calc`).
- Linux builds use `-rdynamic` in example smoke scripts so `dlsym` on executable symbols remains reliable.

### x86_64 trampoline critical fix

- Absolute jump fallback in trampoline must not clobber return register.
- Current implementation uses RIP-indirect `jmp qword ptr [rip]` with inline 64-bit target literal to preserve `rax` semantics.

## 5) Documentation State

- Public APIs in `src/lib.rs` now include English rustdoc with concise behavior notes and minimal `no_run` examples.
- Goal: hovering functions in IDE should show direct usage without leaving source.

## 6) Validation Checklist

Run before release/tag:

```bash
cargo fmt --all -- --check
cargo check --all-targets
cargo test --doc
cargo clippy --all-targets -- -D warnings
cargo check --all-targets --target aarch64-apple-darwin
cargo check --all-targets --target aarch64-apple-ios
cargo check --all-targets --target aarch64-linux-android
cargo check --all-targets --target x86_64-unknown-linux-gnu

# optional but recommended pre-release target checks
cargo check --tests --target aarch64-apple-ios
cargo check --tests --target aarch64-linux-android
```

If local toolchain supports it, also run:

```bash
cargo check --all-targets --target aarch64-unknown-linux-gnu
cargo clippy --all-targets --target aarch64-unknown-linux-gnu -- -D warnings
```

## 7) Near-term Next Steps

- Validate runtime hooking behavior on real iOS/Android environments (trap delivery and patch permissions).
- Add benchmark/profiling harness for slot lookup cost under high patchpoint counts.
- Decide threshold/plan for optional slot-registry redesign if active patchpoints regularly approach `MAX_INSTRUMENTS`.
- Optional: introduce a lightweight backend trait to reduce cfg branching in `lib.rs` and simplify future ports.

## 8) Build/Release Requirements

- Rust toolchain baseline: stable `1.85+`.
- Required components in CI/dev: `rustfmt`, `clippy`.
- Android build baseline: NDK `r26d` (or compatible) and linker env:
  `CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=.../aarch64-linux-android34-clang`.
- Linux example smoke tests rely on `cc` and `-rdynamic` for `dlsym` symbol visibility.
- iOS target currently validates compile/link (`check`, `check --tests`, `clippy`, examples build), not preload-style runtime smoke.

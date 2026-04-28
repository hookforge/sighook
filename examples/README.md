# Examples

Each subdirectory demonstrates one `sighook` API as a Cargo example target.

Current supported host targets:

- `aarch64-apple-darwin`
- `x86_64-apple-darwin`
- `aarch64-unknown-linux-gnu`
- `x86_64-unknown-linux-gnu`

Build all examples from repository root:

```bash
cargo build --examples
```

Run the AArch64 semantic smoke examples on a real host process:

```bash
./scripts/run_aarch64_semantic_examples.sh
```

Build feature-gated asm example:

```bash
cargo build --example patch_asm_add_to_mul --features patch_asm
```

Artifacts are generated under the root `target/debug/examples/` directory.

Available examples:

- `patchcode_add_to_mul`: patch one opcode directly
- `patch_asm_add_to_mul` (requires `patch_asm`): assemble one instruction from string and patch
- `instrument_with_original`: BRK instrumentation + execute original opcode
- `instrument_no_original`: BRK instrumentation + skip original opcode
- `instrument_unhook_restore`: install instruction hook, then unhook and verify original behavior
- `instrument_adrp_no_original`: aarch64 `adrp` patch-point via `instrument_no_original` + manual callback emulation
- `instrument_adrp_with_original`: aarch64 `adrp` patch-point via `instrument(...)` + automatic replay
- `instrument_nop_x16`: aarch64 `nop` patch-point; validates execute-original without `x16` corruption
- `instrument_blr_lr`: aarch64 `blr` patch-point; validates execute-original `lr` semantics
- `instrument_b_cond_nv`: aarch64 `b.nv` patch-point; validates condition replay for cond=`0xF`
- `prepatched_upgrade_execute_original`: aarch64 prepatched slot upgraded from no-original to execute-original
- `instrument_literal_fault_pc`: aarch64 literal-load patch-point; validates fault PC remap for replayed literal faults
- `patch_race_stress`: repeatedly hook/unhook under concurrent callers; validates patch synchronization
- `inline_hook_signal`: function-entry signal hook; callback writes return value and returns to caller
- `inline_hook_fpregs`: function-entry signal hook; callback writes FP/SIMD return registers (`v0` / `xmm0` / `ymm0`)
- `inline_hook_far`: function-entry detour with `inline_hook_jump`

## Coverage matrix

- `aarch64-apple-darwin`: `patchcode` / `instrument` / `instrument_no_original` / `inline_hook` / `inline_hook_fpregs` / `inline_hook_jump`
- `aarch64-apple-darwin`: semantic smoke coverage for `instrument_nop_x16` / `instrument_blr_lr` / `instrument_b_cond_nv` / `prepatched_upgrade_execute_original`
- `aarch64-apple-darwin`: plus optional `patch_asm` smoke (`--features patch_asm`)
- `x86_64-apple-darwin`: runtime smoke coverage for 8 base/stress examples (CI), plus optional `patch_asm` build
- `aarch64-unknown-linux-gnu`: runtime smoke coverage for all 9 core examples (CI, includes `instrument_adrp_no_original` and `instrument_adrp_with_original`)
- `aarch64-unknown-linux-gnu`: semantic smoke coverage for `instrument_nop_x16` / `instrument_blr_lr` / `instrument_b_cond_nv` / `prepatched_upgrade_execute_original`
- `aarch64-unknown-linux-gnu`: plus `instrument_literal_fault_pc` runtime validation for literal replay fault-PC remap
- `aarch64-unknown-linux-gnu`: plus optional `patch_asm` smoke (`--features patch_asm`)
- `x86_64-unknown-linux-gnu`: runtime smoke coverage for 8 base/stress examples (CI), plus optional `patch_asm` smoke (`--features patch_asm`)

## Notes by architecture

- On `aarch64-unknown-linux-gnu`, `calc` examples expose dedicated patchpoint symbols (`calc_add_insn` and `calc_adrp_insn`) and resolve patch points by symbol (no fixed offset dependency).
- `instrument_adrp_no_original` demonstrates `adrp` interception via `instrument_no_original` and manual callback emulation.
- `instrument_adrp_with_original` demonstrates `instrument(...)` replaying a displaced `adrp` patch point directly.
- `instrument_nop_x16` validates that execute-original replay for `nop` no longer leaks `next_pc` into `x16`.
- `instrument_blr_lr` validates that execute-original replay for `blr` presents the original patchpoint `lr` to the callee.
- `instrument_b_cond_nv` validates that `b.nv` behaves as taken in the real process.
- `prepatched_upgrade_execute_original` validates the `prepatched::instrument_no_original(...)` -> `prepatched::instrument(...)` upgrade path after caching the real opcode.
- `instrument_literal_fault_pc` is primarily a Linux `aarch64` validation. On Linux it confirms replayed literal-load faults are reported at the original patchpoint PC; Darwin reports a different `ucontext` PC shape for this fault and is not used as the assertion target.
- On `aarch64-apple-darwin`, `calc` examples keep fixed `ADD_INSN_OFFSET=0x14` for the naked function layout.
- On `x86_64-unknown-linux-gnu`, `calc` examples use fixed offsets in dedicated assembly stubs (`instrument*`: `+0x4`, `patchcode_add_to_mul`: `+0x6`). `patchcode_add_to_mul` patches `add eax, edx; nop; nop` into one-operand `imul edx` (result in `eax`).
- `patch_asm_add_to_mul` uses equivalent patches via assembly text (`aarch64`: `mul w0, w8, w9`; `x86_64`: `imul %edx`).
- `inline_hook_fpregs` validates FP/SIMD callback context mutation: `aarch64`/macOS `x86_64` replace the 128-bit return register, while Linux `x86_64` replaces the 256-bit AVX return register (`ymm0`).

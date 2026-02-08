# Examples

Each subdirectory demonstrates one `sighook` API as a Cargo example target.

Current supported host targets:

- `aarch64-apple-darwin`
- `aarch64-unknown-linux-gnu`
- `x86_64-unknown-linux-gnu`

Build all examples from repository root:

```bash
cargo build --examples
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
- `inline_hook_far`: function-entry detour with inline hook

## Coverage matrix

- `aarch64-apple-darwin`: `patchcode` / `instrument` / `instrument_no_original` / `inline_hook`
- `aarch64-apple-darwin`: plus optional `patch_asm` smoke (`--features patch_asm`)
- `aarch64-unknown-linux-gnu`: runtime smoke coverage for all 4 examples (CI)
- `aarch64-unknown-linux-gnu`: plus optional `patch_asm` smoke (`--features patch_asm`)
- `x86_64-unknown-linux-gnu`: runtime smoke coverage for all 4 examples (CI), plus optional `patch_asm` smoke (`--features patch_asm`)

## Notes by architecture

- On `aarch64-unknown-linux-gnu`, `calc` examples expose a dedicated `calc_add_insn` symbol and resolve patch point by symbol (no fixed offset dependency).
- On `aarch64-apple-darwin`, `calc` examples keep fixed `ADD_INSN_OFFSET=0x14` for the naked function layout.
- On `x86_64-unknown-linux-gnu`, `calc` examples use fixed offsets in dedicated assembly stubs (`instrument*`: `+0x4`, `patchcode_add_to_mul`: `+0x6`). `patchcode_add_to_mul` patches `add eax, edx; nop; nop` into `imul eax, edx; nop`.
- `patch_asm_add_to_mul` uses equivalent patches via assembly text (`aarch64`: `mul w0, w8, w9`; `x86_64`: `imul %edx, %eax; nop`).

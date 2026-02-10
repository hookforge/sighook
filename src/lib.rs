#![allow(deprecated)]
#![doc = include_str!("../README.md")]

#[cfg(not(any(
    all(any(target_os = "macos", target_os = "ios"), target_arch = "aarch64"),
    all(target_os = "macos", target_arch = "x86_64"),
    all(
        any(target_os = "linux", target_os = "android"),
        target_arch = "aarch64"
    ),
    all(target_os = "linux", target_arch = "x86_64")
)))]
compile_error!(
    "sighook only supports Apple aarch64/x86_64 (macOS), Apple aarch64 (iOS), Linux/Android aarch64, and Linux x86_64."
);

#[cfg(all(
    feature = "patch_asm",
    any(
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "macos", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64"),
        all(target_os = "linux", target_arch = "x86_64")
    )
))]
mod asm;
mod constants;
mod context;
mod error;
mod memory;
mod signal;
mod state;
mod trampoline;

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
pub use context::{HookContext, InstrumentCallback};
#[cfg(target_arch = "aarch64")]
pub use context::{HookContext, InstrumentCallback, XRegisters, XRegistersNamed};
pub use error::SigHookError;

/// Replaces one machine instruction at `address` with `new_opcode`.
///
/// The function writes 4 bytes and returns the previously stored 4-byte value.
/// Use this API when you already know the exact opcode encoding for your target architecture.
///
/// - On `aarch64`, `new_opcode` is a 32-bit ARM instruction word.
/// - On `x86_64`, `new_opcode` is written as 4 little-endian bytes.
///   If the decoded current instruction is longer than 4 bytes, the remaining
///   bytes are filled with `NOP`.
///   If the decoded instruction is shorter than 4 bytes, returns [`SigHookError::PatchTooLong`]
///   and you should use [`patch_bytes`] instead.
///
/// # Example
///
/// ```rust,no_run
/// use sighook::patchcode;
///
/// let address = 0x7FFF_0000_0000u64;
/// let old = patchcode(address, 0x90C3_9090)?;
/// let _ = old;
/// # Ok::<(), sighook::SigHookError>(())
/// ```
#[cfg(any(
    target_arch = "aarch64",
    all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos"))
))]
pub fn patchcode(address: u64, new_opcode: u32) -> Result<u32, SigHookError> {
    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
    {
        let instruction_len = memory::instruction_width(address)? as usize;
        let patch_len = 4usize;
        if patch_len > instruction_len {
            return Err(SigHookError::PatchTooLong {
                patch_len,
                instruction_len,
            });
        }

        let mut patch = vec![0x90u8; instruction_len];
        patch[..4].copy_from_slice(&new_opcode.to_le_bytes());
        let original = memory::patch_bytes_public(address, &patch)?;
        let mut opcode = [0u8; 4];
        opcode.copy_from_slice(&original[..4]);
        let original_opcode = u32::from_le_bytes(opcode);
        unsafe {
            state::cache_original_opcode(address, original_opcode);
        }
        Ok(original_opcode)
    }

    #[cfg(target_arch = "aarch64")]
    let original = memory::patch_u32(address, new_opcode)?;

    #[cfg(target_arch = "aarch64")]
    unsafe {
        state::cache_original_opcode(address, original);
    }

    #[cfg(target_arch = "aarch64")]
    Ok(original)
}

/// Replaces one machine instruction at `address` from assembly text.
///
/// This API assembles `asm` into exactly 4 bytes for the active target,
/// then writes it through [`patchcode`].
///
/// Notes:
/// - Requires crate feature `patch_asm`.
/// - On `aarch64`, use ARM64 syntax (e.g. `"mul w0, w8, w9"`).
/// - On Linux `x86_64`, use GNU/AT&T syntax (e.g. `"imul %edx, %eax"`).
/// - On `x86_64`, if assembled bytes are shorter than the decoded current instruction,
///   the trailing bytes are padded with `NOP`; if longer, returns
///   [`SigHookError::PatchTooLong`] and you should use [`patch_bytes`].
///
/// Returns the original 4-byte value previously stored at `address`.
///
/// # Example
///
/// ```rust,no_run
/// # #[cfg(all(feature = "patch_asm", any(all(target_os = "macos", target_arch = "aarch64"), all(target_os = "macos", target_arch = "x86_64"), all(target_os = "linux", target_arch = "aarch64"), all(target_os = "linux", target_arch = "x86_64"))))]
/// # {
/// use sighook::patch_asm;
///
/// let address = 0x7FFF_0000_0000u64;
/// let old = patch_asm(address, "nop")?;
/// let _ = old;
/// # }
/// # Ok::<(), sighook::SigHookError>(())
/// ```
#[cfg(all(
    feature = "patch_asm",
    any(
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "macos", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64"),
        all(target_os = "linux", target_arch = "x86_64")
    )
))]
pub fn patch_asm(address: u64, asm: &str) -> Result<u32, SigHookError> {
    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
    {
        use crate::asm::assemble_bytes;

        let mut patch = assemble_bytes(address, asm)?;
        let instruction_len = memory::instruction_width(address)? as usize;
        if patch.len() > instruction_len {
            return Err(SigHookError::PatchTooLong {
                patch_len: patch.len(),
                instruction_len,
            });
        }

        patch.resize(instruction_len, 0x90);
        let original = memory::patch_bytes_public(address, &patch)?;
        let mut opcode = [0u8; 4];
        if original.len() < 4 {
            return Err(SigHookError::InvalidAddress);
        }
        opcode.copy_from_slice(&original[..4]);
        let original_opcode = u32::from_le_bytes(opcode);
        unsafe {
            state::cache_original_opcode(address, original_opcode);
        }
        return Ok(original_opcode);
    }

    #[cfg(any(
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "linux", target_arch = "aarch64")
    ))]
    {
        let opcode = asm::assemble_patch_opcode(address, asm)?;
        patchcode(address, opcode)
    }
}

/// Installs an instruction-level hook and executes the original instruction afterward.
///
/// This API patches the target instruction with a trap opcode and registers `callback`.
/// On trap, your callback receives a mutable [`HookContext`].
/// If the callback does not redirect control flow (`pc`/`rip` unchanged),
/// the original instruction runs through an internal trampoline, then execution continues.
///
/// # PC-relative note
///
/// Across architectures, this API does **not** support patch points whose original
/// instruction is PC-relative.
///
/// Examples include `aarch64` `adr`/`adrp`, and `x86_64` RIP-relative forms such as
/// `lea` or `mov` using `[rip + disp]`. These instructions can observe a different
/// `pc`/`rip` when replayed by the trampoline, which may produce incorrect behavior.
///
/// For such patch points, prefer [`instrument_no_original`], and emulate the original
/// instruction semantics manually in your callback (typically using `ctx.pc`/`ctx.rip`).
///
/// Returns the original 4-byte value previously stored at `address`.
///
/// # Example
///
/// ```rust,no_run
/// use sighook::{instrument, HookContext};
///
/// extern "C" fn on_hit(_address: u64, _ctx: *mut HookContext) {}
///
/// let target = 0x1000_0000u64;
/// let original = instrument(target, on_hit)?;
/// let _ = original;
/// # Ok::<(), sighook::SigHookError>(())
/// ```
pub fn instrument(address: u64, callback: InstrumentCallback) -> Result<u32, SigHookError> {
    instrument_internal(address, callback, true)
}

/// Installs an instruction-level hook and skips the original instruction by default.
///
/// This behaves like [`instrument`] except `execute_original = false`.
/// After your callback returns, execution advances past the patched instruction
/// unless the callback explicitly changes control flow (`pc`/`rip`).
///
/// Returns the original 4-byte value previously stored at `address`.
///
/// # Example
///
/// ```rust,no_run
/// use sighook::{instrument_no_original, HookContext};
///
/// extern "C" fn replace_logic(_address: u64, _ctx: *mut HookContext) {}
///
/// let target = 0x1000_0010u64;
/// let original = instrument_no_original(target, replace_logic)?;
/// let _ = original;
/// # Ok::<(), sighook::SigHookError>(())
/// ```
pub fn instrument_no_original(
    address: u64,
    callback: InstrumentCallback,
) -> Result<u32, SigHookError> {
    instrument_internal(address, callback, false)
}

fn instrument_internal(
    address: u64,
    callback: InstrumentCallback,
    execute_original: bool,
) -> Result<u32, SigHookError> {
    unsafe {
        if let Some((bytes, len)) = state::original_bytes_by_address(address) {
            state::register_slot(
                address,
                &bytes[..len as usize],
                len,
                callback,
                execute_original,
            )?;
            return state::original_opcode_by_address(address).ok_or(SigHookError::InvalidAddress);
        }

        signal::ensure_handlers_installed()?;

        let step_len: u8 = memory::instruction_width(address)?;

        #[cfg(target_arch = "aarch64")]
        let original_bytes = {
            let original = memory::patch_u32(address, constants::BRK_OPCODE)?;
            original.to_le_bytes().to_vec()
        };

        #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
        let original_bytes = {
            let original_bytes = memory::read_bytes(address, step_len as usize)?;
            let _ = memory::patch_u8(address, memory::int3_opcode())?;
            original_bytes
        };

        let register_result = state::register_slot(
            address,
            &original_bytes,
            step_len,
            callback,
            execute_original,
        );

        if let Err(err) = register_result {
            #[cfg(target_arch = "aarch64")]
            {
                let mut bytes = [0u8; 4];
                bytes.copy_from_slice(&original_bytes[..4]);
                let original_opcode = u32::from_le_bytes(bytes);
                let _ = memory::patch_u32(address, original_opcode);
            }

            #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
            {
                let _ = memory::patch_bytes_public(address, &original_bytes);
            }

            return Err(err);
        }

        if original_bytes.len() < 4 {
            return Err(SigHookError::InvalidAddress);
        }

        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&original_bytes[..4]);
        let original_opcode = u32::from_le_bytes(bytes);
        state::cache_original_opcode(address, original_opcode);

        Ok(original_opcode)
    }
}

/// Detours a function entry to `replace_fn` with inline patching.
///
/// Strategy:
/// - Try near jump first (short encoding).
/// - Fall back to architecture-specific far jump sequence when out of range.
///
/// Returns the first 4 bytes of original instruction bytes at `addr`.
///
/// # Example
///
/// ```rust,no_run
/// use sighook::inline_hook;
///
/// extern "C" fn replacement() {}
///
/// let function_entry = 0x1000_1000u64;
/// let replacement_addr = replacement as usize as u64;
/// let original = inline_hook(function_entry, replacement_addr)?;
/// let _ = original;
/// # Ok::<(), sighook::SigHookError>(())
/// ```
pub fn inline_hook(addr: u64, replace_fn: u64) -> Result<u32, SigHookError> {
    #[cfg(target_arch = "aarch64")]
    {
        match memory::encode_b(addr, replace_fn) {
            Ok(b_opcode) => patchcode(addr, b_opcode),
            Err(SigHookError::BranchOutOfRange) => {
                let original = memory::patch_far_jump(addr, replace_fn)?;
                unsafe {
                    state::cache_original_opcode(addr, original);
                }
                Ok(original)
            }
            Err(err) => Err(err),
        }
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
    {
        if let Ok(jmp) = memory::encode_jmp_rel32(addr, replace_fn) {
            let original = memory::patch_bytes_public(addr, &jmp)?;
            let mut opcode = [0u8; 4];
            if original.len() >= 4 {
                opcode.copy_from_slice(&original[..4]);
                let original_opcode = u32::from_le_bytes(opcode);
                unsafe {
                    state::cache_original_opcode(addr, original_opcode);
                }
                return Ok(original_opcode);
            }
            return Err(SigHookError::InvalidAddress);
        }

        let abs = memory::encode_absolute_jump(replace_fn);
        let original = memory::patch_bytes_public(addr, &abs)?;
        let mut opcode = [0u8; 4];
        if original.len() >= 4 {
            opcode.copy_from_slice(&original[..4]);
            let original_opcode = u32::from_le_bytes(opcode);
            unsafe {
                state::cache_original_opcode(addr, original_opcode);
            }
            return Ok(original_opcode);
        }
        Err(SigHookError::InvalidAddress)
    }
}

/// Returns the saved original 4-byte value for a previously patched address.
///
/// The value is available after a successful call to [`patchcode`], [`instrument`],
/// [`instrument_no_original`], or [`inline_hook`] on the same address.
///
/// # Example
///
/// ```rust,no_run
/// use sighook::{instrument, original_opcode, HookContext};
///
/// extern "C" fn on_hit(_address: u64, _ctx: *mut HookContext) {}
///
/// let addr = 0x1000_2000u64;
/// let _ = instrument(addr, on_hit)?;
/// let maybe_old = original_opcode(addr);
/// let _ = maybe_old;
/// # Ok::<(), sighook::SigHookError>(())
/// ```
pub fn original_opcode(address: u64) -> Option<u32> {
    unsafe {
        state::cached_original_opcode_by_address(address)
            .or_else(|| state::original_opcode_by_address(address))
    }
}

/// Writes raw bytes to `address` and returns the overwritten bytes with the same length.
///
/// Use this API when you need to patch more than one instruction or when your patch
/// length exceeds the current instruction length.
///
/// # Example
///
/// ```rust,no_run
/// use sighook::patch_bytes;
///
/// let address = 0x7FFF_0000_0000u64;
/// let original = patch_bytes(address, &[0x90, 0x90, 0x90, 0x90])?;
/// let _ = original;
/// # Ok::<(), sighook::SigHookError>(())
/// ```
pub fn patch_bytes(address: u64, bytes: &[u8]) -> Result<Vec<u8>, SigHookError> {
    let original = memory::patch_bytes_public(address, bytes)?;
    if original.len() >= 4 {
        let mut opcode = [0u8; 4];
        opcode.copy_from_slice(&original[..4]);
        let original_opcode = u32::from_le_bytes(opcode);
        unsafe {
            state::cache_original_opcode(address, original_opcode);
        }
    }
    Ok(original)
}

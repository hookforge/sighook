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
/// - On Linux `x86_64`, `new_opcode` is written as 4 little-endian bytes.
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
    memory::patch_u32(address, new_opcode)
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
    let opcode = asm::assemble_patch_opcode(address, asm)?;
    patchcode(address, opcode)
}

/// Installs an instruction-level hook and executes the original instruction afterward.
///
/// This API patches the target instruction with a trap opcode and registers `callback`.
/// On trap, your callback receives a mutable [`HookContext`].
/// If the callback does not redirect control flow (`pc`/`rip` unchanged),
/// the original instruction runs through an internal trampoline, then execution continues.
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

        state::register_slot(
            address,
            &original_bytes,
            step_len,
            callback,
            execute_original,
        )?;
        state::original_opcode_by_address(address).ok_or(SigHookError::InvalidAddress)
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
            Err(SigHookError::BranchOutOfRange) => memory::patch_far_jump(addr, replace_fn),
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
                return Ok(u32::from_le_bytes(opcode));
            }
            return Err(SigHookError::InvalidAddress);
        }

        let abs = memory::encode_absolute_jump(replace_fn);
        let original = memory::patch_bytes_public(addr, &abs)?;
        let mut opcode = [0u8; 4];
        if original.len() >= 4 {
            opcode.copy_from_slice(&original[..4]);
            return Ok(u32::from_le_bytes(opcode));
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
    unsafe { state::original_opcode_by_address(address) }
}

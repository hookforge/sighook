#[cfg(all(feature = "patch_asm", target_arch = "aarch64"))]
use keystone_engine::{Arch, Keystone, KeystoneError, Mode};

#[cfg(all(feature = "patch_asm", target_os = "linux", target_arch = "x86_64"))]
use keystone_engine::{Arch, Keystone, KeystoneError, Mode, OptionType, OptionValue};

use crate::error::SigHookError;

const PATCH_ASM_WIDTH: usize = 4;

#[cfg(feature = "patch_asm")]
pub(crate) fn assemble_patch_opcode(address: u64, asm: &str) -> Result<u32, SigHookError> {
    let trimmed = asm.trim();
    if trimmed.is_empty() {
        return Err(SigHookError::AsmEmptyInput);
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        let bytes = assemble_x86_64(trimmed, address)?;
        return to_u32_opcode(bytes);
    }

    #[cfg(target_arch = "aarch64")]
    {
        let bytes = assemble_aarch64(trimmed, address)?;
        return to_u32_opcode(bytes);
    }

    #[allow(unreachable_code)]
    Err(SigHookError::UnsupportedPlatform)
}

#[cfg(all(feature = "patch_asm", target_arch = "aarch64"))]
fn assemble_aarch64(asm: &str, address: u64) -> Result<Vec<u8>, SigHookError> {
    let engine = keystone_engine_init(Arch::ARM64, Mode::LITTLE_ENDIAN)?;
    let output = engine
        .asm(asm.to_string(), address)
        .map_err(map_keystone_error)?;
    Ok(output.bytes)
}

#[cfg(all(feature = "patch_asm", target_os = "linux", target_arch = "x86_64"))]
fn assemble_x86_64(asm: &str, address: u64) -> Result<Vec<u8>, SigHookError> {
    let engine = keystone_engine_init(Arch::X86, Mode::MODE_64)?;
    engine
        .option(OptionType::SYNTAX, OptionValue::SYNTAX_ATT)
        .map_err(map_keystone_error)?;

    let output = engine
        .asm(asm.to_string(), address)
        .map_err(map_keystone_error)?;
    Ok(output.bytes)
}

#[cfg(all(
    feature = "patch_asm",
    any(
        target_arch = "aarch64",
        all(target_os = "linux", target_arch = "x86_64")
    )
))]
fn keystone_engine_init(arch: Arch, mode: Mode) -> Result<Keystone, SigHookError> {
    Keystone::new(arch, mode).map_err(map_keystone_error)
}

#[cfg(all(
    feature = "patch_asm",
    any(
        target_arch = "aarch64",
        all(target_os = "linux", target_arch = "x86_64")
    )
))]
fn map_keystone_error(_err: KeystoneError) -> SigHookError {
    SigHookError::AsmAssembleFailed
}

fn to_u32_opcode(bytes: Vec<u8>) -> Result<u32, SigHookError> {
    if bytes.len() != PATCH_ASM_WIDTH {
        return Err(SigHookError::AsmSizeMismatch {
            expected: PATCH_ASM_WIDTH,
            actual: bytes.len(),
        });
    }

    let mut opcode = [0u8; PATCH_ASM_WIDTH];
    opcode.copy_from_slice(&bytes);
    Ok(u32::from_le_bytes(opcode))
}

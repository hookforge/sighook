//! Runtime code patching orchestration.
//!
//! This module owns the high-level write transaction: compute the affected
//! page range, pause peer threads, make text writable, copy bytes, flush the
//! instruction cache, and restore original page protections.

use crate::error::SigHookError;
use crate::platform;
use libc::c_void;

pub(crate) mod sync;

fn patch_bytes_with_paused_callbacks(
    address: u64,
    bytes: &[u8],
    before_patch: impl FnOnce() -> Result<(), SigHookError>,
    after_patch: impl FnOnce(),
) -> Result<Vec<u8>, SigHookError> {
    if address == 0 || bytes.is_empty() {
        return Err(SigHookError::InvalidAddress);
    }

    let page_size = platform::page_size()?;
    let addr = address as usize;
    let (protect_start, protect_len) =
        platform::protect_range_start_len(addr, bytes.len(), page_size);
    let restore = platform::prepare_restore_protections(protect_start, protect_len)?;
    let mut original = vec![0u8; bytes.len()];

    sync::with_threads_paused(|| {
        before_patch()?;

        platform::make_patch_range_writable(protect_start, protect_len)?;

        unsafe {
            std::ptr::copy_nonoverlapping(addr as *const u8, original.as_mut_ptr(), bytes.len());
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), addr as *mut u8, bytes.len());
        }

        platform::flush_instruction_cache(addr as *mut c_void, bytes.len());
        platform::restore_patch_range_protection(protect_start, protect_len, &restore)?;

        after_patch();

        Ok(())
    })?;

    Ok(original)
}

fn patch_bytes(address: u64, bytes: &[u8]) -> Result<Vec<u8>, SigHookError> {
    patch_bytes_with_paused_callbacks(address, bytes, || Ok(()), || {})
}

pub(crate) fn read_bytes(address: u64, len: usize) -> Result<Vec<u8>, SigHookError> {
    if address == 0 || len == 0 {
        return Err(SigHookError::InvalidAddress);
    }

    let mut out = vec![0u8; len];
    unsafe {
        std::ptr::copy_nonoverlapping(address as *const u8, out.as_mut_ptr(), len);
    }
    Ok(out)
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn patch_u32(address: u64, new_opcode: u32) -> Result<u32, SigHookError> {
    if (address & 0b11) != 0 {
        return Err(SigHookError::InvalidAddress);
    }

    let original = patch_bytes(address, &new_opcode.to_le_bytes())?;
    let mut opcode_bytes = [0u8; 4];
    opcode_bytes.copy_from_slice(&original[0..4]);
    Ok(u32::from_le_bytes(opcode_bytes))
}

pub(crate) fn patch_bytes_public(address: u64, bytes: &[u8]) -> Result<Vec<u8>, SigHookError> {
    patch_bytes(address, bytes)
}

pub(crate) fn patch_bytes_public_with_paused_callbacks(
    address: u64,
    bytes: &[u8],
    before_patch: impl FnOnce() -> Result<(), SigHookError>,
    after_patch: impl FnOnce(),
) -> Result<Vec<u8>, SigHookError> {
    patch_bytes_with_paused_callbacks(address, bytes, before_patch, after_patch)
}

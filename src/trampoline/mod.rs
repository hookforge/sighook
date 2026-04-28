//! Out-of-line execution stubs used when a displaced instruction cannot be replayed
//! directly from saved context.
//!
//! A trampoline copies the original bytes into fresh executable memory and then
//! transfers control back to the sequential original PC. This is the generic
//! execute-original fallback used when no direct replay plan is available.

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
mod x86_64;

use crate::error::SigHookError;
use crate::platform::last_errno;
#[cfg(target_arch = "aarch64")]
use aarch64::write_original_stub;
use libc::c_void;
use std::ptr::null_mut;
#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
use x86_64::write_original_stub;

pub(crate) fn create_original_trampoline(
    address: u64,
    original_bytes: &[u8],
    step_len: u8,
) -> Result<u64, SigHookError> {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return Err(SigHookError::PageSizeUnavailable);
    }

    let page_size = page_size as usize;

    let memory = unsafe {
        libc::mmap(
            null_mut(),
            page_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };

    if memory == libc::MAP_FAILED {
        return Err(SigHookError::MmapFailed {
            errno: last_errno(),
        });
    }

    let base = memory as usize;
    let next_pc = address.wrapping_add(step_len as u64);
    write_original_stub(memory, base, next_pc, original_bytes)?;

    unsafe {
        if libc::mprotect(memory, page_size, libc::PROT_READ | libc::PROT_EXEC) != 0 {
            return Err(SigHookError::TrampolineProtectFailed {
                errno: last_errno(),
            });
        }
    }

    Ok(base as u64)
}

pub(crate) unsafe fn free_original_trampoline(trampoline_pc: u64) {
    if trampoline_pc == 0 {
        return;
    }

    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return;
    }

    unsafe {
        let _ = libc::munmap(trampoline_pc as *mut c_void, page_size as usize);
    }
}

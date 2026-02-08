#[cfg(target_arch = "aarch64")]
use crate::constants::{BR_X16, LDR_X16_LITERAL_8};
use crate::error::SigHookError;
use crate::memory::{flush_instruction_cache, last_errno};
use std::ptr::null_mut;

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

    #[cfg(target_arch = "aarch64")]
    {
        if original_bytes.len() != 4 {
            return Err(SigHookError::InvalidAddress);
        }

        let mut insn = [0u8; 4];
        insn.copy_from_slice(original_bytes);
        let original_opcode = u32::from_le_bytes(insn);

        unsafe {
            std::ptr::write_unaligned(base as *mut u32, original_opcode.to_le());
            std::ptr::write_unaligned((base + 4) as *mut u32, LDR_X16_LITERAL_8.to_le());
            std::ptr::write_unaligned((base + 8) as *mut u32, BR_X16.to_le());
            std::ptr::write_unaligned((base + 12) as *mut u64, next_pc.to_le());
        }

        flush_instruction_cache(memory, 20);
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
    {
        if original_bytes.is_empty() {
            return Err(SigHookError::InvalidAddress);
        }

        unsafe {
            std::ptr::copy_nonoverlapping(
                original_bytes.as_ptr(),
                base as *mut u8,
                original_bytes.len(),
            );
        }

        let jmp_site = base + original_bytes.len();
        if let Ok(rel_jmp) = crate::memory::encode_jmp_rel32(jmp_site as u64, next_pc) {
            unsafe {
                std::ptr::copy_nonoverlapping(rel_jmp.as_ptr(), jmp_site as *mut u8, rel_jmp.len());
            }
            flush_instruction_cache(memory, original_bytes.len() + rel_jmp.len());
        } else {
            let abs = encode_abs_jmp_indirect(next_pc);
            unsafe {
                std::ptr::copy_nonoverlapping(abs.as_ptr(), jmp_site as *mut u8, abs.len());
            }
            flush_instruction_cache(memory, original_bytes.len() + abs.len());
        }
    }

    unsafe {
        if libc::mprotect(memory, page_size, libc::PROT_READ | libc::PROT_EXEC) != 0 {
            return Err(SigHookError::TrampolineProtectFailed {
                errno: last_errno(),
            });
        }
    }

    Ok(base as u64)
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
fn encode_abs_jmp_indirect(to_address: u64) -> [u8; 14] {
    let mut bytes = [0u8; 14];
    bytes[0] = 0xFF;
    bytes[1] = 0x25;
    bytes[2] = 0x00;
    bytes[3] = 0x00;
    bytes[4] = 0x00;
    bytes[5] = 0x00;
    bytes[6..14].copy_from_slice(&to_address.to_le_bytes());
    bytes
}

use crate::arch::encode_jmp_rel32;
use crate::error::SigHookError;
use crate::platform::flush_instruction_cache;
use libc::c_void;

pub(super) fn write_original_stub(
    memory: *mut c_void,
    base: usize,
    next_pc: u64,
    original_bytes: &[u8],
) -> Result<(), SigHookError> {
    if original_bytes.is_empty() {
        return Err(SigHookError::InvalidAddress);
    }

    // Copy the displaced instruction bytes verbatim, then append whichever jump
    // form can reach `next_pc`.
    unsafe {
        std::ptr::copy_nonoverlapping(
            original_bytes.as_ptr(),
            base as *mut u8,
            original_bytes.len(),
        );
    }

    let jmp_site = base + original_bytes.len();
    if let Ok(rel_jmp) = encode_jmp_rel32(jmp_site as u64, next_pc) {
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

    Ok(())
}

fn encode_abs_jmp_indirect(to_address: u64) -> [u8; 14] {
    let mut bytes = [0u8; 14];
    // `jmp qword ptr [rip+0]` followed by the absolute destination literal.
    bytes[0] = 0xFF;
    bytes[1] = 0x25;
    bytes[2] = 0x00;
    bytes[3] = 0x00;
    bytes[4] = 0x00;
    bytes[5] = 0x00;
    bytes[6..14].copy_from_slice(&to_address.to_le_bytes());
    bytes
}

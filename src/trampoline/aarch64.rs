use crate::constants::{BR_X16, LDR_X16_LITERAL_8};
use crate::error::SigHookError;
use crate::platform::flush_instruction_cache;
use libc::c_void;

pub(super) fn write_original_stub(
    memory: *mut c_void,
    base: usize,
    next_pc: u64,
    original_bytes: &[u8],
) -> Result<(), SigHookError> {
    if original_bytes.len() != 4 {
        return Err(SigHookError::InvalidAddress);
    }

    // Layout:
    //   [0x00] original displaced instruction
    //   [0x04] ldr x16, #8
    //   [0x08] br  x16
    //   [0x0C] absolute 64-bit return address
    //
    // This is intentionally tiny and avoids any dependence on branch reach.
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
    Ok(())
}

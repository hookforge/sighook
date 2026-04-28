mod decode;

pub(crate) use decode::instruction_width;

use crate::error::SigHookError;

#[inline]
pub(crate) fn is_int3(byte: u8) -> bool {
    byte == crate::constants::INT3_OPCODE
}

#[inline]
pub(crate) fn read_u8(address: u64) -> u8 {
    unsafe { std::ptr::read_volatile(address as *const u8) }
}

#[inline]
pub(crate) fn int3_opcode() -> u8 {
    crate::constants::INT3_OPCODE
}

pub(crate) fn encode_jmp_rel32(
    from_address: u64,
    to_address: u64,
) -> Result<[u8; 5], SigHookError> {
    // x86 relative jumps are based on RIP after the jump instruction itself.
    let offset = (to_address as i128) - ((from_address as i128) + 5);
    if offset < i32::MIN as i128 || offset > i32::MAX as i128 {
        return Err(SigHookError::BranchOutOfRange);
    }

    let mut bytes = [0u8; 5];
    bytes[0] = 0xE9;
    bytes[1..5].copy_from_slice(&(offset as i32).to_le_bytes());
    Ok(bytes)
}

pub(crate) fn encode_absolute_jump(to_address: u64) -> [u8; 14] {
    let mut bytes = [0u8; 14];
    // jmp qword ptr [rip+0]
    bytes[0] = 0xFF;
    bytes[1] = 0x25;
    bytes[2..6].copy_from_slice(&0u32.to_le_bytes());
    bytes[6..14].copy_from_slice(&to_address.to_le_bytes());
    bytes
}

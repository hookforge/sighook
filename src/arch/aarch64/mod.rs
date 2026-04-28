use crate::constants::{BRK_MASK, BRK_OPCODE};
use crate::error::SigHookError;

#[inline]
pub(crate) fn is_brk(opcode: u32) -> bool {
    (opcode & BRK_MASK) == (BRK_OPCODE & BRK_MASK)
}

#[inline]
pub(crate) fn read_u32(address: u64) -> u32 {
    unsafe { u32::from_le(std::ptr::read_volatile(address as *const u32)) }
}

#[inline]
pub(crate) fn instruction_width(_address: u64) -> Result<u8, SigHookError> {
    Ok(4)
}

pub(crate) fn encode_b(from_address: u64, to_address: u64) -> Result<u32, SigHookError> {
    if (from_address & 0b11) != 0 || (to_address & 0b11) != 0 {
        return Err(SigHookError::InvalidAddress);
    }

    let offset = (to_address as i128) - (from_address as i128);
    if (offset & 0b11) != 0 {
        return Err(SigHookError::BranchOutOfRange);
    }

    // AArch64 `b` encodes a signed 26-bit word offset, so the low two bits are
    // implicit zeros and the effective range is +/- 128 MiB.
    let imm26 = offset >> 2;
    let min = -(1_i128 << 25);
    let max = (1_i128 << 25) - 1;
    if imm26 < min || imm26 > max {
        return Err(SigHookError::BranchOutOfRange);
    }

    let imm26_bits = (imm26 as i64 as u32) & 0x03FF_FFFF;
    Ok(0x1400_0000 | imm26_bits)
}

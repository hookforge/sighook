#[cfg(any(target_os = "macos", target_os = "ios"))]
use crate::constants::VM_PROT_COPY;
#[cfg(target_arch = "aarch64")]
use crate::constants::{BR_X16, BRK_MASK, BRK_OPCODE, LDR_X16_LITERAL_8};
use crate::error::SigHookError;
use libc::{c_int, c_void};

#[cfg(any(target_os = "macos", target_os = "ios"))]
unsafe extern "C" {
    fn mach_vm_protect(
        target_task: libc::vm_map_t,
        address: libc::mach_vm_address_t,
        size: libc::mach_vm_size_t,
        set_maximum: libc::boolean_t,
        new_protection: libc::vm_prot_t,
    ) -> libc::kern_return_t;
}

#[cfg(all(any(target_os = "macos", target_os = "ios"), target_arch = "aarch64"))]
unsafe extern "C" {
    fn sys_icache_invalidate(start: *mut c_void, len: usize);
}

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
unsafe extern "C" {
    fn __clear_cache(begin: *mut c_void, end: *mut c_void);
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[inline]
pub(crate) fn last_errno() -> c_int {
    unsafe { *libc::__error() }
}

#[cfg(target_os = "linux")]
#[inline]
pub(crate) fn last_errno() -> c_int {
    unsafe { *libc::__errno_location() }
}

#[cfg(target_os = "android")]
#[inline]
pub(crate) fn last_errno() -> c_int {
    unsafe { *libc::__errno() }
}

#[cfg(target_arch = "aarch64")]
#[inline]
pub(crate) fn is_brk(opcode: u32) -> bool {
    (opcode & BRK_MASK) == (BRK_OPCODE & BRK_MASK)
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
#[inline]
pub(crate) fn is_int3(byte: u8) -> bool {
    byte == crate::constants::INT3_OPCODE
}

#[cfg(target_arch = "aarch64")]
#[inline]
pub(crate) fn read_u32(address: u64) -> u32 {
    unsafe { u32::from_le(std::ptr::read_volatile(address as *const u32)) }
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
#[inline]
pub(crate) fn read_u8(address: u64) -> u8 {
    unsafe { std::ptr::read_volatile(address as *const u8) }
}

fn page_size() -> Result<usize, SigHookError> {
    let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if value <= 0 {
        return Err(SigHookError::PageSizeUnavailable);
    }
    Ok(value as usize)
}

fn protect_range_start_len(address: usize, len: usize, page_size: usize) -> (usize, usize) {
    let start = address & !(page_size - 1);
    let end_inclusive = address + len - 1;
    let end_page = end_inclusive & !(page_size - 1);
    let total = (end_page + page_size) - start;
    (start, total)
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
#[inline]
fn executable_restore_protections() -> &'static [libc::vm_prot_t] {
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        const PROTS: &[libc::vm_prot_t] = &[
            libc::VM_PROT_READ | libc::VM_PROT_EXECUTE,
            libc::VM_PROT_READ | libc::VM_PROT_EXECUTE | VM_PROT_COPY,
        ];
        PROTS
    }

    #[cfg(not(all(target_os = "macos", target_arch = "x86_64")))]
    {
        const PROTS: &[libc::vm_prot_t] = &[libc::VM_PROT_READ | libc::VM_PROT_EXECUTE];
        PROTS
    }
}

#[cfg(target_arch = "aarch64")]
#[inline]
pub(crate) fn instruction_width(_address: u64) -> Result<u8, SigHookError> {
    Ok(4)
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
pub(crate) fn instruction_width(address: u64) -> Result<u8, SigHookError> {
    use iced_x86::{Decoder, DecoderOptions};

    let mut bytes = [0u8; 15];
    unsafe {
        std::ptr::copy_nonoverlapping(address as *const u8, bytes.as_mut_ptr(), bytes.len());
    }

    let mut decoder = Decoder::with_ip(64, &bytes, address, DecoderOptions::NONE);
    let instruction = decoder.decode();
    if instruction.is_invalid() {
        return Err(SigHookError::DecodeFailed);
    }

    Ok(instruction.len() as u8)
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
#[inline]
pub(crate) fn int3_opcode() -> u8 {
    crate::constants::INT3_OPCODE
}

fn patch_bytes(address: u64, bytes: &[u8]) -> Result<Vec<u8>, SigHookError> {
    if address == 0 || bytes.is_empty() {
        return Err(SigHookError::InvalidAddress);
    }

    let page_size = page_size()?;
    let addr = address as usize;
    let (protect_start, protect_len) = protect_range_start_len(addr, bytes.len(), page_size);

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        let writable_prot = libc::VM_PROT_READ | libc::VM_PROT_WRITE | VM_PROT_COPY;

        let kr = unsafe {
            mach_vm_protect(
                libc::mach_task_self(),
                protect_start as u64,
                protect_len as u64,
                0,
                writable_prot,
            )
        };

        if kr != 0 {
            return Err(SigHookError::ProtectWritableFailed {
                kr,
                errno: last_errno(),
            });
        }
    }

    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    {
        let result = unsafe {
            libc::mprotect(
                protect_start as *mut c_void,
                protect_len,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            )
        };

        if result != 0 {
            return Err(SigHookError::ProtectWritableFailed {
                errno: last_errno(),
            });
        }
    }

    let mut original = vec![0u8; bytes.len()];
    unsafe {
        std::ptr::copy_nonoverlapping(addr as *const u8, original.as_mut_ptr(), bytes.len());
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), addr as *mut u8, bytes.len());
    }

    flush_instruction_cache(addr as *mut c_void, bytes.len());

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        let mut last_kr = 0;
        for &prot in executable_restore_protections() {
            let kr_restore = unsafe {
                mach_vm_protect(
                    libc::mach_task_self(),
                    protect_start as u64,
                    protect_len as u64,
                    0,
                    prot,
                )
            };

            if kr_restore == 0 {
                last_kr = 0;
                break;
            }

            last_kr = kr_restore;
        }

        if last_kr != 0 {
            return Err(SigHookError::ProtectExecutableFailed {
                kr: last_kr,
                errno: last_errno(),
            });
        }
    }

    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        any(target_arch = "aarch64", target_arch = "x86_64")
    ))]
    {
        let result = unsafe {
            libc::mprotect(
                protect_start as *mut c_void,
                protect_len,
                libc::PROT_READ | libc::PROT_EXEC,
            )
        };

        if result != 0 {
            return Err(SigHookError::ProtectExecutableFailed {
                errno: last_errno(),
            });
        }
    }

    Ok(original)
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
pub(crate) fn patch_u8(address: u64, new_opcode: u8) -> Result<u8, SigHookError> {
    let original = patch_bytes(address, &[new_opcode])?;
    Ok(original[0])
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
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

pub(crate) fn flush_instruction_cache(address: *mut c_void, len: usize) {
    #[cfg(all(any(target_os = "macos", target_os = "ios"), target_arch = "aarch64"))]
    unsafe {
        sys_icache_invalidate(address, len);
    }

    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        target_arch = "aarch64"
    ))]
    unsafe {
        let end = (address as usize).wrapping_add(len) as *mut c_void;
        __clear_cache(address, end);
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (address, len);
    }
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn encode_b(from_address: u64, to_address: u64) -> Result<u32, SigHookError> {
    if (from_address & 0b11) != 0 || (to_address & 0b11) != 0 {
        return Err(SigHookError::InvalidAddress);
    }

    let offset = (to_address as i128) - (from_address as i128);
    if (offset & 0b11) != 0 {
        return Err(SigHookError::BranchOutOfRange);
    }

    let imm26 = offset >> 2;
    let min = -(1_i128 << 25);
    let max = (1_i128 << 25) - 1;
    if imm26 < min || imm26 > max {
        return Err(SigHookError::BranchOutOfRange);
    }

    let imm26_bits = (imm26 as i64 as u32) & 0x03FF_FFFF;
    Ok(0x1400_0000 | imm26_bits)
}

#[cfg(target_arch = "aarch64")]
pub(crate) fn patch_far_jump(from_address: u64, to_address: u64) -> Result<u32, SigHookError> {
    if (from_address & 0b11) != 0 {
        return Err(SigHookError::InvalidAddress);
    }

    let mut bytes = [0u8; 16];
    bytes[0..4].copy_from_slice(&LDR_X16_LITERAL_8.to_le_bytes());
    bytes[4..8].copy_from_slice(&BR_X16.to_le_bytes());
    bytes[8..16].copy_from_slice(&to_address.to_le_bytes());

    let original = patch_bytes(from_address, &bytes)?;
    let mut opcode_bytes = [0u8; 4];
    opcode_bytes.copy_from_slice(&original[0..4]);
    Ok(u32::from_le_bytes(opcode_bytes))
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
pub(crate) fn encode_jmp_rel32(
    from_address: u64,
    to_address: u64,
) -> Result<[u8; 5], SigHookError> {
    let offset = (to_address as i128) - ((from_address as i128) + 5);
    if offset < i32::MIN as i128 || offset > i32::MAX as i128 {
        return Err(SigHookError::BranchOutOfRange);
    }

    let mut bytes = [0u8; 5];
    bytes[0] = 0xE9;
    bytes[1..5].copy_from_slice(&(offset as i32).to_le_bytes());
    Ok(bytes)
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
pub(crate) fn encode_absolute_jump(to_address: u64) -> [u8; 14] {
    let mut bytes = [0u8; 14];
    // jmp qword ptr [rip+0]
    bytes[0] = 0xFF;
    bytes[1] = 0x25;
    bytes[2..6].copy_from_slice(&0u32.to_le_bytes());
    bytes[6..14].copy_from_slice(&to_address.to_le_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::protect_range_start_len;

    #[test]
    fn protect_range_single_page() {
        let page_size = 0x1000;
        let (start, len) = protect_range_start_len(0x1234, 4, page_size);
        assert_eq!(start, 0x1000);
        assert_eq!(len, 0x1000);
    }

    #[test]
    fn protect_range_cross_page() {
        let page_size = 0x1000;
        let (start, len) = protect_range_start_len(0x1ffe, 8, page_size);
        assert_eq!(start, 0x1000);
        assert_eq!(len, 0x2000);
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    #[test]
    fn executable_restore_protections_match_target() {
        let prot_list = super::executable_restore_protections();
        assert!(!prot_list.is_empty());
        assert_eq!(prot_list[0], libc::VM_PROT_READ | libc::VM_PROT_EXECUTE);

        #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
        {
            assert_eq!(prot_list.len(), 2);
            assert_eq!(
                prot_list[1],
                libc::VM_PROT_READ | libc::VM_PROT_EXECUTE | crate::constants::VM_PROT_COPY
            );
        }

        #[cfg(not(all(target_os = "macos", target_arch = "x86_64")))]
        {
            assert_eq!(prot_list.len(), 1);
        }
    }
}

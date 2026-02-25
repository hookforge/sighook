#[cfg(any(target_os = "macos", target_os = "ios"))]
use crate::constants::VM_PROT_COPY;
#[cfg(target_arch = "aarch64")]
use crate::constants::{BRK_MASK, BRK_OPCODE};
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

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
unsafe extern "C" {
    fn mach_vm_read_overwrite(
        target_task: libc::vm_map_t,
        address: libc::mach_vm_address_t,
        size: libc::mach_vm_size_t,
        data: libc::mach_vm_address_t,
        outsize: *mut libc::mach_vm_size_t,
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

    let (bytes, available_len) = read_decode_window_x86(address)?;

    let mut decoder = Decoder::with_ip(64, &bytes[..available_len], address, DecoderOptions::NONE);
    let instruction = decoder.decode();
    if instruction.is_invalid() {
        return Err(SigHookError::DecodeFailed);
    }

    Ok(instruction.len() as u8)
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
fn read_decode_window_x86(address: u64) -> Result<([u8; 15], usize), SigHookError> {
    if address == 0 {
        return Err(SigHookError::InvalidAddress);
    }

    let page_size = page_size()?;
    let addr = address as usize;
    let mut bytes = [0u8; 15];
    let page_offset = addr % page_size;
    let first_chunk_len = bytes.len().min(page_size - page_offset);
    read_memory_chunk_x86(addr, &mut bytes[..first_chunk_len])?;

    let mut total_len = first_chunk_len;
    if first_chunk_len < bytes.len() {
        let second_chunk_addr = addr
            .checked_add(first_chunk_len)
            .ok_or(SigHookError::InvalidAddress)?;
        let second_chunk_len = bytes.len() - first_chunk_len;
        if read_memory_chunk_x86(
            second_chunk_addr,
            &mut bytes[first_chunk_len..first_chunk_len + second_chunk_len],
        )
        .is_ok()
        {
            total_len += second_chunk_len;
        }
    }

    Ok((bytes, total_len))
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn read_memory_chunk_x86(address: usize, out: &mut [u8]) -> Result<(), SigHookError> {
    if out.is_empty() {
        return Ok(());
    }

    let local = libc::iovec {
        iov_base: out.as_mut_ptr().cast::<c_void>(),
        iov_len: out.len(),
    };
    let remote = libc::iovec {
        iov_base: address as *mut c_void,
        iov_len: out.len(),
    };

    let read_size = unsafe { libc::process_vm_readv(libc::getpid(), &local, 1, &remote, 1, 0) };
    if read_size >= 0 {
        if read_size as usize == out.len() {
            return Ok(());
        }
        return Err(SigHookError::InvalidAddress);
    }

    let errno = last_errno();
    if !matches!(errno, libc::EPERM | libc::EACCES | libc::ENOSYS) {
        return Err(SigHookError::InvalidAddress);
    }

    read_memory_chunk_x86_proc_mem(address, out)
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn read_memory_chunk_x86_proc_mem(address: usize, out: &mut [u8]) -> Result<(), SigHookError> {
    if out.is_empty() {
        return Ok(());
    }

    const PROC_SELF_MEM: &[u8] = b"/proc/self/mem\0";
    let fd = unsafe {
        libc::open(
            PROC_SELF_MEM.as_ptr().cast::<libc::c_char>(),
            libc::O_RDONLY,
        )
    };
    if fd < 0 {
        return Err(SigHookError::InvalidAddress);
    }

    let result = (|| -> Result<(), SigHookError> {
        let mut copied = 0usize;
        while copied < out.len() {
            let current_address = address
                .checked_add(copied)
                .ok_or(SigHookError::InvalidAddress)?;
            let offset =
                i64::try_from(current_address).map_err(|_| SigHookError::InvalidAddress)?;
            let read_size = unsafe {
                libc::pread(
                    fd,
                    out[copied..].as_mut_ptr().cast::<c_void>(),
                    out.len() - copied,
                    offset as libc::off_t,
                )
            };

            if read_size <= 0 {
                return Err(SigHookError::InvalidAddress);
            }

            copied += read_size as usize;
        }
        Ok(())
    })();

    unsafe {
        libc::close(fd);
    }

    result
}

#[cfg(all(target_arch = "x86_64", target_os = "macos"))]
fn read_memory_chunk_x86(address: usize, out: &mut [u8]) -> Result<(), SigHookError> {
    if out.is_empty() {
        return Ok(());
    }

    let mut out_size: libc::mach_vm_size_t = 0;
    let kr = unsafe {
        mach_vm_read_overwrite(
            libc::mach_task_self(),
            address as libc::mach_vm_address_t,
            out.len() as libc::mach_vm_size_t,
            out.as_mut_ptr() as libc::mach_vm_address_t,
            &mut out_size,
        )
    };
    if kr != 0 || out_size as usize != out.len() {
        return Err(SigHookError::InvalidAddress);
    }

    Ok(())
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

    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
    use super::{instruction_width, page_size};

    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    use super::read_memory_chunk_x86_proc_mem;

    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
    use crate::error::SigHookError;

    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
    use libc::c_void;

    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
    fn map_two_pages(page_size: usize) -> *mut c_void {
        unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                page_size * 2,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        }
    }

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

    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn instruction_width_page_end_with_unmapped_next_page() {
        let page_size = page_size().expect("page size should be available");
        let mapping = map_two_pages(page_size);
        assert_ne!(mapping, libc::MAP_FAILED);

        let first_page_base = mapping as *mut u8;
        let second_page = unsafe { first_page_base.add(page_size) } as *mut c_void;
        assert_eq!(
            unsafe { libc::mprotect(second_page, page_size, libc::PROT_NONE) },
            0
        );

        let patchpoint = unsafe { first_page_base.add(page_size - 1) };
        unsafe {
            std::ptr::write_volatile(patchpoint, 0x90);
        }

        let len = instruction_width(patchpoint as u64).expect("decode should succeed");
        assert_eq!(len, 1);

        assert_eq!(unsafe { libc::munmap(mapping, page_size * 2) }, 0);
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn instruction_width_page_end_incomplete_instruction_returns_error() {
        let page_size = page_size().expect("page size should be available");
        let mapping = map_two_pages(page_size);
        assert_ne!(mapping, libc::MAP_FAILED);

        let first_page_base = mapping as *mut u8;
        let second_page = unsafe { first_page_base.add(page_size) } as *mut c_void;
        assert_eq!(
            unsafe { libc::mprotect(second_page, page_size, libc::PROT_NONE) },
            0
        );

        let patchpoint = unsafe { first_page_base.add(page_size - 1) };
        unsafe {
            std::ptr::write_volatile(patchpoint, 0x0F);
        }

        let err = instruction_width(patchpoint as u64).expect_err("decode should fail");
        assert_eq!(err, SigHookError::DecodeFailed);

        assert_eq!(unsafe { libc::munmap(mapping, page_size * 2) }, 0);
    }

    #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn instruction_width_cross_page_when_next_page_readable() {
        let page_size = page_size().expect("page size should be available");
        let mapping = map_two_pages(page_size);
        assert_ne!(mapping, libc::MAP_FAILED);

        let first_page_base = mapping as *mut u8;
        let patchpoint = unsafe { first_page_base.add(page_size - 2) };
        let insn = [0xE9, 0x01, 0x00, 0x00, 0x00];
        unsafe {
            std::ptr::copy_nonoverlapping(insn.as_ptr(), patchpoint, insn.len());
        }

        let len = instruction_width(patchpoint as u64).expect("decode should succeed");
        assert_eq!(len, 5);

        assert_eq!(unsafe { libc::munmap(mapping, page_size * 2) }, 0);
    }

    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    #[test]
    fn read_memory_chunk_proc_mem_reads_readable_memory() {
        let page_size = page_size().expect("page size should be available");
        let mapping = map_two_pages(page_size);
        assert_ne!(mapping, libc::MAP_FAILED);

        let base = mapping as *mut u8;
        let address = unsafe { base.add(128) };
        let expected = [0x48u8, 0x89, 0xE5, 0x90];
        unsafe {
            std::ptr::copy_nonoverlapping(expected.as_ptr(), address, expected.len());
        }

        let mut out = [0u8; 4];
        read_memory_chunk_x86_proc_mem(address as usize, &mut out)
            .expect("proc mem read should succeed");
        assert_eq!(out, expected);

        assert_eq!(unsafe { libc::munmap(mapping, page_size * 2) }, 0);
    }

    #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
    #[test]
    fn read_memory_chunk_proc_mem_returns_error_on_unmapped_range() {
        let page_size = page_size().expect("page size should be available");
        let mapping = map_two_pages(page_size);
        assert_ne!(mapping, libc::MAP_FAILED);

        let base = mapping as *mut u8;
        let unmapped_page = unsafe { base.add(page_size) } as *mut c_void;
        assert_eq!(unsafe { libc::munmap(unmapped_page, page_size) }, 0);

        let mut out = [0u8; 8];
        let err = read_memory_chunk_x86_proc_mem(unmapped_page as usize, &mut out)
            .expect_err("proc mem read should fail on unmapped range");
        assert_eq!(err, SigHookError::InvalidAddress);

        assert_eq!(unsafe { libc::munmap(mapping, page_size) }, 0);
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

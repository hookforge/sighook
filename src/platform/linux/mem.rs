use crate::error::SigHookError;
use crate::platform::last_errno;
use libc::c_void;

pub(crate) fn read_memory_chunk_x86(address: usize, out: &mut [u8]) -> Result<(), SigHookError> {
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

    // Fall back to `/proc/self/mem` when `process_vm_readv` is unavailable or denied
    // for the current environment.
    read_memory_chunk_x86_proc_mem(address, out)
}

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

#[cfg(test)]
mod tests {
    use super::read_memory_chunk_x86_proc_mem;
    use crate::error::SigHookError;
    use crate::platform::page_size;
    use libc::c_void;

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
}

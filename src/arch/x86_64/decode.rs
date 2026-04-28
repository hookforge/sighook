use crate::error::SigHookError;
use crate::platform::page_size;
use iced_x86::{Decoder, DecoderOptions};

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
use crate::platform::apple::mem::read_memory_chunk_x86;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use crate::platform::linux::mem::read_memory_chunk_x86;

pub(crate) fn instruction_width(address: u64) -> Result<u8, SigHookError> {
    let (bytes, available_len) = read_decode_window_x86(address)?;

    let mut decoder = Decoder::with_ip(64, &bytes[..available_len], address, DecoderOptions::NONE);
    let instruction = decoder.decode();
    if instruction.is_invalid() {
        return Err(SigHookError::DecodeFailed);
    }

    Ok(instruction.len() as u8)
}

fn read_decode_window_x86(address: u64) -> Result<([u8; 15], usize), SigHookError> {
    if address == 0 {
        return Err(SigHookError::InvalidAddress);
    }

    let page_size = page_size()?;
    let addr = address as usize;
    let mut bytes = [0u8; 15];
    let page_offset = addr % page_size;
    let first_chunk_len = bytes.len().min(page_size - page_offset);

    // x86 instructions are up to 15 bytes long, so decoding near a page boundary may
    // need bytes from the following page.
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

#[cfg(test)]
mod tests {
    use super::instruction_width;
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
}

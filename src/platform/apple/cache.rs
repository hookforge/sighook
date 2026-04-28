use libc::c_void;

#[cfg(all(any(target_os = "macos", target_os = "ios"), target_arch = "aarch64"))]
unsafe extern "C" {
    fn sys_icache_invalidate(start: *mut c_void, len: usize);
}

pub(crate) fn flush_instruction_cache(address: *mut c_void, len: usize) {
    #[cfg(all(any(target_os = "macos", target_os = "ios"), target_arch = "aarch64"))]
    unsafe {
        sys_icache_invalidate(address, len);
    }

    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        let _ = (address, len);
    }
}

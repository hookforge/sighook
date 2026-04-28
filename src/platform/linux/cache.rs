use libc::c_void;

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
unsafe extern "C" {
    fn __clear_cache(begin: *mut c_void, end: *mut c_void);
}

pub(crate) fn flush_instruction_cache(address: *mut c_void, len: usize) {
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        target_arch = "aarch64"
    ))]
    unsafe {
        let end = (address as usize).wrapping_add(len) as *mut c_void;
        __clear_cache(address, end);
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        let _ = (address, len);
    }
}

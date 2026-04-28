use crate::error::SigHookError;
use libc::c_int;

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) mod apple;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) mod linux;

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) use apple::cache::flush_instruction_cache;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) use apple::vm::{
    make_patch_range_writable, prepare_restore_protections, restore_patch_range_protection,
};

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) use linux::cache::flush_instruction_cache;
#[cfg(any(target_os = "linux", target_os = "android"))]
pub(crate) use linux::vm::{
    make_patch_range_writable, prepare_restore_protections, restore_patch_range_protection,
};

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

pub(crate) fn page_size() -> Result<usize, SigHookError> {
    let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if value <= 0 {
        return Err(SigHookError::PageSizeUnavailable);
    }
    Ok(value as usize)
}

pub(crate) fn protect_range_start_len(
    address: usize,
    len: usize,
    page_size: usize,
) -> (usize, usize) {
    // OS page-protection calls operate on full pages, so expand to the
    // minimal page-aligned span that covers the requested byte range.
    let start = address & !(page_size - 1);
    let end_inclusive = address + len - 1;
    let end_page = end_inclusive & !(page_size - 1);
    let total = (end_page + page_size) - start;
    (start, total)
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
}

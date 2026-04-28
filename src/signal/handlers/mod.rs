#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
mod x86_64;

#[inline]
#[cfg(target_arch = "aarch64")]
pub(super) fn current_trap_handler_raw() -> libc::sighandler_t {
    aarch64::trap_handler as *const () as libc::sighandler_t
}

#[inline]
#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
pub(super) fn current_trap_handler_raw() -> libc::sighandler_t {
    x86_64::trap_handler as *const () as libc::sighandler_t
}

#[cfg(target_arch = "aarch64")]
#[inline]
pub(super) fn current_fault_handler_raw() -> libc::sighandler_t {
    aarch64::fault_handler as *const () as libc::sighandler_t
}

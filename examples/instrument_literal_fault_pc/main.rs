#[cfg(target_arch = "aarch64")]
use sighook::{HookContext, instrument};

#[cfg(target_arch = "aarch64")]
extern "C" fn on_hit(_address: u64, _ctx: *mut HookContext) {}

#[unsafe(no_mangle)]
pub extern "C" fn install_literal_fault_hook() {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let patchpoint = libc::dlsym(libc::RTLD_DEFAULT, c"literal_fault_patchpoint".as_ptr());
        if patchpoint.is_null() {
            return;
        }

        let _ = instrument(patchpoint as u64, on_hit);
    }
}

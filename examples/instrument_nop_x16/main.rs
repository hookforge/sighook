use sighook::{HookContext, instrument};

extern "C" fn on_hit(_address: u64, _ctx: *mut HookContext) {}

#[used]
#[cfg_attr(
    any(target_os = "macos", target_os = "ios"),
    unsafe(link_section = "__DATA,__mod_init_func")
)]
#[cfg_attr(
    any(target_os = "linux", target_os = "android"),
    unsafe(link_section = ".init_array")
)]
static INIT_ARRAY: extern "C" fn() = init;

extern "C" fn init() {
    #[cfg(target_arch = "aarch64")]
    unsafe {
        let patchpoint = libc::dlsym(libc::RTLD_DEFAULT, c"read_marker_patchpoint".as_ptr());
        if patchpoint.is_null() {
            return;
        }

        let _ = instrument(patchpoint as u64, on_hit);
    }
}

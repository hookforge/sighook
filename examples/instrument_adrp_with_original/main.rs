#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
use sighook::{HookContext, instrument};

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
extern "C" fn on_hit(_address: u64, ctx: *mut HookContext) {
    unsafe {
        (*ctx).regs.named.x8 = 40;
        (*ctx).regs.named.x9 = 2;
    }
}

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
    #[cfg(all(
        any(target_os = "linux", target_os = "android"),
        target_arch = "aarch64"
    ))]
    unsafe {
        let patchpoint = libc::dlsym(libc::RTLD_DEFAULT, c"calc_adrp_insn".as_ptr());
        if patchpoint.is_null() {
            return;
        }

        let _ = instrument(patchpoint as u64, on_hit);
    }
}

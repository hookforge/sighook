#[cfg(target_arch = "aarch64")]
use sighook::{HookContext, prepatched};

#[cfg(target_arch = "aarch64")]
const ADD_W0_W8_W9_OPCODE: u32 = 0x0B09_0100;

#[cfg(target_arch = "aarch64")]
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
        let patchpoint = libc::dlsym(libc::RTLD_DEFAULT, c"calc_prepatched_patchpoint".as_ptr());
        if patchpoint.is_null() {
            return;
        }

        let patchpoint = patchpoint as u64;
        let _ = prepatched::instrument_no_original(patchpoint, on_hit);
        let _ = prepatched::cache_original_opcode(patchpoint, ADD_W0_W8_W9_OPCODE);
        let _ = prepatched::instrument(patchpoint, on_hit);
    }
}

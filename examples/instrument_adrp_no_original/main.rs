#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
use sighook::HookContext;

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
use sighook::instrument_no_original;

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
static mut G_MAGIC_ADDR: u64 = 0;

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
extern "C" fn emulate_adrp(_address: u64, ctx: *mut HookContext) {
    unsafe {
        let page_base = G_MAGIC_ADDR & !0xFFF;
        if page_base != 0 {
            (*ctx).regs.named.x10 = page_base;
        }
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
        let magic = libc::dlsym(libc::RTLD_DEFAULT, c"g_magic".as_ptr());
        if patchpoint.is_null() || magic.is_null() {
            return;
        }

        G_MAGIC_ADDR = magic as u64;
        let _ = instrument_no_original(patchpoint as u64, emulate_adrp);
    }
}

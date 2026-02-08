use sighook::{HookContext, instrument_no_original};

#[cfg(all(any(target_os = "macos", target_os = "ios"), target_arch = "aarch64"))]
const ADD_INSN_OFFSET: u64 = 0x14;

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
const X86_PATCHPOINT_OFFSET: u64 = 0x4;

extern "C" fn replace_logic(_address: u64, ctx: *mut HookContext) {
    unsafe {
        #[cfg(target_arch = "aarch64")]
        {
            (*ctx).regs.named.x0 = 99;
        }

        #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
        {
            (*ctx).rax = 99;
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
    unsafe {
        let target_address = {
            #[cfg(all(
                any(target_os = "linux", target_os = "android"),
                target_arch = "aarch64"
            ))]
            {
                let symbol = libc::dlsym(libc::RTLD_DEFAULT, c"calc_add_insn".as_ptr());
                if symbol.is_null() {
                    return;
                }
                symbol as u64
            }

            #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
            {
                let symbol = libc::dlsym(libc::RTLD_DEFAULT, c"calc".as_ptr());
                if symbol.is_null() {
                    return;
                }
                symbol as u64 + X86_PATCHPOINT_OFFSET
            }

            #[cfg(all(any(target_os = "macos", target_os = "ios"), target_arch = "aarch64"))]
            {
                let symbol = libc::dlsym(libc::RTLD_DEFAULT, c"calc".as_ptr());
                if symbol.is_null() {
                    return;
                }
                symbol as u64 + ADD_INSN_OFFSET
            }
        };

        let _ = instrument_no_original(target_address, replace_logic);
    }
}

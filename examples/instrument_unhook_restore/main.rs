use sighook::{HookContext, instrument, unhook};

#[cfg(all(any(target_os = "macos", target_os = "ios"), target_arch = "aarch64"))]
const ADD_INSN_OFFSET: u64 = 0x14;

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
const X86_PATCHPOINT_OFFSET: u64 = 0x4;

extern "C" fn on_hit_should_not_run(_address: u64, ctx: *mut HookContext) {
    unsafe {
        #[cfg(target_arch = "aarch64")]
        {
            (*ctx).regs.named.x8 = 120;
            (*ctx).regs.named.x9 = 3;
        }

        #[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
        {
            (*ctx).rax = 123;
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
        let calc_symbol = libc::dlsym(libc::RTLD_DEFAULT, c"calc".as_ptr());
        if calc_symbol.is_null() {
            return;
        }
        let calc_fn: extern "C" fn(i32, i32) -> i32 = std::mem::transmute(calc_symbol);

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

        let _ = instrument(target_address, on_hit_should_not_run);

        let hooked = calc_fn(3, 4);
        println!("hooked_calc(3, 4) = {hooked}");
        if hooked != 123 {
            return;
        }

        let _ = unhook(target_address);
    }
}

use sighook::patchcode;

#[cfg(all(any(target_os = "macos", target_os = "ios"), target_arch = "aarch64"))]
const ADD_INSN_OFFSET: u64 = 0x14;

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
const X86_PATCHPOINT_OFFSET: u64 = 0x6;

#[cfg(target_arch = "aarch64")]
const PATCH_ADD_TO_MUL_OPCODE: u32 = 0x1B09_7D00;

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
const PATCH_ADD_TO_MUL_OPCODE: u32 = 0x90_90_EA_F7;

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

        let _ = patchcode(target_address, PATCH_ADD_TO_MUL_OPCODE);
    }
}

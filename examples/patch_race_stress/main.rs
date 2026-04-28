use sighook::{HookContext, inline_hook, unhook};
use std::thread;
use std::time::Duration;

extern "C" fn replace_in_callback(_address: u64, ctx: *mut HookContext) {
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
        let symbol = libc::dlsym(libc::RTLD_DEFAULT, c"stress_target".as_ptr());
        if symbol.is_null() {
            return;
        }

        let function_entry = symbol as u64;
        thread::spawn(move || {
            for _ in 0..500 {
                if let Err(err) = inline_hook(function_entry, replace_in_callback) {
                    eprintln!("inline_hook failed: {err}");
                    std::process::abort();
                }
                thread::sleep(Duration::from_micros(200));
                if let Err(err) = unhook(function_entry) {
                    eprintln!("unhook failed: {err}");
                    std::process::abort();
                }
                thread::sleep(Duration::from_micros(200));
            }
        });
    }
}

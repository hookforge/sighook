use sighook::{HookContext, inline_hook};

#[cfg(any(
    target_arch = "aarch64",
    all(target_arch = "x86_64", target_os = "macos")
))]
fn encode_i32x4(values: [i32; 4]) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    for (index, value) in values.into_iter().enumerate() {
        bytes[index * 4..(index + 1) * 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn encode_i32x8(values: [i32; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (index, value) in values.into_iter().enumerate() {
        bytes[index * 4..(index + 1) * 4].copy_from_slice(&value.to_le_bytes());
    }
    bytes
}

extern "C" fn replace_in_callback(_address: u64, ctx: *mut HookContext) {
    unsafe {
        #[cfg(target_arch = "aarch64")]
        {
            (*ctx).fpregs.regs.named.v0 = u128::from_le_bytes(encode_i32x4([42, 43, 44, 45]));
        }

        #[cfg(all(target_arch = "x86_64", target_os = "macos"))]
        {
            (*ctx).fpregs.xmm[0] = encode_i32x4([42, 43, 44, 45]);
        }

        #[cfg(all(target_arch = "x86_64", target_os = "linux"))]
        {
            (*ctx)
                .fpregs
                .set_ymm(0, encode_i32x8([42, 43, 44, 45, 46, 47, 48, 49]));
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
        let symbol = libc::dlsym(libc::RTLD_DEFAULT, c"target_vec_add".as_ptr());
        if symbol.is_null() {
            return;
        }

        let function_entry = symbol as u64;
        let _ = inline_hook(function_entry, replace_in_callback);
    }
}

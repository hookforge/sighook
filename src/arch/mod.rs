#[cfg(target_arch = "aarch64")]
pub(crate) mod aarch64;
#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
pub(crate) mod x86_64;

#[cfg(target_arch = "aarch64")]
pub(crate) use aarch64::{encode_b, instruction_width, is_brk, read_u32};

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
pub(crate) use x86_64::{
    encode_absolute_jump, encode_jmp_rel32, instruction_width, int3_opcode, is_int3, read_u8,
};

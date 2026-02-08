pub(crate) const MAX_INSTRUMENTS: usize = 256;

#[cfg(target_arch = "aarch64")]
pub(crate) const BRK_OPCODE: u32 = 0xD420_0000;
#[cfg(target_arch = "aarch64")]
pub(crate) const BRK_MASK: u32 = 0xFFE0_001F;
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) const VM_PROT_COPY: libc::vm_prot_t = 0x10;

#[cfg(target_arch = "aarch64")]
pub(crate) const LDR_X16_LITERAL_8: u32 = 0x5800_0050;
#[cfg(target_arch = "aarch64")]
pub(crate) const BR_X16: u32 = 0xD61F_0200;

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
pub(crate) const INT3_OPCODE: u8 = 0xCC;

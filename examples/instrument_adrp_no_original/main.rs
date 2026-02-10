#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
use sighook::{HookContext, instrument_no_original};

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
const ADRP_MASK: u32 = 0x9F00_0000;
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
const ADRP_OPCODE: u32 = 0x9000_0000;
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
const ADRP_DEST_X10: u32 = 10;

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
static mut ADRP_IMM_PAGES: i64 = 0;

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
#[inline]
fn sign_extend_21(value: u32) -> i64 {
    let raw = (value & 0x1F_FFFF) as i64;
    (raw << (64 - 21)) >> (64 - 21)
}

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
fn decode_adrp(opcode: u32) -> Option<(i64, u32)> {
    if (opcode & ADRP_MASK) != ADRP_OPCODE {
        return None;
    }

    let immlo = (opcode >> 29) & 0x3;
    let immhi = (opcode >> 5) & 0x7_FFFF;
    let imm21 = (immhi << 2) | immlo;
    let imm_pages = sign_extend_21(imm21);
    let rd = opcode & 0x1F;
    Some((imm_pages, rd))
}

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
extern "C" fn emulate_adrp(_address: u64, ctx: *mut HookContext) {
    unsafe {
        let pc_page = ((*ctx).pc & !0xFFF) as i128;
        let target_page = pc_page + ((ADRP_IMM_PAGES as i128) << 12);
        if !(0..=u64::MAX as i128).contains(&target_page) {
            return;
        }

        (*ctx).regs.named.x10 = target_page as u64;
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

        let original = match instrument_no_original(patchpoint as u64, emulate_adrp) {
            Ok(opcode) => opcode,
            Err(_) => return,
        };

        let (imm_pages, rd) = match decode_adrp(original) {
            Some(v) => v,
            None => return,
        };

        if rd != ADRP_DEST_X10 {
            return;
        }

        ADRP_IMM_PAGES = imm_pages;
    }
}

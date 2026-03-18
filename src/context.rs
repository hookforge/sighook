//! Signal-frame to `HookContext` remapping for each supported platform.
//!
//! The trap handler works with a normalized `HookContext` instead of exposing raw
//! `ucontext_t` layouts to callbacks. Each platform section in this file therefore
//! performs the same three-step translation:
//!
//! 1. copy machine state out of the native signal frame,
//! 2. present it through the crate-defined register layout,
//! 3. write the final callback-mutated state back to the native frame.
//!
//! This is also where FP/SIMD state is normalized across Darwin and Linux, including
//! Linux x86_64 AVX high halves and Linux AArch64 FPSIMD extension records.

#[cfg(target_arch = "aarch64")]
use std::ops::{Deref, DerefMut};

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct XRegistersNamed {
    pub x0: u64,
    pub x1: u64,
    pub x2: u64,
    pub x3: u64,
    pub x4: u64,
    pub x5: u64,
    pub x6: u64,
    pub x7: u64,
    pub x8: u64,
    pub x9: u64,
    pub x10: u64,
    pub x11: u64,
    pub x12: u64,
    pub x13: u64,
    pub x14: u64,
    pub x15: u64,
    pub x16: u64,
    pub x17: u64,
    pub x18: u64,
    pub x19: u64,
    pub x20: u64,
    pub x21: u64,
    pub x22: u64,
    pub x23: u64,
    pub x24: u64,
    pub x25: u64,
    pub x26: u64,
    pub x27: u64,
    pub x28: u64,
    pub x29: u64,
    pub x30: u64,
}

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Copy, Clone)]
pub union XRegisters {
    pub x: [u64; 31],
    pub named: XRegistersNamed,
}

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct VRegistersNamed {
    pub v0: u128,
    pub v1: u128,
    pub v2: u128,
    pub v3: u128,
    pub v4: u128,
    pub v5: u128,
    pub v6: u128,
    pub v7: u128,
    pub v8: u128,
    pub v9: u128,
    pub v10: u128,
    pub v11: u128,
    pub v12: u128,
    pub v13: u128,
    pub v14: u128,
    pub v15: u128,
    pub v16: u128,
    pub v17: u128,
    pub v18: u128,
    pub v19: u128,
    pub v20: u128,
    pub v21: u128,
    pub v22: u128,
    pub v23: u128,
    pub v24: u128,
    pub v25: u128,
    pub v26: u128,
    pub v27: u128,
    pub v28: u128,
    pub v29: u128,
    pub v30: u128,
    pub v31: u128,
}

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Copy, Clone)]
pub union VRegisters {
    pub v: [u128; 32],
    pub named: VRegistersNamed,
}

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FpRegisters {
    pub regs: VRegisters,
    pub fpsr: u32,
    pub fpcr: u32,
}

#[cfg(target_arch = "aarch64")]
impl Deref for FpRegisters {
    type Target = VRegisters;

    fn deref(&self) -> &Self::Target {
        &self.regs
    }
}

#[cfg(target_arch = "aarch64")]
impl DerefMut for FpRegisters {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.regs
    }
}

#[cfg(target_arch = "aarch64")]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct HookContext {
    pub regs: XRegisters,
    pub sp: u64,
    pub pc: u64,
    pub cpsr: u32,
    pub pad: u32,
    pub fpregs: FpRegisters,
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FpRegisters {
    pub fcw: u16,
    pub fsw: u16,
    pub ftw: u16,
    pub fop: u16,
    pub mxcsr: u32,
    pub mxcsr_mask: u32,
    pub st: [[u8; 16]; 8],
    pub xmm: [[u8; 16]; 16],
    pub ymm_hi: [[u8; 16]; 16],
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
impl FpRegisters {
    pub fn ymm(&self, index: usize) -> [u8; 32] {
        let mut value = [0u8; 32];
        value[..16].copy_from_slice(&self.xmm[index]);
        value[16..].copy_from_slice(&self.ymm_hi[index]);
        value
    }

    pub fn set_ymm(&mut self, index: usize, value: [u8; 32]) {
        self.xmm[index].copy_from_slice(&value[..16]);
        self.ymm_hi[index].copy_from_slice(&value[16..]);
    }
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct HookContext {
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rsp: u64,
    pub rip: u64,
    pub eflags: u64,
    pub fpregs: FpRegisters,
}

pub type InstrumentCallback = extern "C" fn(address: u64, ctx: *mut HookContext);

#[cfg(target_arch = "aarch64")]
fn zeroed_fpregs() -> FpRegisters {
    unsafe { std::mem::zeroed() }
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
fn zeroed_fpregs() -> FpRegisters {
    unsafe { std::mem::zeroed() }
}

#[cfg(all(any(target_os = "macos", target_os = "ios"), target_arch = "aarch64"))]
pub unsafe fn remap_ctx(uc: *mut libc::ucontext_t) -> *mut HookContext {
    if uc.is_null() {
        return std::ptr::null_mut();
    }

    let mcontext = unsafe { (*uc).uc_mcontext };
    if mcontext.is_null() {
        return std::ptr::null_mut();
    }

    let ss = unsafe { &(*mcontext).__ss };
    let ns = unsafe { &(*mcontext).__ns };

    // Darwin stores x0..x28 in `__x`, while x29/x30 live in dedicated frame-pointer
    // and link-register fields. Normalize that split layout back into one flat array.
    let mut regs = [0u64; 31];
    regs[..29].copy_from_slice(&ss.__x);
    regs[29] = ss.__fp;
    regs[30] = ss.__lr;

    // Darwin's NEON/SIMD block is already contiguous, so we can copy the 32 vector
    // registers directly into `HookContext`.
    let mut fpregs = zeroed_fpregs();
    unsafe {
        std::ptr::copy_nonoverlapping(
            ns.__v.as_ptr().cast::<u128>(),
            fpregs.regs.v.as_mut_ptr(),
            32,
        );
    }
    fpregs.fpsr = ns.__fpsr;
    fpregs.fpcr = ns.__fpcr;

    let ctx = HookContext {
        regs: XRegisters { x: regs },
        sp: ss.__sp,
        pc: ss.__pc,
        cpsr: ss.__cpsr,
        pad: ss.__pad,
        fpregs,
    };

    Box::into_raw(Box::new(ctx))
}

#[cfg(all(any(target_os = "macos", target_os = "ios"), target_arch = "aarch64"))]
pub unsafe fn write_back_ctx(uc: *mut libc::ucontext_t, ctx: *mut HookContext) {
    if uc.is_null() || ctx.is_null() {
        return;
    }

    let mcontext = unsafe { (*uc).uc_mcontext };
    if mcontext.is_null() {
        return;
    }

    let ss = unsafe { &mut (*mcontext).__ss };
    let ns = unsafe { &mut (*mcontext).__ns };
    let ctx = unsafe { &*ctx };
    let regs = unsafe { ctx.regs.x };

    ss.__x.copy_from_slice(&regs[..29]);
    ss.__fp = regs[29];
    ss.__lr = regs[30];
    ss.__sp = ctx.sp;
    ss.__pc = ctx.pc;
    ss.__cpsr = ctx.cpsr;
    ss.__pad = ctx.pad;

    unsafe {
        std::ptr::copy_nonoverlapping(
            ctx.fpregs.regs.v.as_ptr(),
            ns.__v.as_mut_ptr().cast::<u128>(),
            32,
        );
    }
    ns.__fpsr = ctx.fpregs.fpsr;
    ns.__fpcr = ctx.fpregs.fpcr;
}

#[cfg(all(any(target_os = "macos", target_os = "ios"), target_arch = "aarch64"))]
pub unsafe fn free_ctx(ctx: *mut HookContext) {
    if !ctx.is_null() {
        let _ = unsafe { Box::from_raw(ctx) };
    }
}

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
// Linux AArch64 stores optional context records, including FPSIMD state, inside the
// `reserved` tail of the machine context. The record stream is self-describing via
// `(magic, size)` headers.
const FPSIMD_MAGIC: u32 = 0x4650_8001;

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
#[repr(C)]
#[derive(Copy, Clone)]
struct LinuxAarch64Reserved {
    bytes: [u8; 4096],
}

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
#[repr(C, align(16))]
#[derive(Copy, Clone)]
struct LinuxAarch64AlignedReserved(LinuxAarch64Reserved);

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
#[repr(C)]
#[derive(Copy, Clone)]
struct LinuxAarch64MContext {
    fault_address: u64,
    regs: [u64; 31],
    sp: u64,
    pc: u64,
    pstate: u64,
    reserved: LinuxAarch64AlignedReserved,
}

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
#[repr(C)]
#[derive(Copy, Clone)]
struct LinuxAarch64CtxHeader {
    magic: u32,
    size: u32,
}

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
#[repr(C, align(16))]
#[derive(Copy, Clone)]
struct LinuxAarch64FpsimdContext {
    head: LinuxAarch64CtxHeader,
    fpsr: u32,
    fpcr: u32,
    vregs: [u128; 32],
}

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
unsafe fn linux_aarch64_mcontext(uc: *mut libc::ucontext_t) -> *mut LinuxAarch64MContext {
    unsafe { std::ptr::addr_of_mut!((*uc).uc_mcontext).cast::<LinuxAarch64MContext>() }
}

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
unsafe fn linux_aarch64_fpsimd_context(
    mcontext: *mut LinuxAarch64MContext,
) -> Option<*mut LinuxAarch64FpsimdContext> {
    let reserved = unsafe { &mut (*mcontext).reserved.0.bytes };
    let base = reserved.as_mut_ptr();
    let len = reserved.len();
    let mut offset = 0usize;

    // Walk the variable-length extension-record stream until we either find the
    // FPSIMD block or encounter a terminating / malformed header.
    while offset + std::mem::size_of::<LinuxAarch64CtxHeader>() <= len {
        let head = unsafe { &*base.add(offset).cast::<LinuxAarch64CtxHeader>() };
        if head.magic == 0 || head.size == 0 {
            break;
        }

        let size = head.size as usize;
        if size < std::mem::size_of::<LinuxAarch64CtxHeader>() || offset + size > len {
            break;
        }

        if head.magic == FPSIMD_MAGIC && size >= std::mem::size_of::<LinuxAarch64FpsimdContext>() {
            return Some(unsafe { base.add(offset).cast::<LinuxAarch64FpsimdContext>() });
        }

        offset += size;
    }

    None
}

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
pub unsafe fn remap_ctx(uc: *mut libc::ucontext_t) -> *mut HookContext {
    let mcontext = unsafe { linux_aarch64_mcontext(uc) };
    let mut fpregs = zeroed_fpregs();

    // The kernel may omit FPSIMD state in some frames. We still produce a valid
    // `HookContext`; FP/SIMD state simply remains zero-initialized in that case.
    if let Some(fpsimd) = unsafe { linux_aarch64_fpsimd_context(mcontext) } {
        let fpsimd = unsafe { &*fpsimd };
        fpregs.regs.v = fpsimd.vregs;
        fpregs.fpsr = fpsimd.fpsr;
        fpregs.fpcr = fpsimd.fpcr;
    }

    let ctx = HookContext {
        regs: XRegisters {
            x: unsafe { (*mcontext).regs },
        },
        sp: unsafe { (*mcontext).sp },
        pc: unsafe { (*mcontext).pc },
        cpsr: unsafe { (*mcontext).pstate as u32 },
        pad: 0,
        fpregs,
    };

    Box::into_raw(Box::new(ctx))
}

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
pub unsafe fn write_back_ctx(uc: *mut libc::ucontext_t, ctx: *mut HookContext) {
    if ctx.is_null() {
        return;
    }

    let mcontext = unsafe { linux_aarch64_mcontext(uc) };
    let ctx = unsafe { &*ctx };

    unsafe {
        (*mcontext).regs = ctx.regs.x;
        (*mcontext).sp = ctx.sp;
        (*mcontext).pc = ctx.pc;
        (*mcontext).pstate = ctx.cpsr as u64;
    }

    if let Some(fpsimd) = unsafe { linux_aarch64_fpsimd_context(mcontext) } {
        let fpsimd = unsafe { &mut *fpsimd };
        fpsimd.vregs = ctx.fpregs.regs.v;
        fpsimd.fpsr = ctx.fpregs.fpsr;
        fpsimd.fpcr = ctx.fpregs.fpcr;
    }
}

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
pub unsafe fn free_ctx(ctx: *mut HookContext) {
    if !ctx.is_null() {
        let _ = unsafe { Box::from_raw(ctx) };
    }
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
// Darwin's public float-state types are awkward to use directly, so we mirror the
// relevant kernel layout here and normalize it into `FpRegisters`.
#[repr(C)]
#[derive(Copy, Clone)]
struct DarwinX86FloatState64 {
    fpu_reserved: [libc::c_int; 2],
    fpu_fcw: libc::c_short,
    fpu_fsw: libc::c_short,
    fpu_ftw: u8,
    fpu_rsrv1: u8,
    fpu_fop: u16,
    fpu_ip: u32,
    fpu_cs: u16,
    fpu_rsrv2: u16,
    fpu_dp: u32,
    fpu_ds: u16,
    fpu_rsrv3: u16,
    fpu_mxcsr: u32,
    fpu_mxcsrmask: u32,
    stmm: [libc::__darwin_mmst_reg; 8],
    xmm: [libc::__darwin_xmm_reg; 16],
    fpu_rsrv4: [u32; 24],
    fpu_reserved1: libc::c_int,
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
fn copy_from_bytes<const N: usize>(dst: &mut [u8; N], src: *const u8) {
    unsafe {
        std::ptr::copy_nonoverlapping(src, dst.as_mut_ptr(), N);
    }
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
fn copy_to_bytes<const N: usize>(dst: *mut u8, src: &[u8; N]) {
    unsafe {
        std::ptr::copy_nonoverlapping(src.as_ptr(), dst, N);
    }
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
fn read_darwin_x86_fpregs(fs: *const DarwinX86FloatState64) -> FpRegisters {
    let fs = unsafe { &*fs };
    let mut fpregs = zeroed_fpregs();

    fpregs.fcw = fs.fpu_fcw as u16;
    fpregs.fsw = fs.fpu_fsw as u16;
    fpregs.ftw = fs.fpu_ftw as u16;
    fpregs.fop = fs.fpu_fop;
    fpregs.mxcsr = fs.fpu_mxcsr;
    fpregs.mxcsr_mask = fs.fpu_mxcsrmask;

    // x87 registers are 80-bit values. We preserve those 10 bytes and explicitly
    // clear the remaining tail bytes in our 16-byte storage slots.
    for (idx, stmm) in fs.stmm.iter().enumerate() {
        copy_from_bytes(&mut fpregs.st[idx], stmm.__mmst_reg.as_ptr().cast::<u8>());
        copy_to_bytes(fpregs.st[idx][10..].as_mut_ptr(), &[0u8; 6]);
    }

    for (idx, xmm) in fs.xmm.iter().enumerate() {
        copy_from_bytes(&mut fpregs.xmm[idx], xmm.__xmm_reg.as_ptr().cast::<u8>());
    }

    fpregs
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
fn write_darwin_x86_fpregs(fs: *mut DarwinX86FloatState64, fpregs: &FpRegisters) {
    let fs = unsafe { &mut *fs };

    fs.fpu_fcw = fpregs.fcw as libc::c_short;
    fs.fpu_fsw = fpregs.fsw as libc::c_short;
    fs.fpu_ftw = fpregs.ftw as u8;
    fs.fpu_fop = fpregs.fop;
    fs.fpu_mxcsr = fpregs.mxcsr;
    fs.fpu_mxcsrmask = fpregs.mxcsr_mask;

    for (idx, stmm) in fs.stmm.iter_mut().enumerate() {
        let mut value = [0u8; 10];
        value.copy_from_slice(&fpregs.st[idx][..10]);
        copy_to_bytes(stmm.__mmst_reg.as_mut_ptr().cast::<u8>(), &value);
        copy_to_bytes(stmm.__mmst_rsrv.as_mut_ptr().cast::<u8>(), &[0u8; 6]);
    }

    for (idx, xmm) in fs.xmm.iter_mut().enumerate() {
        copy_to_bytes(xmm.__xmm_reg.as_mut_ptr().cast::<u8>(), &fpregs.xmm[idx]);
    }
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub unsafe fn remap_ctx(uc: *mut libc::ucontext_t) -> *mut HookContext {
    let mcontext = unsafe { (*uc).uc_mcontext };
    if mcontext.is_null() {
        return std::ptr::null_mut();
    }

    let ss = unsafe { &(*mcontext).__ss };
    let fs = unsafe { std::ptr::addr_of!((*mcontext).__fs).cast::<DarwinX86FloatState64>() };

    let ctx = HookContext {
        r8: ss.__r8,
        r9: ss.__r9,
        r10: ss.__r10,
        r11: ss.__r11,
        r12: ss.__r12,
        r13: ss.__r13,
        r14: ss.__r14,
        r15: ss.__r15,
        rdi: ss.__rdi,
        rsi: ss.__rsi,
        rbp: ss.__rbp,
        rbx: ss.__rbx,
        rdx: ss.__rdx,
        rax: ss.__rax,
        rcx: ss.__rcx,
        rsp: ss.__rsp,
        rip: ss.__rip,
        eflags: ss.__rflags,
        fpregs: read_darwin_x86_fpregs(fs),
    };

    Box::into_raw(Box::new(ctx))
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub unsafe fn write_back_ctx(uc: *mut libc::ucontext_t, ctx: *mut HookContext) {
    let mcontext = unsafe { (*uc).uc_mcontext };
    if mcontext.is_null() || ctx.is_null() {
        return;
    }

    let ss = unsafe { &mut (*mcontext).__ss };
    let fs = unsafe { std::ptr::addr_of_mut!((*mcontext).__fs).cast::<DarwinX86FloatState64>() };
    let ctx = unsafe { &*ctx };

    ss.__r8 = ctx.r8;
    ss.__r9 = ctx.r9;
    ss.__r10 = ctx.r10;
    ss.__r11 = ctx.r11;
    ss.__r12 = ctx.r12;
    ss.__r13 = ctx.r13;
    ss.__r14 = ctx.r14;
    ss.__r15 = ctx.r15;
    ss.__rdi = ctx.rdi;
    ss.__rsi = ctx.rsi;
    ss.__rbp = ctx.rbp;
    ss.__rbx = ctx.rbx;
    ss.__rdx = ctx.rdx;
    ss.__rax = ctx.rax;
    ss.__rcx = ctx.rcx;
    ss.__rsp = ctx.rsp;
    ss.__rip = ctx.rip;
    ss.__rflags = ctx.eflags;

    write_darwin_x86_fpregs(fs, &ctx.fpregs);
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
// XSAVE metadata used to discover whether a signal frame carries AVX YMM high halves.
const FP_XSTATE_MAGIC1: u32 = 0x4650_5853;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const FP_XSTATE_MAGIC2: u32 = 0x4650_5845;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const XFEATURE_MASK_YMM: u64 = 1 << 2;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[repr(C)]
#[derive(Copy, Clone)]
struct LinuxX86FpxReg {
    bytes: [u8; 16],
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[repr(C)]
#[derive(Copy, Clone)]
struct LinuxX86XmmReg {
    bytes: [u8; 16],
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[repr(C)]
#[derive(Copy, Clone)]
struct LinuxX86SwReserved {
    magic1: u32,
    extended_size: u32,
    xstate_bv: u64,
    xstate_size: u32,
    padding: [u32; 7],
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[repr(C)]
#[derive(Copy, Clone)]
struct LinuxX86FpState {
    fcw: u16,
    fsw: u16,
    ftw: u16,
    fop: u16,
    rip: u64,
    rdp: u64,
    mxcsr: u32,
    mxcsr_mask: u32,
    st: [LinuxX86FpxReg; 8],
    xmm: [LinuxX86XmmReg; 16],
    reserved: [u8; 48],
    sw_reserved: LinuxX86SwReserved,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[repr(C)]
#[derive(Copy, Clone)]
struct LinuxX86XSaveHeader {
    xfeatures: u64,
    xcomp_bv: u64,
    reserved: [u64; 6],
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[repr(C)]
#[derive(Copy, Clone)]
struct LinuxX86YmmhState {
    ymmh_space: [[u8; 16]; 16],
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[repr(C)]
#[derive(Copy, Clone)]
struct LinuxX86MContext {
    gregs: [libc::greg_t; 23],
    fpregs: *mut LinuxX86FpState,
    reserved: [u64; 8],
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
unsafe fn linux_x86_mcontext(uc: *mut libc::ucontext_t) -> *mut LinuxX86MContext {
    unsafe { std::ptr::addr_of_mut!((*uc).uc_mcontext).cast::<LinuxX86MContext>() }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
unsafe fn linux_x86_ymmh_state(fpstate: *mut LinuxX86FpState) -> Option<*mut LinuxX86YmmhState> {
    if fpstate.is_null() {
        return None;
    }

    let sw = unsafe { &(*fpstate).sw_reserved };
    if sw.magic1 != FP_XSTATE_MAGIC1 || (sw.xstate_bv & XFEATURE_MASK_YMM) == 0 {
        return None;
    }

    // Validate both the XSAVE payload size and the enclosing extended buffer size
    // before trusting any embedded offsets.
    let required_xstate = std::mem::size_of::<LinuxX86FpState>()
        + std::mem::size_of::<LinuxX86XSaveHeader>()
        + std::mem::size_of::<LinuxX86YmmhState>();
    let required_extended = required_xstate + std::mem::size_of::<u32>();
    if sw.xstate_size < required_xstate as u32 || sw.extended_size < required_extended as u32 {
        return None;
    }

    let base = fpstate.cast::<u8>();
    let magic2_ptr =
        unsafe { base.add(sw.extended_size as usize - std::mem::size_of::<u32>()) }.cast::<u32>();
    if unsafe { *magic2_ptr } != FP_XSTATE_MAGIC2 {
        return None;
    }

    Some(unsafe {
        base.add(
            std::mem::size_of::<LinuxX86FpState>() + std::mem::size_of::<LinuxX86XSaveHeader>(),
        )
        .cast::<LinuxX86YmmhState>()
    })
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn read_linux_x86_fpregs(fpstate: *const LinuxX86FpState) -> FpRegisters {
    if fpstate.is_null() {
        return zeroed_fpregs();
    }

    let fpstate = unsafe { &*fpstate };
    let mut fpregs = zeroed_fpregs();

    fpregs.fcw = fpstate.fcw;
    fpregs.fsw = fpstate.fsw;
    fpregs.ftw = fpstate.ftw;
    fpregs.fop = fpstate.fop;
    fpregs.mxcsr = fpstate.mxcsr;
    fpregs.mxcsr_mask = fpstate.mxcsr_mask;

    for (idx, st) in fpstate.st.iter().enumerate() {
        fpregs.st[idx] = st.bytes;
    }

    for (idx, xmm) in fpstate.xmm.iter().enumerate() {
        fpregs.xmm[idx] = xmm.bytes;
    }

    // If the frame exposes AVX state, pull in the upper 128 bits of each YMM
    // register; otherwise the zero-initialized default correctly represents SSE-only
    // state.
    if let Some(ymmh) = unsafe { linux_x86_ymmh_state(fpstate as *const _ as *mut _) } {
        let ymmh = unsafe { &*ymmh };
        fpregs.ymm_hi = ymmh.ymmh_space;
    }

    fpregs
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn write_linux_x86_fpregs(fpstate: *mut LinuxX86FpState, fpregs: &FpRegisters) {
    if fpstate.is_null() {
        return;
    }

    let fpstate = unsafe { &mut *fpstate };

    fpstate.fcw = fpregs.fcw;
    fpstate.fsw = fpregs.fsw;
    fpstate.ftw = fpregs.ftw;
    fpstate.fop = fpregs.fop;
    fpstate.mxcsr = fpregs.mxcsr;
    fpstate.mxcsr_mask = fpregs.mxcsr_mask;

    for (idx, st) in fpstate.st.iter_mut().enumerate() {
        st.bytes = fpregs.st[idx];
    }

    for (idx, xmm) in fpstate.xmm.iter_mut().enumerate() {
        xmm.bytes = fpregs.xmm[idx];
    }

    if let Some(ymmh) = unsafe { linux_x86_ymmh_state(fpstate) } {
        unsafe {
            (*ymmh).ymmh_space = fpregs.ymm_hi;
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub unsafe fn remap_ctx(uc: *mut libc::ucontext_t) -> *mut HookContext {
    let mcontext = unsafe { linux_x86_mcontext(uc) };
    let gregs = unsafe { &(*mcontext).gregs };

    let ctx = HookContext {
        r8: gregs[libc::REG_R8 as usize] as u64,
        r9: gregs[libc::REG_R9 as usize] as u64,
        r10: gregs[libc::REG_R10 as usize] as u64,
        r11: gregs[libc::REG_R11 as usize] as u64,
        r12: gregs[libc::REG_R12 as usize] as u64,
        r13: gregs[libc::REG_R13 as usize] as u64,
        r14: gregs[libc::REG_R14 as usize] as u64,
        r15: gregs[libc::REG_R15 as usize] as u64,
        rdi: gregs[libc::REG_RDI as usize] as u64,
        rsi: gregs[libc::REG_RSI as usize] as u64,
        rbp: gregs[libc::REG_RBP as usize] as u64,
        rbx: gregs[libc::REG_RBX as usize] as u64,
        rdx: gregs[libc::REG_RDX as usize] as u64,
        rax: gregs[libc::REG_RAX as usize] as u64,
        rcx: gregs[libc::REG_RCX as usize] as u64,
        rsp: gregs[libc::REG_RSP as usize] as u64,
        rip: gregs[libc::REG_RIP as usize] as u64,
        eflags: gregs[libc::REG_EFL as usize] as u64,
        fpregs: read_linux_x86_fpregs(unsafe { (*mcontext).fpregs }),
    };

    Box::into_raw(Box::new(ctx))
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub unsafe fn write_back_ctx(uc: *mut libc::ucontext_t, ctx: *mut HookContext) {
    if ctx.is_null() {
        return;
    }

    let mcontext = unsafe { linux_x86_mcontext(uc) };
    let gregs = unsafe { &mut (*mcontext).gregs };
    let ctx = unsafe { &*ctx };

    gregs[libc::REG_R8 as usize] = ctx.r8 as libc::greg_t;
    gregs[libc::REG_R9 as usize] = ctx.r9 as libc::greg_t;
    gregs[libc::REG_R10 as usize] = ctx.r10 as libc::greg_t;
    gregs[libc::REG_R11 as usize] = ctx.r11 as libc::greg_t;
    gregs[libc::REG_R12 as usize] = ctx.r12 as libc::greg_t;
    gregs[libc::REG_R13 as usize] = ctx.r13 as libc::greg_t;
    gregs[libc::REG_R14 as usize] = ctx.r14 as libc::greg_t;
    gregs[libc::REG_R15 as usize] = ctx.r15 as libc::greg_t;
    gregs[libc::REG_RDI as usize] = ctx.rdi as libc::greg_t;
    gregs[libc::REG_RSI as usize] = ctx.rsi as libc::greg_t;
    gregs[libc::REG_RBP as usize] = ctx.rbp as libc::greg_t;
    gregs[libc::REG_RBX as usize] = ctx.rbx as libc::greg_t;
    gregs[libc::REG_RDX as usize] = ctx.rdx as libc::greg_t;
    gregs[libc::REG_RAX as usize] = ctx.rax as libc::greg_t;
    gregs[libc::REG_RCX as usize] = ctx.rcx as libc::greg_t;
    gregs[libc::REG_RSP as usize] = ctx.rsp as libc::greg_t;
    gregs[libc::REG_RIP as usize] = ctx.rip as libc::greg_t;
    gregs[libc::REG_EFL as usize] = ctx.eflags as libc::greg_t;

    write_linux_x86_fpregs(unsafe { (*mcontext).fpregs }, &ctx.fpregs);
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
pub unsafe fn free_ctx(ctx: *mut HookContext) {
    if !ctx.is_null() {
        let _ = unsafe { Box::from_raw(ctx) };
    }
}

#[cfg(all(test, target_arch = "aarch64"))]
mod tests {
    use super::{FpRegisters, VRegisters};

    #[test]
    fn aarch64_fpreg_named_and_array_views_alias() {
        let mut fpregs = FpRegisters {
            regs: VRegisters { v: [0; 32] },
            fpsr: 0,
            fpcr: 0,
        };

        unsafe {
            fpregs.named.v0 = 0x11;
            fpregs.named.v31 = 0x22;
            assert_eq!(fpregs.v[0], 0x11);
            assert_eq!(fpregs.v[31], 0x22);

            fpregs.v[1] = 0x33;
            assert_eq!(fpregs.named.v1, 0x33);
        }
    }
}

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
pub struct HookContext {
    pub regs: XRegisters,
    pub sp: u64,
    pub pc: u64,
    pub cpsr: u32,
    pub pad: u32,
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
}

pub type InstrumentCallback = extern "C" fn(address: u64, ctx: *mut HookContext);

#[cfg(all(any(target_os = "macos", target_os = "ios"), target_arch = "aarch64"))]
pub unsafe fn remap_ctx(thread_state: *mut libc::__darwin_arm_thread_state64) -> *mut HookContext {
    thread_state.cast::<HookContext>()
}

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
pub unsafe fn remap_ctx(_uc: *mut libc::ucontext_t) -> *mut HookContext {
    let mcontext = unsafe { &mut (*_uc).uc_mcontext };
    let mut regs = [0u64; 31];

    unsafe {
        std::ptr::copy_nonoverlapping(mcontext.regs.as_ptr().cast::<u64>(), regs.as_mut_ptr(), 31);
    }

    let ctx = HookContext {
        regs: XRegisters { x: regs },
        sp: mcontext.sp,
        pc: mcontext.pc,
        cpsr: mcontext.pstate as u32,
        pad: 0,
    };

    Box::into_raw(Box::new(ctx))
}

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
pub unsafe fn write_back_ctx(_uc: *mut libc::ucontext_t, ctx: *mut HookContext) {
    let mcontext = unsafe { &mut (*_uc).uc_mcontext };
    let ctx = unsafe { &*ctx };

    let regs = unsafe { ctx.regs.x };
    unsafe {
        std::ptr::copy_nonoverlapping(regs.as_ptr(), mcontext.regs.as_mut_ptr().cast::<u64>(), 31);
    }

    mcontext.sp = ctx.sp as libc::c_ulonglong;
    mcontext.pc = ctx.pc as libc::c_ulonglong;
    mcontext.pstate = ctx.cpsr as libc::c_ulonglong;
}

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
pub unsafe fn free_ctx(ctx: *mut HookContext) {
    let _ = unsafe { Box::from_raw(ctx) };
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub unsafe fn remap_ctx(_uc: *mut libc::ucontext_t) -> *mut HookContext {
    let mcontext = unsafe { (*_uc).uc_mcontext };
    if mcontext.is_null() {
        return std::ptr::null_mut();
    }

    let ss = unsafe { &(*mcontext).__ss };

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
    };

    Box::into_raw(Box::new(ctx))
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub unsafe fn remap_ctx(_uc: *mut libc::ucontext_t) -> *mut HookContext {
    let gregs = unsafe { &(*_uc).uc_mcontext.gregs };

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
    };

    Box::into_raw(Box::new(ctx))
}

#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
pub unsafe fn write_back_ctx(_uc: *mut libc::ucontext_t, ctx: *mut HookContext) {
    let mcontext = unsafe { (*_uc).uc_mcontext };
    if mcontext.is_null() {
        return;
    }

    let ss = unsafe { &mut (*mcontext).__ss };
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
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub unsafe fn write_back_ctx(_uc: *mut libc::ucontext_t, ctx: *mut HookContext) {
    let gregs = unsafe { &mut (*_uc).uc_mcontext.gregs };
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
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
pub unsafe fn free_ctx(ctx: *mut HookContext) {
    let _ = unsafe { Box::from_raw(ctx) };
}

use crate::context::InstrumentCallback;
use crate::error::SigHookError;
use crate::memory::last_errno;
use crate::state;
use libc::{c_int, c_void};
use std::mem::zeroed;
use std::ptr::null_mut;

#[cfg(all(any(target_os = "macos", target_os = "ios"), target_arch = "aarch64"))]
extern "C" fn trap_handler(_sig: c_int, info: *mut libc::siginfo_t, uctx: *mut c_void) {
    use crate::context::remap_ctx;
    use crate::memory::{is_brk, read_u32};

    if info.is_null() || uctx.is_null() {
        unsafe { libc::_exit(1) }
    }

    let uc = unsafe { &mut *(uctx as *mut libc::ucontext_t) };
    if uc.uc_mcontext.is_null() {
        unsafe { libc::_exit(1) }
    }

    let raw_ss = unsafe { &mut (*uc.uc_mcontext).__ss };
    let ctx_ptr = unsafe { remap_ctx(raw_ss as *mut libc::__darwin_arm_thread_state64) };
    let ctx = unsafe { &mut *ctx_ptr };
    let trap_address = ctx.pc;

    let opcode = read_u32(trap_address);
    if !is_brk(opcode) {
        unsafe { libc::_exit(1) }
    }

    handle_trap_aarch64(trap_address, ctx_ptr, |ctx_ptr, next_pc, trampoline_pc| {
        let ctx = unsafe { &mut *ctx_ptr };
        if trampoline_pc != 0 {
            ctx.pc = trampoline_pc;
        } else {
            ctx.pc = next_pc;
        }
    });
}

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
extern "C" fn trap_handler(_sig: c_int, info: *mut libc::siginfo_t, uctx: *mut c_void) {
    use crate::context::{free_ctx, remap_ctx, write_back_ctx};
    use crate::memory::{is_brk, read_u32};

    if info.is_null() || uctx.is_null() {
        return;
    }

    let uc_ptr = uctx as *mut libc::ucontext_t;
    let ctx_ptr = unsafe { remap_ctx(uc_ptr) };
    let ctx = unsafe { &mut *ctx_ptr };
    let trap_address = ctx.pc;

    let opcode = read_u32(trap_address);
    if !is_brk(opcode) {
        unsafe {
            free_ctx(ctx_ptr);
        }
        return;
    }

    handle_trap_aarch64(trap_address, ctx_ptr, |ctx_ptr, next_pc, trampoline_pc| {
        let ctx = unsafe { &mut *ctx_ptr };
        if trampoline_pc != 0 {
            ctx.pc = trampoline_pc;
        } else {
            ctx.pc = next_pc;
        }
    });

    unsafe {
        write_back_ctx(uc_ptr, ctx_ptr);
        free_ctx(ctx_ptr);
    }
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
extern "C" fn trap_handler(_sig: c_int, info: *mut libc::siginfo_t, uctx: *mut c_void) {
    use crate::context::{free_ctx, remap_ctx, write_back_ctx};
    use crate::memory::{is_int3, read_u8};

    if info.is_null() || uctx.is_null() {
        return;
    }

    let uc_ptr = uctx as *mut libc::ucontext_t;
    let ctx_ptr = unsafe { remap_ctx(uc_ptr) };
    let ctx = unsafe { &mut *ctx_ptr };

    if ctx.rip == 0 {
        unsafe {
            free_ctx(ctx_ptr);
        }
        return;
    }

    let trap_address = ctx.rip.wrapping_sub(1);
    let opcode = read_u8(trap_address);
    if !is_int3(opcode) {
        unsafe {
            free_ctx(ctx_ptr);
        }
        return;
    }

    handle_trap_x86_64(trap_address, ctx_ptr, |ctx_ptr, next_pc, trampoline_pc| {
        let ctx = unsafe { &mut *ctx_ptr };
        if trampoline_pc != 0 {
            ctx.rip = trampoline_pc;
        } else {
            ctx.rip = next_pc;
        }
    });

    unsafe {
        write_back_ctx(uc_ptr, ctx_ptr);
        free_ctx(ctx_ptr);
    }
}

#[cfg(target_arch = "aarch64")]
fn handle_trap_aarch64(
    address: u64,
    ctx_ptr: *mut crate::context::HookContext,
    set_pc: impl FnOnce(*mut crate::context::HookContext, u64, u64),
) {
    let slot = unsafe { state::slot_by_address(address) };
    let slot = match slot {
        Some(slot) => slot,
        None => return,
    };

    let callback: InstrumentCallback = match slot.callback {
        Some(cb) => cb,
        None => return,
    };

    let original_pc = unsafe { (*ctx_ptr).pc };
    callback(address, ctx_ptr);

    let current_pc = unsafe { (*ctx_ptr).pc };
    if current_pc != original_pc {
        return;
    }

    let next_pc = address.wrapping_add(slot.step_len as u64);
    let trampoline_pc = if slot.execute_original {
        slot.trampoline_pc
    } else {
        0
    };
    set_pc(ctx_ptr, next_pc, trampoline_pc);
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
fn handle_trap_x86_64(
    address: u64,
    ctx_ptr: *mut crate::context::HookContext,
    set_pc: impl FnOnce(*mut crate::context::HookContext, u64, u64),
) {
    let slot = unsafe { state::slot_by_address(address) };
    let slot = match slot {
        Some(slot) => slot,
        None => return,
    };

    let callback: InstrumentCallback = match slot.callback {
        Some(cb) => cb,
        None => return,
    };

    let original_pc = unsafe { (*ctx_ptr).rip };
    callback(address, ctx_ptr);

    let current_pc = unsafe { (*ctx_ptr).rip };
    if current_pc != original_pc {
        return;
    }

    let next_pc = address.wrapping_add(slot.step_len as u64);
    let trampoline_pc = if slot.execute_original {
        slot.trampoline_pc
    } else {
        0
    };
    set_pc(ctx_ptr, next_pc, trampoline_pc);
}

fn install_signal(signum: c_int) -> Result<(), SigHookError> {
    unsafe {
        let mut act: libc::sigaction = zeroed();
        act.sa_flags = libc::SA_SIGINFO;
        act.sa_sigaction = trap_handler as *const () as usize;

        if libc::sigemptyset(&mut act.sa_mask) != 0 {
            return Err(SigHookError::SigEmptySetFailed {
                signum,
                errno: last_errno(),
            });
        }

        if libc::sigaction(signum, &act, null_mut()) != 0 {
            return Err(SigHookError::SigActionFailed {
                signum,
                errno: last_errno(),
            });
        }
    }

    Ok(())
}

pub(crate) unsafe fn ensure_handlers_installed() -> Result<(), SigHookError> {
    if unsafe { state::HANDLERS_INSTALLED } {
        return Ok(());
    }

    install_signal(libc::SIGTRAP)?;
    install_signal(libc::SIGILL)?;

    unsafe {
        state::HANDLERS_INSTALLED = true;
    }
    Ok(())
}

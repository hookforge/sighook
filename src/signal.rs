use crate::context::InstrumentCallback;
use crate::error::SigHookError;
use crate::memory::last_errno;
use crate::state;
use core::mem::MaybeUninit;
use libc::{c_int, c_void};
use std::mem::zeroed;
use std::ptr::null_mut;

type SigInfoHandler = extern "C" fn(c_int, *mut libc::siginfo_t, *mut c_void);
type SigHandler = extern "C" fn(c_int);

static mut PREV_SIGTRAP_ACTION: MaybeUninit<libc::sigaction> = MaybeUninit::uninit();
static mut PREV_SIGTRAP_SET: bool = false;
static mut PREV_SIGILL_ACTION: MaybeUninit<libc::sigaction> = MaybeUninit::uninit();
static mut PREV_SIGILL_SET: bool = false;

#[inline]
fn current_handler_raw() -> libc::sighandler_t {
    trap_handler as *const () as libc::sighandler_t
}

unsafe fn save_previous_action(signum: c_int, previous_action: &libc::sigaction) {
    match signum {
        libc::SIGTRAP => unsafe {
            std::ptr::copy_nonoverlapping(
                previous_action,
                std::ptr::addr_of_mut!(PREV_SIGTRAP_ACTION).cast::<libc::sigaction>(),
                1,
            );
            PREV_SIGTRAP_SET = true;
        },
        libc::SIGILL => unsafe {
            std::ptr::copy_nonoverlapping(
                previous_action,
                std::ptr::addr_of_mut!(PREV_SIGILL_ACTION).cast::<libc::sigaction>(),
                1,
            );
            PREV_SIGILL_SET = true;
        },
        _ => {}
    }
}

unsafe fn previous_action(signum: c_int) -> Option<libc::sigaction> {
    match signum {
        libc::SIGTRAP => {
            if unsafe { PREV_SIGTRAP_SET } {
                Some(unsafe {
                    std::ptr::read(
                        std::ptr::addr_of!(PREV_SIGTRAP_ACTION).cast::<libc::sigaction>(),
                    )
                })
            } else {
                None
            }
        }
        libc::SIGILL => {
            if unsafe { PREV_SIGILL_SET } {
                Some(unsafe {
                    std::ptr::read(std::ptr::addr_of!(PREV_SIGILL_ACTION).cast::<libc::sigaction>())
                })
            } else {
                None
            }
        }
        _ => None,
    }
}

unsafe fn raise_with_default(signum: c_int) {
    let mut default_action: libc::sigaction = unsafe { zeroed() };
    default_action.sa_flags = 0;
    default_action.sa_sigaction = libc::SIG_DFL;

    unsafe {
        let _ = libc::sigemptyset(&mut default_action.sa_mask);
        let _ = libc::sigaction(signum, &default_action, null_mut());
        let _ = libc::raise(signum);
    }
}

unsafe fn chain_previous(signum: c_int, info: *mut libc::siginfo_t, uctx: *mut c_void) {
    let previous = match unsafe { previous_action(signum) } {
        Some(previous) => previous,
        None => {
            unsafe {
                raise_with_default(signum);
            }
            return;
        }
    };

    let handler = previous.sa_sigaction;
    if handler == libc::SIG_IGN {
        return;
    }

    if handler == libc::SIG_DFL || handler == current_handler_raw() {
        unsafe {
            raise_with_default(signum);
        }
        return;
    }

    if (previous.sa_flags & libc::SA_SIGINFO) != 0 {
        let siginfo_handler: SigInfoHandler = unsafe { std::mem::transmute(handler) };
        siginfo_handler(signum, info, uctx);
        return;
    }

    let simple_handler: SigHandler = unsafe { std::mem::transmute(handler) };
    simple_handler(signum);
}

#[cfg(all(any(target_os = "macos", target_os = "ios"), target_arch = "aarch64"))]
extern "C" fn trap_handler(signum: c_int, info: *mut libc::siginfo_t, uctx: *mut c_void) {
    use crate::context::remap_ctx;
    use crate::memory::{is_brk, read_u32};

    if info.is_null() || uctx.is_null() {
        unsafe {
            chain_previous(signum, info, uctx);
        }
        return;
    }

    let uc = unsafe { &mut *(uctx as *mut libc::ucontext_t) };
    if uc.uc_mcontext.is_null() {
        unsafe {
            chain_previous(signum, info, uctx);
        }
        return;
    }

    let raw_ss = unsafe { &mut (*uc.uc_mcontext).__ss };
    let ctx_ptr = unsafe { remap_ctx(raw_ss as *mut libc::__darwin_arm_thread_state64) };
    let ctx = unsafe { &mut *ctx_ptr };
    let trap_address = ctx.pc;

    let opcode = read_u32(trap_address);
    if !is_brk(opcode) {
        unsafe {
            chain_previous(signum, info, uctx);
        }
        return;
    }

    let handled = handle_trap_aarch64(trap_address, ctx_ptr, |ctx_ptr, next_pc, trampoline_pc| {
        let ctx = unsafe { &mut *ctx_ptr };
        if trampoline_pc != 0 {
            ctx.pc = trampoline_pc;
        } else {
            ctx.pc = next_pc;
        }
    });

    if !handled {
        unsafe {
            chain_previous(signum, info, uctx);
        }
    }
}

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
extern "C" fn trap_handler(signum: c_int, info: *mut libc::siginfo_t, uctx: *mut c_void) {
    use crate::context::{free_ctx, remap_ctx, write_back_ctx};
    use crate::memory::{is_brk, read_u32};

    if info.is_null() || uctx.is_null() {
        unsafe {
            chain_previous(signum, info, uctx);
        }
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
            chain_previous(signum, info, uctx);
        }
        return;
    }

    let handled = handle_trap_aarch64(trap_address, ctx_ptr, |ctx_ptr, next_pc, trampoline_pc| {
        let ctx = unsafe { &mut *ctx_ptr };
        if trampoline_pc != 0 {
            ctx.pc = trampoline_pc;
        } else {
            ctx.pc = next_pc;
        }
    });

    if !handled {
        unsafe {
            free_ctx(ctx_ptr);
            chain_previous(signum, info, uctx);
        }
        return;
    }

    unsafe {
        write_back_ctx(uc_ptr, ctx_ptr);
        free_ctx(ctx_ptr);
    }
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
extern "C" fn trap_handler(signum: c_int, info: *mut libc::siginfo_t, uctx: *mut c_void) {
    use crate::context::{free_ctx, remap_ctx, write_back_ctx};
    use crate::memory::{is_int3, read_u8};

    if info.is_null() || uctx.is_null() {
        unsafe {
            chain_previous(signum, info, uctx);
        }
        return;
    }

    let uc_ptr = uctx as *mut libc::ucontext_t;
    let ctx_ptr = unsafe { remap_ctx(uc_ptr) };
    if ctx_ptr.is_null() {
        unsafe {
            chain_previous(signum, info, uctx);
        }
        return;
    }

    let ctx = unsafe { &mut *ctx_ptr };

    if ctx.rip == 0 {
        unsafe {
            free_ctx(ctx_ptr);
            chain_previous(signum, info, uctx);
        }
        return;
    }

    let trap_address = ctx.rip.wrapping_sub(1);
    let opcode = read_u8(trap_address);
    if !is_int3(opcode) {
        unsafe {
            free_ctx(ctx_ptr);
            chain_previous(signum, info, uctx);
        }
        return;
    }

    let handled = handle_trap_x86_64(trap_address, ctx_ptr, |ctx_ptr, next_pc, trampoline_pc| {
        let ctx = unsafe { &mut *ctx_ptr };
        if trampoline_pc != 0 {
            ctx.rip = trampoline_pc;
        } else {
            ctx.rip = next_pc;
        }
    });

    if !handled {
        unsafe {
            free_ctx(ctx_ptr);
            chain_previous(signum, info, uctx);
        }
        return;
    }

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
) -> bool {
    let slot = unsafe { state::slot_by_address(address) };
    let slot = match slot {
        Some(slot) => slot,
        None => return false,
    };

    let callback: InstrumentCallback = match slot.callback {
        Some(cb) => cb,
        None => return false,
    };

    let original_pc = unsafe { (*ctx_ptr).pc };
    callback(address, ctx_ptr);

    let current_pc = unsafe { (*ctx_ptr).pc };
    if current_pc != original_pc {
        return true;
    }

    if slot.return_to_caller {
        let ctx = unsafe { &mut *ctx_ptr };
        ctx.pc = unsafe { ctx.regs.named.x30 };
        return true;
    }

    let next_pc = address.wrapping_add(slot.step_len as u64);
    let trampoline_pc = if slot.execute_original {
        slot.trampoline_pc
    } else {
        0
    };
    set_pc(ctx_ptr, next_pc, trampoline_pc);
    true
}

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
fn handle_trap_x86_64(
    address: u64,
    ctx_ptr: *mut crate::context::HookContext,
    set_pc: impl FnOnce(*mut crate::context::HookContext, u64, u64),
) -> bool {
    let slot = unsafe { state::slot_by_address(address) };
    let slot = match slot {
        Some(slot) => slot,
        None => return false,
    };

    let callback: InstrumentCallback = match slot.callback {
        Some(cb) => cb,
        None => return false,
    };

    let original_pc = unsafe { (*ctx_ptr).rip };
    callback(address, ctx_ptr);

    let current_pc = unsafe { (*ctx_ptr).rip };
    if current_pc != original_pc {
        return true;
    }

    if slot.return_to_caller {
        let ctx = unsafe { &mut *ctx_ptr };
        if ctx.rsp == 0 {
            return false;
        }

        let return_address = unsafe { std::ptr::read_unaligned(ctx.rsp as *const u64) };
        ctx.rsp = ctx.rsp.wrapping_add(8);
        ctx.rip = return_address;
        return true;
    }

    let next_pc = address.wrapping_add(slot.step_len as u64);
    let trampoline_pc = if slot.execute_original {
        slot.trampoline_pc
    } else {
        0
    };
    set_pc(ctx_ptr, next_pc, trampoline_pc);
    true
}

fn install_signal(signum: c_int) -> Result<(), SigHookError> {
    unsafe {
        let mut act: libc::sigaction = zeroed();
        let mut previous_action: libc::sigaction = zeroed();
        act.sa_flags = libc::SA_SIGINFO;
        act.sa_sigaction = trap_handler as *const () as usize;

        if libc::sigemptyset(&mut act.sa_mask) != 0 {
            return Err(SigHookError::SigEmptySetFailed {
                signum,
                errno: last_errno(),
            });
        }

        if libc::sigaction(signum, &act, &mut previous_action) != 0 {
            return Err(SigHookError::SigActionFailed {
                signum,
                errno: last_errno(),
            });
        }

        save_previous_action(signum, &previous_action);
    }

    Ok(())
}

pub(crate) unsafe fn ensure_handlers_installed() -> Result<(), SigHookError> {
    if unsafe { state::HANDLERS_INSTALLED } {
        return Ok(());
    }

    install_signal(libc::SIGTRAP)?;

    #[cfg(target_arch = "aarch64")]
    install_signal(libc::SIGILL)?;

    unsafe {
        state::HANDLERS_INSTALLED = true;
    }
    Ok(())
}

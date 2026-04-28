use super::{current_fault_handler_raw, current_trap_handler_raw};
use crate::context::InstrumentCallback;
use crate::replay::ReplayPlan;
use crate::signal::active::ActiveTrapGuard;
use crate::signal::chain::chain_previous;
use crate::state;
use libc::{c_int, c_void};

unsafe fn maybe_remap_fault_pc(uctx: *mut c_void) {
    let original_pc = crate::replay::take_fault_pc_remap();
    if let Some(original_pc) = original_pc {
        unsafe {
            crate::context::rewrite_signal_pc(uctx as *mut libc::ucontext_t, original_pc);
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(super) extern "C" fn trap_handler(
    signum: c_int,
    info: *mut libc::siginfo_t,
    uctx: *mut c_void,
) {
    use crate::arch::{is_brk, read_u32};
    use crate::context::{remap_ctx, write_back_ctx};

    let _guard = ActiveTrapGuard::enter();

    if info.is_null() || uctx.is_null() {
        unsafe {
            chain_previous(signum, info, uctx, current_trap_handler_raw());
        }
        return;
    }

    let uc = unsafe { &mut *(uctx as *mut libc::ucontext_t) };
    if uc.uc_mcontext.is_null() {
        unsafe {
            chain_previous(signum, info, uctx, current_trap_handler_raw());
        }
        return;
    }

    let uc_ptr = uctx as *mut libc::ucontext_t;
    let Some(mut ctx) = (unsafe { remap_ctx(uc_ptr) }) else {
        unsafe {
            chain_previous(signum, info, uctx, current_trap_handler_raw());
        }
        return;
    };

    let trap_address = ctx.pc;
    let ctx_ptr: *mut crate::context::HookContext = &mut ctx;
    let slot = unsafe { state::trap_slot_by_address(trap_address) };
    let managed_trap = slot.is_some();
    let opcode = if managed_trap {
        0
    } else {
        read_u32(trap_address)
    };
    let retired_slot = if !managed_trap && signum == libc::SIGTRAP && !is_brk(opcode) {
        // A peer can take the old BRK exception just before unhook restores bytes.
        // If the restored instruction is not a trap, this is that delayed exception.
        unsafe { state::retired_slot_by_address(trap_address) }
    } else {
        None
    };

    if !managed_trap && retired_slot.is_none() && !is_brk(opcode) {
        unsafe {
            chain_previous(signum, info, uctx, current_trap_handler_raw());
        }
        return;
    }

    if !handle_trap_aarch64(trap_address, ctx_ptr, slot.or(retired_slot)) {
        unsafe {
            chain_previous(signum, info, uctx, current_trap_handler_raw());
        }
        return;
    }

    unsafe {
        write_back_ctx(uc_ptr, &ctx);
    }
}

#[cfg(any(target_os = "linux", target_os = "android"))]
pub(super) extern "C" fn trap_handler(
    signum: c_int,
    info: *mut libc::siginfo_t,
    uctx: *mut c_void,
) {
    use crate::arch::{is_brk, read_u32};
    use crate::context::{remap_ctx, write_back_ctx};

    let _guard = ActiveTrapGuard::enter();

    if info.is_null() || uctx.is_null() {
        unsafe {
            chain_previous(signum, info, uctx, current_trap_handler_raw());
        }
        return;
    }

    let uc_ptr = uctx as *mut libc::ucontext_t;
    let Some(mut ctx) = (unsafe { remap_ctx(uc_ptr) }) else {
        unsafe {
            chain_previous(signum, info, uctx, current_trap_handler_raw());
        }
        return;
    };
    let trap_address = ctx.pc;
    let ctx_ptr: *mut crate::context::HookContext = &mut ctx;
    let slot = unsafe { state::trap_slot_by_address(trap_address) };
    let managed_trap = slot.is_some();
    let opcode = if managed_trap {
        0
    } else {
        read_u32(trap_address)
    };
    let retired_slot = if !managed_trap && signum == libc::SIGTRAP && !is_brk(opcode) {
        // A peer can take the old BRK exception just before unhook restores bytes.
        // If the restored instruction is not a trap, this is that delayed exception.
        unsafe { state::retired_slot_by_address(trap_address) }
    } else {
        None
    };

    if !managed_trap && retired_slot.is_none() && !is_brk(opcode) {
        unsafe {
            chain_previous(signum, info, uctx, current_trap_handler_raw());
        }
        return;
    }

    if !handle_trap_aarch64(trap_address, ctx_ptr, slot.or(retired_slot)) {
        unsafe {
            chain_previous(signum, info, uctx, current_trap_handler_raw());
        }
        return;
    }

    unsafe {
        write_back_ctx(uc_ptr, &ctx);
    }
}

pub(super) extern "C" fn fault_handler(
    signum: c_int,
    info: *mut libc::siginfo_t,
    uctx: *mut c_void,
) {
    if info.is_null() || uctx.is_null() {
        unsafe {
            chain_previous(signum, info, uctx, current_fault_handler_raw());
        }
        return;
    }

    unsafe {
        maybe_remap_fault_pc(uctx);
        chain_previous(signum, info, uctx, current_fault_handler_raw());
    }
}

fn handle_trap_aarch64(
    address: u64,
    ctx_ptr: *mut crate::context::HookContext,
    slot: Option<state::InstrumentSlot>,
) -> bool {
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

    // At this point the callback chose not to redirect control flow. The remaining
    // decision is therefore purely "how should execute-original behave for this
    // displaced instruction?" The precomputed replay plan answers that without
    // decoding instruction bits in the signal handler.
    match slot.replay_plan {
        ReplayPlan::Skip => {
            let ctx = unsafe { &mut *ctx_ptr };
            ctx.pc = address.wrapping_add(slot.step_len as u64);
            true
        }
        ReplayPlan::Trampoline => {
            if slot.trampoline_pc == 0 {
                return false;
            }

            let ctx = unsafe { &mut *ctx_ptr };
            ctx.pc = slot.trampoline_pc;
            true
        }
        plan => crate::replay::apply_replay_plan(plan, ctx_ptr, address, slot.step_len),
    }
}

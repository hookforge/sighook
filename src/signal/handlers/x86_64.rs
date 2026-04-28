use crate::context::InstrumentCallback;
use crate::signal::active::ActiveTrapGuard;
use crate::signal::chain::chain_previous;
use crate::state;
use libc::{c_int, c_void};

pub(super) extern "C" fn trap_handler(
    signum: c_int,
    info: *mut libc::siginfo_t,
    uctx: *mut c_void,
) {
    use crate::arch::{is_int3, read_u8};
    use crate::context::{remap_ctx, write_back_ctx};

    let _guard = ActiveTrapGuard::enter();

    if info.is_null() || uctx.is_null() {
        unsafe {
            chain_previous(signum, info, uctx, super::current_trap_handler_raw());
        }
        return;
    }

    let uc_ptr = uctx as *mut libc::ucontext_t;
    let Some(mut ctx) = (unsafe { remap_ctx(uc_ptr) }) else {
        unsafe {
            chain_previous(signum, info, uctx, super::current_trap_handler_raw());
        }
        return;
    };
    let ctx_ptr: *mut crate::context::HookContext = &mut ctx;

    if ctx.rip == 0 {
        unsafe {
            chain_previous(signum, info, uctx, super::current_trap_handler_raw());
        }
        return;
    }

    let trap_address = ctx.rip.wrapping_sub(1);
    let slot = unsafe { state::trap_slot_by_address(trap_address) };
    let managed_trap = slot.is_some();
    let opcode = if managed_trap {
        0
    } else {
        read_u8(trap_address)
    };
    let retired_slot = if !managed_trap && !is_int3(opcode) {
        // A peer can take the old INT3 exception just before unhook restores bytes.
        // If the restored byte is not INT3, this is that delayed exception.
        unsafe { state::retired_slot_by_address(trap_address) }
    } else {
        None
    };
    if !managed_trap && retired_slot.is_none() && !is_int3(opcode) {
        unsafe {
            chain_previous(signum, info, uctx, super::current_trap_handler_raw());
        }
        return;
    }

    if !handle_trap_x86_64(
        trap_address,
        ctx_ptr,
        slot.or(retired_slot),
        |ctx_ptr, next_pc, trampoline_pc| {
            let ctx = unsafe { &mut *ctx_ptr };
            if trampoline_pc != 0 {
                ctx.rip = trampoline_pc;
            } else {
                ctx.rip = next_pc;
            }
        },
    ) {
        unsafe {
            chain_previous(signum, info, uctx, super::current_trap_handler_raw());
        }
        return;
    }

    unsafe {
        write_back_ctx(uc_ptr, &ctx);
    }
}

fn handle_trap_x86_64(
    address: u64,
    ctx_ptr: *mut crate::context::HookContext,
    slot: Option<state::InstrumentSlot>,
    set_pc: impl FnOnce(*mut crate::context::HookContext, u64, u64),
) -> bool {
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

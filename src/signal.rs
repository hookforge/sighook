use crate::context::InstrumentCallback;
use crate::error::SigHookError;
use crate::platform::last_errno;
#[cfg(target_arch = "aarch64")]
use crate::replay::ReplayPlan;
use crate::state;
use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use libc::{c_int, c_void};
use std::mem::zeroed;
use std::ptr::null_mut;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

type SigInfoHandler = extern "C" fn(c_int, *mut libc::siginfo_t, *mut c_void);
type SigHandler = extern "C" fn(c_int);

struct PreviousActionSlot {
    action: UnsafeCell<MaybeUninit<libc::sigaction>>,
    set: AtomicBool,
}

impl PreviousActionSlot {
    const fn new() -> Self {
        Self {
            action: UnsafeCell::new(MaybeUninit::uninit()),
            set: AtomicBool::new(false),
        }
    }

    unsafe fn store(&self, previous_action: &libc::sigaction) {
        unsafe {
            std::ptr::copy_nonoverlapping(previous_action, (*self.action.get()).as_mut_ptr(), 1);
        }
        self.set.store(true, Ordering::Release);
    }

    fn load(&self) -> Option<libc::sigaction> {
        if !self.set.load(Ordering::Acquire) {
            return None;
        }

        Some(unsafe { std::ptr::read((*self.action.get()).as_ptr()) })
    }
}

unsafe impl Sync for PreviousActionSlot {}

static PREV_SIGTRAP_ACTION: PreviousActionSlot = PreviousActionSlot::new();
static PREV_SIGILL_ACTION: PreviousActionSlot = PreviousActionSlot::new();
#[cfg(target_arch = "aarch64")]
static PREV_SIGSEGV_ACTION: PreviousActionSlot = PreviousActionSlot::new();
#[cfg(target_arch = "aarch64")]
static PREV_SIGBUS_ACTION: PreviousActionSlot = PreviousActionSlot::new();
static ACTIVE_TRAP_HANDLERS: AtomicUsize = AtomicUsize::new(0);
static HANDLERS_INSTALLED: OnceLock<Result<(), SigHookError>> = OnceLock::new();

#[inline]
fn current_trap_handler_raw() -> libc::sighandler_t {
    trap_handler as *const () as libc::sighandler_t
}

#[cfg(target_arch = "aarch64")]
#[inline]
fn current_fault_handler_raw() -> libc::sighandler_t {
    fault_handler as *const () as libc::sighandler_t
}

unsafe fn save_previous_action(signum: c_int, previous_action: &libc::sigaction) {
    match signum {
        libc::SIGTRAP => unsafe { PREV_SIGTRAP_ACTION.store(previous_action) },
        libc::SIGILL => unsafe { PREV_SIGILL_ACTION.store(previous_action) },
        #[cfg(target_arch = "aarch64")]
        libc::SIGSEGV => unsafe { PREV_SIGSEGV_ACTION.store(previous_action) },
        #[cfg(target_arch = "aarch64")]
        libc::SIGBUS => unsafe { PREV_SIGBUS_ACTION.store(previous_action) },
        _ => {}
    }
}

unsafe fn previous_action(signum: c_int) -> Option<libc::sigaction> {
    match signum {
        libc::SIGTRAP => PREV_SIGTRAP_ACTION.load(),
        libc::SIGILL => PREV_SIGILL_ACTION.load(),
        #[cfg(target_arch = "aarch64")]
        libc::SIGSEGV => PREV_SIGSEGV_ACTION.load(),
        #[cfg(target_arch = "aarch64")]
        libc::SIGBUS => PREV_SIGBUS_ACTION.load(),
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

unsafe fn chain_previous(
    signum: c_int,
    info: *mut libc::siginfo_t,
    uctx: *mut c_void,
    current_handler_raw: libc::sighandler_t,
) {
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

    if handler == libc::SIG_DFL || handler == current_handler_raw {
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

#[cfg(target_arch = "aarch64")]
unsafe fn maybe_remap_fault_pc(uctx: *mut c_void) {
    let original_pc = crate::replay::take_fault_pc_remap();
    if let Some(original_pc) = original_pc {
        unsafe {
            crate::context::rewrite_signal_pc(uctx as *mut libc::ucontext_t, original_pc);
        }
    }
}

struct ActiveTrapGuard;

impl ActiveTrapGuard {
    fn enter() -> Self {
        ACTIVE_TRAP_HANDLERS.fetch_add(1, Ordering::AcqRel);
        Self
    }
}

impl Drop for ActiveTrapGuard {
    fn drop(&mut self) {
        ACTIVE_TRAP_HANDLERS.fetch_sub(1, Ordering::AcqRel);
    }
}

pub(crate) fn wait_for_trap_handlers_quiescent() -> Result<(), SigHookError> {
    let deadline = Instant::now() + Duration::from_secs(5);
    while ACTIVE_TRAP_HANDLERS.load(Ordering::Acquire) != 0 {
        if Instant::now() >= deadline {
            return Err(SigHookError::PatchSynchronizationFailed);
        }
        std::thread::yield_now();
    }
    state::reclaim_retired_slot_snapshots();
    Ok(())
}

pub(crate) fn trap_handlers_active() -> bool {
    ACTIVE_TRAP_HANDLERS.load(Ordering::Acquire) != 0
}

#[cfg(all(any(target_os = "macos", target_os = "ios"), target_arch = "aarch64"))]
extern "C" fn trap_handler(signum: c_int, info: *mut libc::siginfo_t, uctx: *mut c_void) {
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

#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    target_arch = "aarch64"
))]
extern "C" fn trap_handler(signum: c_int, info: *mut libc::siginfo_t, uctx: *mut c_void) {
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

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
extern "C" fn trap_handler(signum: c_int, info: *mut libc::siginfo_t, uctx: *mut c_void) {
    use crate::arch::{is_int3, read_u8};
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
    let ctx_ptr: *mut crate::context::HookContext = &mut ctx;

    if ctx.rip == 0 {
        unsafe {
            chain_previous(signum, info, uctx, current_trap_handler_raw());
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
            chain_previous(signum, info, uctx, current_trap_handler_raw());
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
            chain_previous(signum, info, uctx, current_trap_handler_raw());
        }
        return;
    }

    unsafe {
        write_back_ctx(uc_ptr, &ctx);
    }
}

#[cfg(target_arch = "aarch64")]
extern "C" fn fault_handler(signum: c_int, info: *mut libc::siginfo_t, uctx: *mut c_void) {
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

#[cfg(target_arch = "aarch64")]
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

#[cfg(all(target_arch = "x86_64", any(target_os = "linux", target_os = "macos")))]
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

fn install_signal(signum: c_int, handler: libc::sighandler_t) -> Result<(), SigHookError> {
    unsafe {
        let mut act: libc::sigaction = zeroed();
        let mut previous_action: libc::sigaction = zeroed();
        act.sa_flags = libc::SA_SIGINFO;
        act.sa_sigaction = handler;

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

unsafe fn install_handlers_once() -> Result<(), SigHookError> {
    install_signal(libc::SIGTRAP, current_trap_handler_raw())?;

    #[cfg(target_arch = "aarch64")]
    {
        install_signal(libc::SIGILL, current_trap_handler_raw())?;
        install_signal(libc::SIGSEGV, current_fault_handler_raw())?;
        install_signal(libc::SIGBUS, current_fault_handler_raw())?;
    }

    Ok(())
}

pub(crate) unsafe fn ensure_handlers_installed() -> Result<(), SigHookError> {
    match HANDLERS_INSTALLED.get_or_init(|| unsafe { install_handlers_once() }) {
        Ok(()) => Ok(()),
        Err(err) => Err(*err),
    }
}

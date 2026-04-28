use crate::error::SigHookError;
use crate::state;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static ACTIVE_TRAP_HANDLERS: AtomicUsize = AtomicUsize::new(0);

pub(in crate::signal) struct ActiveTrapGuard;

impl ActiveTrapGuard {
    pub(in crate::signal) fn enter() -> Self {
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

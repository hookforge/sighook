use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use libc::c_int;
use std::sync::atomic::{AtomicBool, Ordering};

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

pub(in crate::signal) unsafe fn save_previous_action(
    signum: c_int,
    previous_action: &libc::sigaction,
) {
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

pub(in crate::signal) unsafe fn previous_action(signum: c_int) -> Option<libc::sigaction> {
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

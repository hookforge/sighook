#[cfg(target_arch = "aarch64")]
use super::handlers::current_fault_handler_raw;
use super::handlers::current_trap_handler_raw;
use super::previous::save_previous_action;
use crate::error::SigHookError;
use crate::platform::last_errno;
use libc::c_int;
use std::mem::zeroed;
use std::sync::OnceLock;

static HANDLERS_INSTALLED: OnceLock<Result<(), SigHookError>> = OnceLock::new();

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

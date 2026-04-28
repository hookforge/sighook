use super::previous::previous_action;
use libc::{c_int, c_void};
use std::mem::zeroed;
use std::ptr::null_mut;

type SigInfoHandler = extern "C" fn(c_int, *mut libc::siginfo_t, *mut c_void);
type SigHandler = extern "C" fn(c_int);

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

pub(in crate::signal) unsafe fn chain_previous(
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

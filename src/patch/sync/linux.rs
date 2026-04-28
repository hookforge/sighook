use crate::error::SigHookError;
use libc::{c_int, c_void};
use std::cell::Cell;
use std::fs;
use std::hint::spin_loop;
use std::mem::zeroed;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static HANDLER_INSTALLED: OnceLock<Result<(), SigHookError>> = OnceLock::new();
static STOP_SIGNAL: OnceLock<c_int> = OnceLock::new();
static STOP_ACTIVE: AtomicBool = AtomicBool::new(false);
static STOP_GENERATION: AtomicUsize = AtomicUsize::new(0);
static STOP_ACKS: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static LAST_ACKED_GENERATION: Cell<usize> = const { Cell::new(0) };
}

pub(crate) fn with_threads_paused<T>(
    f: impl FnOnce() -> Result<T, SigHookError>,
) -> Result<T, SigHookError> {
    ensure_handler_installed()?;

    let current_tid = current_tid()?;
    let tids = list_other_tids(current_tid)?;
    if tids.is_empty() {
        return f();
    }

    let _generation = STOP_GENERATION.fetch_add(1, Ordering::AcqRel) + 1;
    STOP_ACKS.store(0, Ordering::Release);
    STOP_ACTIVE.store(true, Ordering::Release);

    let send_result = send_stop_signal(&tids);
    if send_result.is_err() {
        STOP_ACTIVE.store(false, Ordering::Release);
        STOP_GENERATION.fetch_add(1, Ordering::AcqRel);
        return Err(SigHookError::PatchSynchronizationFailed);
    }

    let deadline = Instant::now() + Duration::from_millis(500);
    while STOP_ACKS.load(Ordering::Acquire) != tids.len() {
        if Instant::now() >= deadline {
            STOP_ACTIVE.store(false, Ordering::Release);
            STOP_GENERATION.fetch_add(1, Ordering::AcqRel);
            return Err(SigHookError::PatchSynchronizationFailed);
        }
        std::thread::yield_now();
    }

    let result = f();

    STOP_ACTIVE.store(false, Ordering::Release);
    STOP_GENERATION.fetch_add(1, Ordering::AcqRel);
    result
}

fn ensure_handler_installed() -> Result<(), SigHookError> {
    match HANDLER_INSTALLED.get_or_init(install_handler) {
        Ok(()) => Ok(()),
        Err(err) => Err(*err),
    }
}

fn install_handler() -> Result<(), SigHookError> {
    unsafe {
        let mut act: libc::sigaction = zeroed();
        act.sa_flags = libc::SA_SIGINFO | libc::SA_RESTART;
        act.sa_sigaction = stop_handler as *const () as usize;
        if libc::sigemptyset(&mut act.sa_mask) != 0 {
            return Err(SigHookError::PatchSynchronizationFailed);
        }

        let our_handler = stop_handler as *const () as usize;
        for signo in stop_signal_candidates() {
            let mut current_action: libc::sigaction = zeroed();
            if libc::sigaction(signo, std::ptr::null(), &mut current_action) != 0 {
                continue;
            }
            let current_handler = current_action.sa_sigaction;
            if current_handler != libc::SIG_DFL && current_handler != our_handler {
                continue;
            }

            let mut previous_action: libc::sigaction = zeroed();
            if libc::sigaction(signo, &act, &mut previous_action) != 0 {
                continue;
            }

            let previous_handler = previous_action.sa_sigaction;
            if (previous_handler == libc::SIG_DFL || previous_handler == our_handler)
                && STOP_SIGNAL.set(signo).is_ok()
            {
                return Ok(());
            }

            let _ = libc::sigaction(signo, &previous_action, std::ptr::null_mut());
        }
    }
    Err(SigHookError::PatchSynchronizationFailed)
}

fn stop_signal_candidates() -> impl Iterator<Item = c_int> {
    (libc::SIGRTMIN()..=libc::SIGRTMAX()).rev()
}

fn stop_signal() -> Result<c_int, SigHookError> {
    STOP_SIGNAL
        .get()
        .copied()
        .ok_or(SigHookError::PatchSynchronizationFailed)
}

fn current_tid() -> Result<libc::pid_t, SigHookError> {
    let tid = unsafe { libc::syscall(libc::SYS_gettid) as libc::pid_t };
    if tid <= 0 {
        return Err(SigHookError::PatchSynchronizationFailed);
    }
    Ok(tid)
}

fn list_other_tids(current_tid: libc::pid_t) -> Result<Vec<libc::pid_t>, SigHookError> {
    let mut tids = Vec::new();
    for entry in
        fs::read_dir("/proc/self/task").map_err(|_| SigHookError::PatchSynchronizationFailed)?
    {
        let entry = entry.map_err(|_| SigHookError::PatchSynchronizationFailed)?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or(SigHookError::PatchSynchronizationFailed)?;
        let tid = name
            .parse::<libc::pid_t>()
            .map_err(|_| SigHookError::PatchSynchronizationFailed)?;
        if tid != current_tid {
            tids.push(tid);
        }
    }
    Ok(tids)
}

fn send_stop_signal(tids: &[libc::pid_t]) -> Result<(), SigHookError> {
    let pid = unsafe { libc::getpid() };
    let signal = stop_signal()?;
    for &tid in tids {
        let rc = unsafe { libc::syscall(libc::SYS_tgkill, pid, tid, signal) as c_int };
        if rc != 0 {
            return Err(SigHookError::PatchSynchronizationFailed);
        }
    }
    Ok(())
}

extern "C" fn stop_handler(_signum: c_int, _info: *mut libc::siginfo_t, _uctx: *mut c_void) {
    if !STOP_ACTIVE.load(Ordering::Acquire) {
        return;
    }

    let generation = STOP_GENERATION.load(Ordering::Acquire);
    if generation == 0 {
        return;
    }

    LAST_ACKED_GENERATION.with(|last| {
        if last.get() != generation {
            last.set(generation);
            STOP_ACKS.fetch_add(1, Ordering::AcqRel);
        }
    });

    while STOP_ACTIVE.load(Ordering::Acquire)
        && STOP_GENERATION.load(Ordering::Acquire) == generation
    {
        spin_loop();
    }
}

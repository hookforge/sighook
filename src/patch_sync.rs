use crate::error::SigHookError;
use std::sync::Mutex;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::sync::OnceLock;

static PATCH_LOCK: Mutex<()> = Mutex::new(());

fn lock_or_recover<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

pub(crate) fn with_threads_paused<T>(
    f: impl FnOnce() -> Result<T, SigHookError>,
) -> Result<T, SigHookError> {
    let _guard = lock_or_recover(&PATCH_LOCK);

    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        return linux::with_threads_paused(f);
    }

    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        return apple::with_threads_paused(f);
    }

    #[allow(unreachable_code)]
    f()
}

#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux {
    use super::OnceLock;
    use crate::error::SigHookError;
    use libc::{c_int, c_void};
    use std::cell::Cell;
    use std::fs;
    use std::hint::spin_loop;
    use std::mem::zeroed;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    static HANDLER_INSTALLED: OnceLock<Result<(), SigHookError>> = OnceLock::new();
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
            act.sa_flags = libc::SA_SIGINFO;
            act.sa_sigaction = stop_handler as usize;
            if libc::sigemptyset(&mut act.sa_mask) != 0 {
                return Err(SigHookError::PatchSynchronizationFailed);
            }
            if libc::sigaction(stop_signal(), &act, std::ptr::null_mut()) != 0 {
                return Err(SigHookError::PatchSynchronizationFailed);
            }
        }
        Ok(())
    }

    fn stop_signal() -> c_int {
        libc::SIGRTMAX() - 1
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
        for &tid in tids {
            let rc = unsafe { libc::syscall(libc::SYS_tgkill, pid, tid, stop_signal()) as c_int };
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
}

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod apple {
    use crate::error::SigHookError;
    use libc::{
        kern_return_t, mach_msg_type_number_t, mach_port_t, pthread_mach_thread_np, pthread_self,
        task_t, task_threads, thread_act_array_t, thread_act_t, vm_deallocate,
    };
    use std::mem::size_of;

    unsafe extern "C" {
        fn mach_port_deallocate(task: task_t, name: mach_port_t) -> kern_return_t;
        fn thread_suspend(target_thread: thread_act_t) -> kern_return_t;
        fn thread_resume(target_thread: thread_act_t) -> kern_return_t;
    }

    pub(crate) fn with_threads_paused<T>(
        f: impl FnOnce() -> Result<T, SigHookError>,
    ) -> Result<T, SigHookError> {
        let current = unsafe { pthread_mach_thread_np(pthread_self()) };
        let mut threads: thread_act_array_t = std::ptr::null_mut();
        let mut thread_count: mach_msg_type_number_t = 0;
        let kr = unsafe { task_threads(libc::mach_task_self(), &mut threads, &mut thread_count) };
        if kr != 0 {
            return Err(SigHookError::PatchSynchronizationFailed);
        }

        let thread_slice = unsafe { std::slice::from_raw_parts(threads, thread_count as usize) };
        let mut suspended = Vec::new();
        for &thread in thread_slice {
            if thread == current {
                continue;
            }
            let kr = unsafe { thread_suspend(thread) };
            if kr != 0 {
                resume_threads(&suspended);
                deallocate_threads(current, threads, thread_count);
                return Err(SigHookError::PatchSynchronizationFailed);
            }
            suspended.push(thread);
        }

        let result = f();

        resume_threads(&suspended);
        deallocate_threads(current, threads, thread_count);
        result
    }

    fn resume_threads(threads: &[mach_port_t]) {
        for &thread in threads {
            let _ = unsafe { thread_resume(thread) };
        }
    }

    fn deallocate_threads(
        current: mach_port_t,
        threads: thread_act_array_t,
        thread_count: mach_msg_type_number_t,
    ) {
        if !threads.is_null() {
            let thread_slice =
                unsafe { std::slice::from_raw_parts(threads, thread_count as usize) };
            for &thread in thread_slice {
                if thread != current {
                    let _ = unsafe { mach_port_deallocate(libc::mach_task_self(), thread) };
                }
            }
            let bytes = (thread_count as usize)
                .checked_mul(size_of::<thread_act_t>())
                .unwrap_or(0);
            let _ = unsafe {
                vm_deallocate(
                    libc::mach_task_self(),
                    threads as libc::vm_address_t,
                    bytes as libc::vm_size_t,
                )
            };
        }
    }
}

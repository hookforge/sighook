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

const KERN_INVALID_ARGUMENT: kern_return_t = 4;
const MACH_SEND_INVALID_DEST: kern_return_t = 0x1000_0003;

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
    let mut suspended = Vec::with_capacity(thread_slice.len().saturating_sub(1));
    for &thread in thread_slice {
        if thread == current {
            continue;
        }
        let kr = unsafe { thread_suspend(thread) };
        if kr != 0 {
            if matches!(kr, KERN_INVALID_ARGUMENT | MACH_SEND_INVALID_DEST) {
                continue;
            }
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
        let thread_slice = unsafe { std::slice::from_raw_parts(threads, thread_count as usize) };
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

#![allow(clippy::missing_const_for_thread_local)]

use crate::error::SigHookError;
use std::sync::Mutex;

#[cfg(any(target_os = "macos", target_os = "ios"))]
mod apple;
#[cfg(any(target_os = "linux", target_os = "android"))]
mod linux;

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

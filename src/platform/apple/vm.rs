use crate::constants::VM_PROT_COPY;
use crate::error::SigHookError;
use crate::platform::last_errno;

unsafe extern "C" {
    fn mach_vm_protect(
        target_task: libc::vm_map_t,
        address: libc::mach_vm_address_t,
        size: libc::mach_vm_size_t,
        set_maximum: libc::boolean_t,
        new_protection: libc::vm_prot_t,
    ) -> libc::kern_return_t;
}

pub(crate) struct RestoreProtections;

pub(crate) fn prepare_restore_protections(
    _start: usize,
    _len: usize,
) -> Result<RestoreProtections, SigHookError> {
    Ok(RestoreProtections)
}

pub(crate) fn make_patch_range_writable(start: usize, len: usize) -> Result<(), SigHookError> {
    // Apple code pages are commonly copy-on-write mappings, so `VM_PROT_COPY`
    // keeps the kernel happy while we temporarily enable writes.
    let writable_prot = libc::VM_PROT_READ | libc::VM_PROT_WRITE | VM_PROT_COPY;

    let kr = unsafe {
        mach_vm_protect(
            libc::mach_task_self(),
            start as u64,
            len as u64,
            0,
            writable_prot,
        )
    };

    if kr != 0 {
        return Err(SigHookError::ProtectWritableFailed {
            kr,
            errno: last_errno(),
        });
    }

    Ok(())
}

pub(crate) fn restore_patch_range_protection(
    start: usize,
    len: usize,
    _restore: &RestoreProtections,
) -> Result<(), SigHookError> {
    let mut last_kr = 0;
    for &prot in executable_restore_protections() {
        let kr_restore =
            unsafe { mach_vm_protect(libc::mach_task_self(), start as u64, len as u64, 0, prot) };

        if kr_restore == 0 {
            last_kr = 0;
            break;
        }

        last_kr = kr_restore;
    }

    if last_kr != 0 {
        return Err(SigHookError::ProtectExecutableFailed {
            kr: last_kr,
            errno: last_errno(),
        });
    }

    Ok(())
}

#[inline]
pub(crate) fn executable_restore_protections() -> &'static [libc::vm_prot_t] {
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        const PROTS: &[libc::vm_prot_t] = &[
            libc::VM_PROT_READ | libc::VM_PROT_EXECUTE,
            libc::VM_PROT_READ | libc::VM_PROT_EXECUTE | VM_PROT_COPY,
        ];
        PROTS
    }

    #[cfg(not(all(target_os = "macos", target_arch = "x86_64")))]
    {
        const PROTS: &[libc::vm_prot_t] = &[libc::VM_PROT_READ | libc::VM_PROT_EXECUTE];
        PROTS
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn executable_restore_protections_match_target() {
        let prot_list = super::executable_restore_protections();
        assert!(!prot_list.is_empty());
        assert_eq!(prot_list[0], libc::VM_PROT_READ | libc::VM_PROT_EXECUTE);

        #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
        {
            assert_eq!(prot_list.len(), 2);
            assert_eq!(
                prot_list[1],
                libc::VM_PROT_READ | libc::VM_PROT_EXECUTE | crate::constants::VM_PROT_COPY
            );
        }

        #[cfg(not(all(target_os = "macos", target_arch = "x86_64")))]
        {
            assert_eq!(prot_list.len(), 1);
        }
    }
}

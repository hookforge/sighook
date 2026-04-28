use crate::error::SigHookError;

unsafe extern "C" {
    fn mach_vm_read_overwrite(
        target_task: libc::vm_map_t,
        address: libc::mach_vm_address_t,
        size: libc::mach_vm_size_t,
        data: libc::mach_vm_address_t,
        outsize: *mut libc::mach_vm_size_t,
    ) -> libc::kern_return_t;
}

pub(crate) fn read_memory_chunk_x86(address: usize, out: &mut [u8]) -> Result<(), SigHookError> {
    if out.is_empty() {
        return Ok(());
    }

    let mut out_size: libc::mach_vm_size_t = 0;
    let kr = unsafe {
        mach_vm_read_overwrite(
            libc::mach_task_self(),
            address as libc::mach_vm_address_t,
            out.len() as libc::mach_vm_size_t,
            out.as_mut_ptr() as libc::mach_vm_address_t,
            &mut out_size,
        )
    };
    if kr != 0 || out_size as usize != out.len() {
        return Err(SigHookError::InvalidAddress);
    }

    Ok(())
}
